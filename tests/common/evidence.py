"""
EvidenceRecorder：六层证据链记录器（详细原理见 docs/04_evidence_model.md）

六层 = client / gateway / application / wazuh / vigil_ai / response
每条用例 start() 一次，多次叠加各层证据，finish() 写出 JSON。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class CaseEvidence:
    case_id: str          # 用例 ID（如 SOC-ATT-004）
    mitre: str            # 主线 ATT&CK 技术 ID 或 'N/A'
    run_id: str           # 本次运行 ID（时间戳）
    started_at: str = ""
    finished_at: str = ""
    status: str = "RUNNING"  # PASS / WARN / FAIL / SKIP
    message: str = ""
    duration_ms: float = 0.0
    time_window: dict = field(default_factory=dict)  # {start, end}
    evidence: dict = field(default_factory=lambda: {
        "client": [],        # 测试发起端：命令、请求参数、源 IP 等
        "gateway": [],       # 网关层：route/upstream/status/request_id
        "application": [],   # 应用层：审计事件、平台业务行为
        "wazuh": [],         # Wazuh decoder/rule/alert
        "vigil_ai": [],      # finding/case/AI 研判
        "response": [],      # 响应动作（审批、dry-run、执行、回滚）
    })
    ai_score: dict | None = None  # AIScorer 输出
    assertions: list[dict] = field(default_factory=list)
    # ---------- 可观测性专项 (8 类) ----------
    observability: dict = field(default_factory=lambda: {
        "request_ids": [],         # 各 HTTP 请求的 X-Request-Id
        "wazuh_rule_keys": [],     # 推断出的 Wazuh 规则关键字 / mitre 标签
        "wazuh_alert_ids": [],     # 从 finding_id 解析出的 alert_id
        "case_finding_links": [],  # [{case_id, finding_ids[]}]
        "approvals": [],           # {action_id, status, target, approved_at, executed_at, ...}
        "rollback_records": [],    # 平台无独立 API，记录代理事件
        "sse_probes": [],          # {path, status, content_type, is_real_sse}
        "auth_policy": {},         # 鉴权探测信号汇总
    })


class EvidenceRecorder:
    """单个用例的证据收集器 —— 由 conftest fixture 创建。"""

    def __init__(self, case_id: str, mitre: str, run_dir: str, run_id: str) -> None:
        self._t0 = time.perf_counter()
        ts = datetime.utcnow().isoformat()
        self.data = CaseEvidence(
            case_id=case_id,
            mitre=mitre,
            run_id=run_id,
            started_at=ts,
            time_window={"start": ts, "end": ""},
        )
        self.run_dir = run_dir
        os.makedirs(os.path.join(run_dir, "evidence"), exist_ok=True)

    # 六层证据快速入口 ----------------------------------------
    def client(self, item: Any):
        self.data.evidence["client"].append(_normalize(item))

    def gateway(self, item: Any):
        self.data.evidence["gateway"].append(_normalize(item))

    def application(self, item: Any):
        self.data.evidence["application"].append(_normalize(item))

    def wazuh(self, item: Any):
        self.data.evidence["wazuh"].append(_normalize(item))

    def vigil(self, item: Any):
        self.data.evidence["vigil_ai"].append(_normalize(item))

    def response(self, item: Any):
        self.data.evidence["response"].append(_normalize(item))

    # 工具 ---------------------------------------------------
    def assertion(self, name: str, ok: bool, detail: str = ""):
        self.data.assertions.append({"name": name, "ok": ok, "detail": detail})

    def set_ai_score(self, score):
        self.data.ai_score = asdict(score) if hasattr(score, "__dataclass_fields__") else score

    # ---------- 可观测性记录 ----------
    def obs_request_ids(self, ids: list[str]):
        self.data.observability["request_ids"].extend(ids)

    def obs_alert_ids(self, alert_ids: list[str]):
        self.data.observability["wazuh_alert_ids"].extend([x for x in alert_ids if x])

    def obs_rule_keys(self, keys: list[str]):
        self.data.observability["wazuh_rule_keys"].extend([x for x in keys if x])

    def obs_case_finding(self, case_id: str, finding_ids: list[str]):
        self.data.observability["case_finding_links"].append(
            {"case_id": case_id, "finding_ids": finding_ids, "count": len(finding_ids)}
        )

    def obs_approval(self, approval: dict):
        self.data.observability["approvals"].append(approval)

    def obs_rollback(self, item: dict):
        self.data.observability["rollback_records"].append(item)

    def obs_sse_probe(self, item: dict):
        self.data.observability["sse_probes"].append(item)

    def obs_auth_policy(self, policy: dict):
        self.data.observability["auth_policy"] = policy

    def finish(self, status: str, message: str = ""):
        self.data.status = status
        self.data.message = message
        self.data.finished_at = datetime.utcnow().isoformat()
        self.data.time_window["end"] = self.data.finished_at
        self.data.duration_ms = (time.perf_counter() - self._t0) * 1000
        return self._write()

    def _write(self) -> str:
        """把当前 data 写到 evidence/<case_id>.json。可重复调用，会覆盖之前的写出。"""
        path = os.path.join(self.run_dir, "evidence", f"{self.data.case_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self.data), f, ensure_ascii=False, indent=2, default=str)
        return path

    # 用例可以在执行过程中显式塞这两个属性，供 conftest teardown 时附加观测
    def hint_findings(self, findings):
        self._hint_findings = findings

    def hint_case_ids(self, case_ids):
        self._hint_case_ids = case_ids


def _normalize(item: Any) -> Any:
    """对 dataclass / object 做兼容序列化处理。"""
    if hasattr(item, "__dataclass_fields__"):
        return asdict(item)
    if isinstance(item, (dict, list, str, int, float, bool)) or item is None:
        return item
    try:
        return dict(vars(item))
    except Exception:
        return repr(item)
