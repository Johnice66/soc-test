"""通用可观测性附加器

用例 finish() 前调用 attach_observability(rec, target)，自动把以下 8 类信息写进证据：
1. request_id —— 把 HTTPClient.call_log 里所有请求的 X-Request-Id 列出来
2. rule_id     —— 用 finding 的 mitre_predictions 和 description 关键字推断（平台 finding 未直接暴露 rule.id）
3. alert_id    —— 从 finding_id 'wazuh-<unix>.<id>' 解析
4. case ⇄ finding 关联 —— 拉用例内创建过的 case 详情，记录关联 finding_ids
5. 审批单     —— /api/approvals?status=pending|approved|rejected
6. 响应回滚    —— 平台无独立 API；记录"读为代理"的事实 + 找有 execution_result 的项
7. SSE        —— 探测常见 /api/*/stream 路径，确认是否真 SSE
8. token 鉴权策略 —— /api/auth/login 错误信息、/api/users/me 401 等
"""
from __future__ import annotations

from typing import Iterable, Optional

from .evidence import EvidenceRecorder
from .http_client import HTTPClient


_SSE_PROBE_PATHS = [
    "/api/orchestrator/stream",
    "/api/orchestrator/events",
    "/api/agent/events",
    "/api/events",
    "/api/events/stream",
    "/api/notifications",
]

# session 级 cache：SSE 与 auth 探测每次 pytest run 只跑一次
_session_cache: dict = {"sse": None, "auth": None}


def reset_session_cache() -> None:
    _session_cache["sse"] = None
    _session_cache["auth"] = None


def attach_observability(
    rec: EvidenceRecorder,
    target: HTTPClient,
    *,
    findings: Optional[Iterable[dict]] = None,
    case_ids: Optional[Iterable[str]] = None,
    probe_sse: bool = True,
    probe_auth: bool = True,
    probe_approvals: bool = True,
    sse_paths: Optional[list[str]] = None,
) -> None:
    """把 8 类可观测性信息写进 rec.observability。失败任何一项都不抛异常。"""

    # 1) request_id —— 来源是 HTTPClient 的 call_log
    try:
        ids = [c.request_id for c in target.call_log if getattr(c, "request_id", None)]
        rec.obs_request_ids(ids)
    except Exception:
        pass

    # 2) rule_id 推断 + 3) alert_id 解析
    if findings is not None:
        rule_keys: list[str] = []
        alert_ids: list[str] = []
        for f in findings:
            fid = (f or {}).get("finding_id")
            if fid:
                aid = HTTPClient.parse_wazuh_alert_id(fid)
                if aid:
                    alert_ids.append(aid)
            preds = (f or {}).get("mitre_predictions") or {}
            for tech, prob in preds.items():
                rule_keys.append(f"{tech} ({prob})")
            desc = (f or {}).get("description") or ""
            if desc:
                rule_keys.append(desc[:80])
        rec.obs_alert_ids(alert_ids[:20])
        # 去重
        rec.obs_rule_keys(list(dict.fromkeys(rule_keys))[:20])

    # 4) case ⇄ finding 关联
    if case_ids:
        for cid in case_ids:
            try:
                detail = target.get_case_detail(cid)
                rec.obs_case_finding(cid, detail.get("finding_ids", []) or [])
            except Exception:
                pass

    # 5) 审批单 + 6) 响应回滚（代理）
    if probe_approvals:
        try:
            pending = target.list_approvals("pending")
            approved = target.list_approvals("approved")
            executed = target.list_approvals("executed")
            rejected = target.list_approvals("rejected")
            summary = {
                "counts": {
                    "pending": pending.get("count", 0),
                    "approved": approved.get("count", 0),
                    "executed": executed.get("count", 0),
                    "rejected": rejected.get("count", 0),
                },
            }
            # 取每个状态最近的 1 条做样例（脱敏：只留关键字段）
            for st, payload in [("pending", pending), ("approved", approved), ("executed", executed)]:
                actions = payload.get("actions") or []
                if actions:
                    a = actions[0]
                    summary[f"sample_{st}"] = {
                        "action_id": a.get("action_id"),
                        "action_type": a.get("action_type"),
                        "target": a.get("target"),
                        "status": a.get("status"),
                        "created_at": a.get("created_at"),
                        "approved_at": a.get("approved_at"),
                        "approved_by": a.get("approved_by"),
                        "executed_at": a.get("executed_at"),
                        "execution_result": a.get("execution_result"),
                        "rejection_reason": a.get("rejection_reason"),
                        "workflow_run_id": a.get("workflow_run_id"),
                    }
            rec.obs_approval(summary)
            # 回滚：平台没有独立 API；把 status=rejected 的项作为代理回滚记录
            for a in (rejected.get("actions") or [])[:5]:
                rec.obs_rollback({
                    "proxy": "approval-reject-as-rollback",
                    "action_id": a.get("action_id"),
                    "rejected_at": a.get("rejection_reason"),
                    "target": a.get("target"),
                })
            if not (rejected.get("actions") or []):
                rec.obs_rollback({
                    "proxy": "platform-no-rollback-api",
                    "note": "平台未暴露 /rollback 端点；当前回滚由 approval reject + workflow undo 代理",
                })
        except Exception as e:
            rec.obs_approval({"error": str(e)[:120]})

    # 7) SSE 探测（session 级 cache，跨用例只跑一次）
    if probe_sse:
        if _session_cache["sse"] is None:
            results = []
            for p in (sse_paths or _SSE_PROBE_PATHS):
                try:
                    results.append(target.probe_sse_real(p))
                except Exception as e:
                    results.append({"path": p, "error": str(e)[:120]})
            _session_cache["sse"] = results
        for item in _session_cache["sse"]:
            rec.obs_sse_probe(dict(item))

    # 8) 鉴权策略（session 级 cache）
    if probe_auth:
        if _session_cache["auth"] is None:
            try:
                _session_cache["auth"] = target.probe_auth_policy()
            except Exception as e:
                _session_cache["auth"] = {"error": str(e)[:120]}
        rec.obs_auth_policy(dict(_session_cache["auth"]))
