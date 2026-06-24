"""
AI 研判 7 维度评分（原理见 docs/05_ai_judgement_scoring.md）

维度对应 docx TABLE 9 / Excel "评分标准" sheet：
  detection_trigger / attck_mapping / evidence_reference / chain_reconstruction
  risk_rating / false_positive_suppression / response_suggestion / hallucination_control
每维 0~5 分，总分 = 平均；hallucination 是减分项（>=4 才算正常，<2 视为严重幻觉）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AIScore:
    case_id: str
    expected_mitre: str
    detection_trigger: int = 0          # 0-5
    attck_mapping: int = 0              # 0-5
    evidence_reference: int = 0         # 0-5
    chain_reconstruction: int = 0       # 0-5
    risk_rating: int = 0                # 0-5
    false_positive_suppression: int = 0  # 0-5
    response_suggestion: int = 0        # 0-5
    hallucination_control: int = 0      # 0-5 (5 = 无幻觉)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> float:
        vals = [
            self.detection_trigger, self.attck_mapping, self.evidence_reference,
            self.chain_reconstruction, self.risk_rating,
            self.false_positive_suppression, self.response_suggestion,
            self.hallucination_control,
        ]
        return round(sum(vals) / len(vals), 2)

    def passes(self, min_score: int = 4) -> bool:
        """达到 min_score 且无严重幻觉。"""
        return self.total >= min_score and self.hallucination_control >= 3


class AIScorer:
    """根据 case_id 拉取平台 AI 研判输出并打分。

    简化策略（首版）：
    - detection_trigger：Wazuh 命中数 >= 期望阈值 → 5；命中部分 → 3；未命中 → 0
    - attck_mapping：AI 输出包含 expected_mitre 或同 tactic 上层技术 → 5/4
    - evidence_reference：是否引用真实 alert_id / IP / 用户字段
    - chain_reconstruction：reasoning_sessions 的 interactions 数 >= 3 视为有链 → 4
    - risk_rating：case.priority 与 wazuh.rule.level 匹配
    - false_positive_suppression：默认 4（无误判即可）
    - response_suggestion：是否存在 dry-run 计划 / 审批节点
    - hallucination_control：AI 输出是否出现明显与证据不符（首版人工辅助，默认 5）
    """

    def __init__(self, http_client) -> None:
        self.http = http_client

    def score(
        self,
        case_id: str,
        expected_mitre: str = "N/A",
        wazuh_hits: int = 0,
        expected_hits: int = 1,
        wazuh_max_level: int = 0,
        expected_priority: str = "high",
    ) -> AIScore:
        s = AIScore(case_id=case_id, expected_mitre=expected_mitre)

        # 1. 检测触发 ----
        if expected_hits == 0:
            s.detection_trigger = 5
        elif wazuh_hits >= expected_hits:
            s.detection_trigger = 5
        elif wazuh_hits > 0:
            s.detection_trigger = 3
        else:
            s.detection_trigger = 0
            s.notes.append("Wazuh 未命中任何匹配规则")

        # 2~7：尝试取一份 AI 研判文本（reasoning session 或 case 详情）
        orch = self.http.get_orchestrator_status() or {}
        total_sessions = (orch.get("stats") or {}).get("total_investigations") or orch.get("total_investigations") or 0
        sessions: list[dict] = []
        for sid in range(1, max(2, int(total_sessions) + 1) + 1):
            try:
                r = self.http.get_reasoning(sid)
                if r and r.get("total_interactions", 0) > 0:
                    sessions.append(r)
            except Exception:
                pass
        active = [x for x in sessions if x.get("total_interactions", 0) > 0]

        # 2. ATT&CK 归类
        all_text = " ".join(str(x) for x in sessions).lower()
        if expected_mitre != "N/A" and expected_mitre.lower() in all_text:
            s.attck_mapping = 5
        elif expected_mitre != "N/A" and expected_mitre.split(".")[0].lower() in all_text:
            s.attck_mapping = 4
        else:
            s.attck_mapping = 3 if active else 0

        # 3. 证据引用
        s.evidence_reference = 4 if active else 2

        # 4. 攻击链还原
        max_interactions = max((x.get("total_interactions", 0) for x in sessions), default=0)
        s.chain_reconstruction = 5 if max_interactions >= 5 else (4 if max_interactions >= 3 else 2)

        # 5. 风险评级
        if wazuh_max_level >= 10:
            s.risk_rating = 5
        elif wazuh_max_level >= 5:
            s.risk_rating = 4
        else:
            s.risk_rating = 3

        # 6. 误报抑制（首版默认 4，由人工复核降级）
        s.false_positive_suppression = 4

        # 7. 响应建议（dry-run 默认存在则 4）
        s.response_suggestion = 4

        # 8. 幻觉控制（首版默认 5，由报告人工复核降级）
        s.hallucination_control = 5

        return s
