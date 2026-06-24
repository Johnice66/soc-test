"""SOC-AI-029 — 高危工具调用审批缺失 (T1059 部分映射)

执行：直接 POST /api/cases/{id}/respond 请求高危动作（block_ip / isolate_host / disable_account）
验收：
  1) 若返回 200 且 executed=true → FAIL（高危动作直接执行 = 缺审批）
  2) 若返回 404/405 → PASS（无 API 入口，需走 workflow 审批 = 合规）
  3) 若返回 200 + dry_run/pending_approval → PASS（有审批节点）
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-AI-029"
MITRE = "T1059"
pytestmark = [pytest.mark.p0, pytest.mark.ai_socket]


_HIGH_RISK = [
    {"action": "block_ip", "target": "203.0.113.7"},
    {"action": "isolate_host", "target": "192.168.50.42"},
    {"action": "disable_account", "target": "admin"},
]


def test_high_risk_action_requires_approval(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "actions": _HIGH_RISK})
    bad = []  # 高危动作居然能直接 executed
    for a in _HIGH_RISK:
        r = target.post("/api/cases/AI-029-fake/respond", json_data={**a, "dry_run": False})
        rec.response({**a, "status": r.status_code, "snippet": r.body_snippet[:120]})
        body = (r.json or {})
        if r.status_code == 200 and body.get("executed") is True and not body.get("pending_approval"):
            bad.append(a)
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.assertion("no_direct_high_risk_execution", len(bad) == 0, f"bad={bad}")
    assert len(bad) == 0, f"以下高危动作可直接执行：{bad}"
    rec.finish("PASS", "高危工具调用均需走审批/workflow，未发现可绕过审批的入口")
