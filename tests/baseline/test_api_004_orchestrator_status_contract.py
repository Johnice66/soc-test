"""SOC-API-004 — /api/orchestrator/status 数据契约

字段必须含：enabled, active_agents, max_concurrent_agents, queued, completed, failed,
pending_review；所有计数必须为非负整数。
"""
import pytest

CASE_ID = "SOC-API-004"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_REQUIRED = ["enabled", "active_agents", "max_concurrent_agents", "queued",
             "completed", "failed", "pending_review"]
_COUNT_FIELDS = ["active_agents", "max_concurrent_agents", "queued",
                 "completed", "failed", "pending_review"]


def test_orchestrator_status_contract(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    r = target.raw_request("GET", "/api/orchestrator/status")
    body = r["json"] or {}
    rec.gateway({"status": r["status"], "body": body})

    rec.assertion("http_200", r["status"] == 200, str(r["status"]))
    missing = [k for k in _REQUIRED if k not in body]
    rec.assertion("required_fields_present", not missing, str(missing))

    non_int_or_neg = []
    for k in _COUNT_FIELDS:
        v = body.get(k)
        if not isinstance(v, int) or v < 0:
            non_int_or_neg.append({k: v})
    rec.assertion("counts_non_neg_int", not non_int_or_neg, str(non_int_or_neg))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=1, expected_hits=1)
    rec.set_ai_score(score)
    all_ok = all(a["ok"] for a in rec.data.assertions)
    if all_ok:
        rec.finish("PASS", f"orchestrator 字段合规 enabled={body.get('enabled')}")
    else:
        rec.finish("FAIL", f"字段不合规 missing={missing} bad={non_int_or_neg}")
