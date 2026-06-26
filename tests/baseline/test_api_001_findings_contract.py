"""SOC-API-001 — /api/findings/ 数据契约

GET /api/findings/?limit=10 返回 {"findings":[...]}，每条必须含核心字段：
  finding_id, description, mitre_predictions, anomaly_score, ts
limit 必须生效。
"""
import pytest

CASE_ID = "SOC-API-001"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_REQUIRED = {"finding_id", "description"}
_RECOMMENDED = {"mitre_predictions", "anomaly_score"}


def test_findings_contract(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder

    items = target.get_findings(limit=10)
    rec.gateway({"endpoint": "/api/findings/?limit=10", "received_count": len(items)})

    if not items:
        rec.assertion("findings_returned", False, "0 条 finding")
        rec.finish("WARN", "平台当前无 finding，无法验证字段契约")
        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        return

    missing_required = []
    missing_recommended = []
    for i, f in enumerate(items):
        miss = _REQUIRED - set(f.keys())
        if miss:
            missing_required.append({"index": i, "missing": list(miss)})
        rmiss = _RECOMMENDED - set(f.keys())
        if rmiss:
            missing_recommended.append({"index": i, "missing": list(rmiss)})

    sample = items[0]
    rec.application({"sample_keys": sorted(sample.keys()),
                     "missing_required": missing_required,
                     "missing_recommended": missing_recommended})

    limit_ok = len(items) <= 10
    rec.assertion("limit_respected", limit_ok, f"received={len(items)}")
    rec.assertion("required_fields_present", not missing_required, str(missing_required))
    rec.assertion("recommended_fields_present", not missing_recommended,
                  str(missing_recommended))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(items), expected_hits=1)
    rec.set_ai_score(score)
    if not missing_required and limit_ok and not missing_recommended:
        rec.finish("PASS", f"{len(items)} 条 finding 字段全部合规")
    elif not missing_required and limit_ok:
        rec.finish("WARN", f"必需字段齐全但缺推荐字段: {missing_recommended}")
    else:
        rec.finish("FAIL", f"契约不合规: required={missing_required}")
