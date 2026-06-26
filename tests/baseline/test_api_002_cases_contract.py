"""SOC-API-002 — /api/cases/ 数据契约

GET /api/cases/?limit=10 返回 {"cases":[...]}，每条必须含：
  case_id, title, priority, status；case_id 格式 case-YYYY-MM-DD-<hex>
"""
import re
import pytest

CASE_ID = "SOC-API-002"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_REQUIRED = {"case_id", "title", "priority", "status"}
_CID_RE = re.compile(r"^case-\d{4}-\d{2}-\d{2}-[0-9a-f]{4,}$")


def test_cases_contract(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    cases = target.list_cases(limit=10)
    rec.gateway({"endpoint": "/api/cases/?limit=10", "received_count": len(cases)})

    if not cases:
        rec.assertion("cases_returned", False, "0 条 case")
        rec.finish("WARN", "平台当前无 case")
        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        return

    missing = []
    bad_ids = []
    for i, c in enumerate(cases):
        miss = _REQUIRED - set(c.keys())
        if miss:
            missing.append({"index": i, "missing": list(miss)})
        cid = c.get("case_id", "")
        if not _CID_RE.match(cid):
            bad_ids.append(cid)

    rec.application({"sample_keys": sorted(cases[0].keys()),
                     "missing_required": missing,
                     "id_format_bad": bad_ids})

    rec.assertion("required_fields_present", not missing, str(missing))
    rec.assertion("case_id_format_ok", not bad_ids, str(bad_ids))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(cases), expected_hits=1)
    rec.set_ai_score(score)
    if not missing and not bad_ids:
        rec.finish("PASS", f"{len(cases)} 条 case 字段与 ID 格式全部合规")
    elif not missing:
        rec.finish("WARN", f"字段齐全但 ID 格式异常: {bad_ids}")
    else:
        rec.finish("FAIL", f"契约不合规 missing={missing} bad_ids={bad_ids}")
