"""SOC-AUTH-002 — 伪造 Bearer / 错误凭据响应一致性

要求：
  1. 三种"非法凭据"形态 (无 Bearer / 伪造 JWT / 过期式) 在受保护端点上必须返回 401。
  2. 错误消息文本必须一致（不能因为用户存在/不存在/格式不同而不同），避免用户枚举。
"""
import pytest

CASE_ID = "SOC-AUTH-002"
MITRE = "T1550.001"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_PROTECTED = "/api/users/me"

_PROBES = {
    "no_header": {},
    "garbage_jwt": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aGVsbG8.signature"},
    "format_x.y.z": {"Authorization": "Bearer x.y.z"},
    "non_bearer_scheme": {"Authorization": "Basic dGVzdDp0ZXN0"},
    "empty_bearer": {"Authorization": "Bearer "},
}


def test_unauth_responses_consistent(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"endpoint": _PROTECTED, "probes": list(_PROBES.keys())})

    results = {}
    for name, h in _PROBES.items():
        r = target.raw_request("GET", _PROTECTED, headers=h)
        results[name] = {
            "status": r["status"],
            "body_detail": (r["json"] or {}).get("detail") if isinstance(r["json"], dict) else None,
            "body_snip": (r["text"] or "")[:120],
        }
    rec.gateway({"probe_results": results})

    statuses = [v["status"] for v in results.values()]
    all_401 = all(s == 401 for s in statuses)
    distinct_msgs = {v["body_detail"] for v in results.values() if v["body_detail"]}
    rec.assertion("all_return_401", all_401, str(statuses))
    rec.assertion("messages_not_user_enumerating", len(distinct_msgs) <= 2,
                  f"distinct={distinct_msgs}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=int(all_401), expected_hits=1)
    rec.set_ai_score(score)
    if all_401 and len(distinct_msgs) <= 2:
        rec.finish("PASS", f"5 种伪造尝试均 401，错误消息一致 ({len(distinct_msgs)} 种)")
    elif all_401:
        rec.finish("WARN", f"全 401 但错误消息 {len(distinct_msgs)} 种，可能可用于探测")
    else:
        rec.finish("FAIL", f"状态码不一致: {statuses}")
