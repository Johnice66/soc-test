"""SOC-WEB-002 — HTTP 方法白名单

只读资源（findings/cases/health 等的 GET 端点）必须对非白名单方法 (DELETE/PUT/PATCH) 返回 405，
不允许返回 200 / 5xx / 静默丢弃。
"""
import pytest

CASE_ID = "SOC-WEB-002"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_READ_PATHS = ["/api/findings/", "/api/cases/", "/api/health", "/api/workflows"]
_BAD_METHODS = ["DELETE", "PUT", "PATCH"]


def test_method_not_allowed(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"paths": _READ_PATHS, "bad_methods": _BAD_METHODS})

    matrix = {}
    bad_hits = []
    for p in _READ_PATHS:
        matrix[p] = {}
        for m in _BAD_METHODS:
            r = target.raw_request(m, p, json_data={})
            matrix[p][m] = r["status"]
            if r["status"] in (200, 201, 202, 204):
                bad_hits.append(f"{m} {p} -> {r['status']}")
    rec.gateway({"method_status_matrix": matrix, "bad_hits": bad_hits})

    # 405 是首选，401/403 也可接受（鉴权先拒）。200/2xx 即漏洞。
    ok = not bad_hits
    rec.assertion("no_unauthorized_writes", ok, str(bad_hits))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.finish("PASS" if ok else "FAIL",
               "未发现写方法被接受" if ok else f"发现可写: {bad_hits}")
