"""SOC-WEB-001 — 关键安全响应头存在性

核查目标平台前端/API 是否返回 OWASP 推荐的安全响应头组合。
要求 (硬指标 ≥6/8 PASS，否则 WARN)：
  - content-security-policy
  - x-frame-options       (DENY 或 SAMEORIGIN)
  - x-content-type-options (nosniff)
  - referrer-policy
  - access-control-allow-origin 不为 *
"""
from __future__ import annotations

import pytest

CASE_ID = "SOC-WEB-001"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]


def _has(headers: dict, key: str, contains: str | None = None) -> bool:
    v = headers.get(key.lower())
    if v is None:
        return False
    if contains is None:
        return True
    return contains.lower() in v.lower()


def test_security_headers(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"probes": ["/", "/api/health", "/api/findings/"]})

    paths = ["/", "/api/health", "/api/findings/"]
    captured = {}
    for p in paths:
        r = target.raw_request("GET", p)
        captured[p] = {"status": r["status"], "headers": r["headers"]}
    rec.gateway({"captured_headers": captured})

    checks = []
    for p, r in captured.items():
        h = r["headers"]
        checks.append((f"{p} csp", _has(h, "content-security-policy")))
        checks.append((f"{p} x-frame-options", _has(h, "x-frame-options", "deny") or _has(h, "x-frame-options", "sameorigin")))
        checks.append((f"{p} x-content-type-options", _has(h, "x-content-type-options", "nosniff")))
        checks.append((f"{p} referrer-policy", _has(h, "referrer-policy")))
        # access-control-allow-origin 不应为 *
        aco = h.get("access-control-allow-origin", "")
        checks.append((f"{p} aco-not-wildcard", aco != "*"))

    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    rec.application({"checks_pass": passed, "checks_total": total,
                     "failed": [name for name, ok in checks if not ok]})

    for name, ok in checks:
        rec.assertion(name, ok, "" if ok else "missing/invalid")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    if passed == total:
        rec.finish("PASS", f"安全响应头全部就位 {passed}/{total}")
    elif passed >= int(total * 0.75):
        rec.finish("WARN", f"{passed}/{total} 通过，存在弱项")
    else:
        rec.finish("FAIL", f"{passed}/{total} 通过，安全响应头基线不足")
