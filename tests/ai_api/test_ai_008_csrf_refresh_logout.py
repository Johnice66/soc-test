"""SOC-AI-008 — CSRF 刷新/登出保护

匿名（无 refresh cookie / 无 csrf token）对 /api/auth/refresh 与 /api/auth/logout 发 POST，
必须返回 401，不应返回 200/204（不能匿名诱发刷新/登出副作用）。
"""
import pytest

CASE_ID = "SOC-AI-008"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]


def test_csrf_protected_endpoints(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"endpoints": ["/api/auth/refresh", "/api/auth/logout"]})

    refresh = target.raw_request("POST", "/api/auth/refresh", json_data={})
    logout = target.raw_request("POST", "/api/auth/logout", json_data={})
    rec.gateway({
        "refresh": {"status": refresh["status"], "detail": (refresh["json"] or {}).get("detail")},
        "logout": {"status": logout["status"], "detail": (logout["json"] or {}).get("detail")},
    })

    refresh_blocked = refresh["status"] in (401, 403)
    logout_blocked = logout["status"] in (401, 403)
    rec.assertion("anon_refresh_blocked", refresh_blocked, str(refresh["status"]))
    rec.assertion("anon_logout_blocked", logout_blocked, str(logout["status"]))

    score = ai_scorer.score(CASE_ID, "N/A",
                            wazuh_hits=int(refresh_blocked and logout_blocked),
                            expected_hits=1)
    rec.set_ai_score(score)
    if refresh_blocked and logout_blocked:
        rec.finish("PASS", f"refresh={refresh['status']} logout={logout['status']}")
    else:
        rec.finish("FAIL", f"refresh={refresh['status']} logout={logout['status']} —— 存在匿名诱发副作用风险")
