"""SOC-AUTH-001 — 登录暴力限流

15 次快速错误登录尝试，平台必须在 ≤10 次内开始返回 429（或 423 lockout）。
"""
import time
import pytest

CASE_ID = "SOC-AUTH-001"
MITRE = "T1110"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_ATTEMPTS = 15
_THRESHOLD = 10  # 第 N 次之前必须出现限流


def test_login_rate_limit(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"attempts": _ATTEMPTS, "threshold": _THRESHOLD,
                "endpoint": "/api/auth/login",
                "payload": {"username_or_email": "_probe_brute", "password": "_wrong"}})

    statuses = []
    first_throttle = None
    for i in range(_ATTEMPTS):
        r = target.raw_request(
            "POST", "/api/auth/login",
            json_data={"username_or_email": "_probe_brute", "password": "_wrong"},
            timeout=4,
        )
        statuses.append(r["status"])
        if r["status"] in (429, 423) and first_throttle is None:
            first_throttle = i + 1
            break
        time.sleep(0.02)

    rec.gateway({"status_sequence": statuses, "first_throttle_at_attempt": first_throttle})

    throttled = first_throttle is not None
    in_threshold = throttled and first_throttle <= _THRESHOLD
    rec.assertion("rate_limit_kicks_in", throttled, str(statuses))
    rec.assertion("throttle_within_threshold", in_threshold,
                  f"first_throttle={first_throttle} threshold={_THRESHOLD}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=1 if throttled else 0, expected_hits=1)
    rec.set_ai_score(score)
    if in_threshold:
        rec.finish("PASS", f"第 {first_throttle} 次触发限流（{statuses[-3:]}）")
    elif throttled:
        rec.finish("WARN", f"触发了限流但偏晚（第 {first_throttle} 次）")
    else:
        rec.finish("FAIL", f"未触发限流，{_ATTEMPTS} 次响应: {statuses}")
