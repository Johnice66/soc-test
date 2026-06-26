"""SOC-AI-003 — 跨用户 reasoning session 访问（IDOR）

匿名访问 /api/reasoning/<id> 与 /api/reasoning/<id>/interactions，期望平台返回 401/403。
当前平台已确认返回 200 + 完整会话数据（含 token cost / interactions）—— 这是真实的
broken authn / IDOR；用例用 FAIL 把这个证据钉住，待平台修复后转 PASS。
"""
import pytest

CASE_ID = "SOC-AI-003"
MITRE = "T1190"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]

_SESSIONS = [1, 2, 3]  # 探测前 3 个 session id


def test_reasoning_idor(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"endpoints": [f"/api/reasoning/{i}" for i in _SESSIONS],
                "auth_used": "none (anonymous)"})

    results = []
    leaked = []
    for sid in _SESSIONS:
        r1 = target.raw_request("GET", f"/api/reasoning/{sid}")
        r2 = target.raw_request("GET", f"/api/reasoning/{sid}/interactions?limit=3")
        results.append({"sid": sid,
                        "detail_status": r1["status"],
                        "interactions_status": r2["status"],
                        "detail_keys": list((r1["json"] or {}).keys())[:8] if isinstance(r1["json"], dict) else [],
                        "interactions_count": (r2["json"] or {}).get("total") if isinstance(r2["json"], dict) else None})
        body1 = r1["json"] or {}
        if isinstance(body1, dict) and body1.get("total_interactions", 0) > 0 and r1["status"] == 200:
            leaked.append(sid)
    rec.gateway({"probes": results, "leaked_sessions": leaked})

    # 期望：401/403；实际：可能 200。我们既记录现状又设硬断言。
    rec.assertion("no_anonymous_reasoning_read", not leaked,
                  f"匿名可读: {leaked}")

    score = ai_scorer.score(CASE_ID, MITRE,
                            wazuh_hits=0 if leaked else 1,
                            expected_hits=1)
    rec.set_ai_score(score)
    if not leaked:
        rec.finish("PASS", "未发现匿名可读 reasoning 会话")
    else:
        rec.finish("FAIL",
                   f"匿名可读 reasoning sessions={leaked}；"
                   "平台暴露 AI 会话内容/费用，建议加 user/session 校验")
