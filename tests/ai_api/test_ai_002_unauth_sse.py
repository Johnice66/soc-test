"""SOC-AI-002 — 未认证 SSE 事件流访问

枚举多种可能的 SSE 端点路径，匿名访问；任何一条返回 `content-type: text/event-stream`
且 200 就视为未鉴权 SSE 暴露（FAIL）。当前平台经探测都是 JSON 包装 404，预期 PASS。
"""
import pytest

CASE_ID = "SOC-AI-002"
MITRE = "T1190"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]

_PROBE_SSE_PATHS = [
    "/api/agents/sessions/1/events",
    "/api/agents/events",
    "/api/sse",
    "/api/events/stream",
    "/api/reasoning/1/stream",
    "/api/reasoning/1/events",
    "/api/notifications/stream",
    "/api/workflows/incident-response/stream",
]


def test_unauth_sse_blocked(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"probe_paths": _PROBE_SSE_PATHS})

    probes = []
    leaked = []
    for p in _PROBE_SSE_PATHS:
        probe = target.probe_sse_real(p, timeout=3)
        probes.append(probe)
        rec.obs_sse_probe(probe)
        if probe.get("is_real_sse") and probe.get("status") == 200:
            leaked.append(probe)
    rec.gateway({"probe_count": len(probes), "leaked_count": len(leaked),
                 "probes": probes})

    rec.assertion("no_unauth_sse_endpoint", not leaked, str(leaked))

    score = ai_scorer.score(CASE_ID, MITRE,
                            wazuh_hits=0 if not leaked else len(leaked),
                            expected_hits=0)
    rec.set_ai_score(score)
    if not leaked:
        rec.finish("PASS", f"探测 {len(probes)} 条 SSE 端点，无未鉴权暴露")
    else:
        rec.finish("FAIL", f"发现未鉴权 SSE: {[x['path'] for x in leaked]}")
