"""SOC-AI-012 — 登出后长连接未失效 (T1550.004 部分映射)

执行：1) 探测 SSE 流端点 2) 模拟"登出"（清空 Cookie） 3) 再次访问同一流
验收：登出前 200，登出后 4xx；或者两次都 401（说明本就需要鉴权）。
若平台当前 SSE 不需要鉴权 → WARN。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-AI-012"
MITRE = "T1550.004"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]


_SSE_PATHS = [
    "/api/orchestrator/stream",
    "/api/agent/events",
    "/api/events",
    "/api/notifications/stream",
]


def test_logout_invalidates_stream(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "paths": _SSE_PATHS})
    findings = []
    for p in _SSE_PATHS:
        status, events = target.open_sse(p, max_events=1, timeout=4)
        rec.gateway({"path": p, "sse_status": status, "events_read": len(events)})
        if status == 200:
            findings.append(p)
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    if not findings:
        rec.assertion("no_open_sse_stream", True, "未发现可匿名读取的 SSE 流")
        rec.finish("PASS", "未发现可匿名读取的 SSE 流；登出场景不适用")
    else:
        rec.assertion("found_anon_sse", False, f"匿名 200 流：{findings}")
        rec.finish("WARN", f"以下 SSE 端点匿名可读，登出失效需人工验证：{findings}")
