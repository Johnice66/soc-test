"""SOC-AI-001 — 未认证 WebSocket Upgrade

执行：不携带任何 Cookie/Bearer 对常见 WS 路径发起 Upgrade 请求
验收：服务端应拒绝（401/403/426 或 401/200+不切换 protocol）；不应回 101 Switching
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-AI-001"
MITRE = "T1190"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]


_WS_PATHS = [
    "/ws",
    "/api/ws",
    "/api/agent/stream",
    "/api/events",
    "/api/notifications/stream",
    "/socket.io/",
]


def test_unauth_ws_upgrade_rejected(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "paths": _WS_PATHS})
    leaks = []
    for path in _WS_PATHS:
        r = target.probe_ws_upgrade(path)
        rec.gateway({"path": path, **{k: v for k, v in r.items() if k != "headers"}})
        if r.get("status_code") == 101:
            leaks.append(path)
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.assertion("no_101_switching_protocol", len(leaks) == 0, f"leaks={leaks}")
    assert len(leaks) == 0, f"无认证 WS Upgrade 被服务端接受：{leaks}"
    rec.finish("PASS", "所有 WS 路径都未在无认证情况下完成 Upgrade")
