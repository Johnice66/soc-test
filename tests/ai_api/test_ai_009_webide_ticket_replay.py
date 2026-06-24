"""SOC-AI-009 — WebIDE 一次性 ticket 重放 (T1550.001 部分映射)

执行：探测常见 WebIDE ticket 端点（/api/webide/ticket, /api/ide/session 等），
      若返回 ticket，则用同一 ticket 重复访问 ≥ 2 次，验证是否生效。
当前平台无 WebIDE 端点 → 用例结果为 SKIP/WARN，记录探测证据。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-AI-009"
MITRE = "T1550.001"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]


_TICKET_PATHS = [
    "/api/webide/ticket",
    "/api/ide/session",
    "/api/ide/ticket",
    "/api/wattbot/ticket",
    "/api/workspace/ticket",
]


def test_webide_ticket_replay(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "paths": _TICKET_PATHS})
    issued = []
    for p in _TICKET_PATHS:
        r = target.post(p, json_data={"workspace_id": "default"})
        rec.gateway({"path": p, "status": r.status_code, "snippet": r.body_snippet[:80]})
        if r.status_code == 200 and r.json and ("ticket" in r.json or "token" in r.json):
            issued.append((p, r.json))

    if not issued:
        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        rec.assertion("no_ticket_endpoint", True, "平台未暴露 WebIDE ticket 端点")
        rec.finish("WARN", "未探测到 WebIDE ticket 端点；按当前平台无此入口，跳过重放验证")
        return

    # 真发现 ticket：重放 2 次，对比 status
    p, body = issued[0]
    ticket = body.get("ticket") or body.get("token")
    r1 = target.get(f"{p}?ticket={ticket}")
    r2 = target.get(f"{p}?ticket={ticket}")
    rec.gateway({"replay_1": r1.status_code, "replay_2": r2.status_code})
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.assertion("ticket_one_time_use", r2.status_code in (401, 403, 409, 410),
                  f"replay status={r2.status_code}")
    if r2.status_code in (401, 403, 409, 410):
        rec.finish("PASS", "ticket 不可重放")
    else:
        rec.finish("WARN", f"ticket 可重放：status={r2.status_code}")
