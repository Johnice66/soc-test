"""SOC-AI-006 — X-Workspace-Id 头越权

伪造 X-Workspace-Id 头访问受保护端点，平台不应仅凭该头就授权访问。
做法：对若干"看似要做范围过滤"的端点，分别发"无 X-Workspace-Id"与"伪造 X-Workspace-Id"两次，
对比响应是否一致 / 是否因头存在而出现额外鉴权流程。
"""
import pytest

CASE_ID = "SOC-AI-006"
MITRE = "T1078"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]

_TARGETS = ["/api/findings/", "/api/cases/", "/api/workflows", "/api/approvals"]
_FAKE_WS = "ws-fake-12345-attacker"


def test_workspace_id_spoof(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"endpoints": _TARGETS, "fake_workspace_id": _FAKE_WS})

    diffs = []
    leaks = []
    for p in _TARGETS:
        a = target.raw_request("GET", p)
        b = target.raw_request("GET", p, headers={"X-Workspace-Id": _FAKE_WS})
        same_status = a["status"] == b["status"]
        a_keys = sorted((a["json"] or {}).keys()) if isinstance(a["json"], dict) else []
        b_keys = sorted((b["json"] or {}).keys()) if isinstance(b["json"], dict) else []
        a_len = len(str(a["text"] or ""))
        b_len = len(str(b["text"] or ""))
        diffs.append({"path": p, "status_a": a["status"], "status_b": b["status"],
                      "same_status": same_status, "a_keys": a_keys, "b_keys": b_keys,
                      "size_a": a_len, "size_b": b_len})
        # 若 b 返回比 a 多了内容（伪 ws 反而拿到更多数据） → 越权
        if same_status and b_len > a_len * 1.2:
            leaks.append(p)
    rec.gateway({"diffs": diffs, "leaked_paths": leaks})

    rec.assertion("no_extra_data_for_fake_workspace", not leaks, str(leaks))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0 if leaks else 1, expected_hits=1)
    rec.set_ai_score(score)
    if not leaks:
        rec.finish("PASS", f"伪造 X-Workspace-Id 未导致额外数据暴露")
    else:
        rec.finish("FAIL", f"伪造 ws 导致响应膨胀: {leaks}")
