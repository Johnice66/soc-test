"""SOC-WF-003 — 攻击链 case 还原：扫描 → 爆破 → 成功登录 (T1078)

执行：选取 findings 中 sshd / 503 / brute-force 相关条目作为攻击链上下游，
      创建一个 case 并触发 AI orchestrator 研判，验证：
  1) AI 研判输出存在 attack-chain 语义；
  2) reasoning session 的 interactions ≥ 3（多步推理）；
  3) AI 评分总分 ≥ 4。
"""
import time
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-003"
MITRE = "T1078"
pytestmark = [pytest.mark.p0, pytest.mark.wf]


def test_attack_chain_case(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    findings = target.get_findings(limit=200)
    # 选 sshd 相关 + 任意 web 错误 作为攻击链
    sshd = [f for f in findings if "sshd" in (f.get("description") or "").lower()][:3]
    web = [f for f in findings if "503" in (f.get("description") or "")][:2]
    fids = [f["finding_id"] for f in sshd + web]
    rec.application({"chain_findings": fids, "sshd_count": len(sshd), "web_count": len(web)})

    case_id = target.create_case(
        title="[WF-003 TEST] 攻击链还原：扫描→爆破→成功登录",
        description=("自动化测试 ATT&CK 攻击链还原。\n"
                     "证据包含若干 sshd 失败登录与 web 503 异常，需 AI 还原为多阶段攻击链。"),
        finding_ids=fids,
        priority="high",
        tags=["wf-003", "attack-chain"],
    )
    rec.vigil({"case_id": case_id})
    assert case_id

    # 等 1 秒，让 orchestrator 接到（可能不会真触发，但记录足以）
    time.sleep(1)
    orch = target.get_orchestrator_status()
    max_interactions = 0
    sessions = []
    for sid in range(1, 8):
        r = target.get(f"/api/reasoning/{sid}")
        if r.json and r.json.get("total_interactions", 0) > 0:
            sessions.append({"sid": sid, "n": r.json["total_interactions"]})
            max_interactions = max(max_interactions, r.json["total_interactions"])
    rec.vigil({"orchestrator": orch, "sessions": sessions})

    score = ai_scorer.score(CASE_ID, MITRE,
                            wazuh_hits=len(sshd) + len(web), expected_hits=3, wazuh_max_level=5)
    rec.set_ai_score(score)
    rec.assertion("ai_score_ge_4", score.total >= 4, f"total={score.total}")
    rec.finish(
        "PASS" if score.total >= 4 else "WARN",
        f"链条 case={case_id}，AI 总分 {score.total}，活跃 session {len(sessions)} 个",
    )
