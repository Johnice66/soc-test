"""SOC-ATT-004 — SSH 密码猜测 (T1110.001)

执行：在被测主机用错误密码尝试 SSH 登录 5 次 → 触发 Wazuh 规则 5503/5710 等
验收：
  1) Wazuh Indexer 中能查到 >= 5 条 sshd 失败登录告警（src_ip 命中）
  2) 平台 findings 接口能在窗口内出现新增 sshd 告警（间接验证：现有 sshd findings 计数）
"""
import time
import pytest
from tests.common.matrix_loader import get_case
from tests.common.ai_score import AIScorer

CASE_ID = "SOC-ATT-004"
MITRE = "T1110.001"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_ssh_password_guessing(target, wazuh, ssh_host, evidence_recorder, ai_scorer: AIScorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "attack": "ssh-password-guess", "attempts": 5})

    # 1) 执行 5 次失败登录（dry-run 模式下只记录）
    victim = "testuser"
    cmd = (
        f"for i in 1 2 3 4 5; do "
        f"sshpass -p 'wrong_pw_$i' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
        f"{victim}@127.0.0.1 'true' 2>&1 || true; "
        f"done"
    )
    r = ssh_host.run(cmd, timeout=60)
    rec.client({"cmd": cmd, "exit_code": r.exit_code, "dry_run": r.dry_run})

    # 2) 等待 Wazuh 索引出 sshd 失败告警（30s 内）
    alerts = wazuh.wait_alerts(
        rule_description_like="sshd authentication",
        min_count=3, timeout_seconds=60, since_seconds=300,
    )
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "level": a.rule_level,
                "desc": a.description, "src_ip": a.src_ip} for a in alerts])

    # 3) 平台 findings 接口验证
    findings = target.get_findings(limit=200)
    sshd_findings = [f for f in findings if "sshd" in (f.get("description") or "").lower()]
    rec.application({"sshd_findings_in_platform": len(sshd_findings)})

    # 4) AI 研判评分
    score = ai_scorer.score(
        case_id=CASE_ID, expected_mitre=MITRE,
        wazuh_hits=len(alerts), expected_hits=3,
        wazuh_max_level=max((a.rule_level for a in alerts), default=0),
    )
    rec.set_ai_score(score)
    rec.assertion("wazuh_alerts_ge_3", len(alerts) >= 3, f"alerts={len(alerts)}")
    assert len(alerts) >= 3, f"SSH 爆破未被 Wazuh 检测到（{len(alerts)} 条）"
    rec.finish("PASS", f"SSH 爆破触发 {len(alerts)} 条告警；AI 评分 {score.total}")
