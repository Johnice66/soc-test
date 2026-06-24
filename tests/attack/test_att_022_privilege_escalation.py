"""SOC-ATT-022 — 异常提权尝试 (T1548)

执行：用受控账号尝试 sudo -k && sudo -n 探测 / 多次 sudo 失败
验收：Wazuh 应触发 sudo 相关 (5400/5402) 或 PAM 失败规则
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-022"
MITRE = "T1548"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_sudo_abuse(ssh_host, wazuh, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    # 模拟：连续 sudo 失败
    cmd = (
        "for i in 1 2 3; do "
        "echo wrongpw | sudo -k -S whoami 2>&1 || true; done"
    )
    r = ssh_host.run(cmd, timeout=30)
    rec.client({"exit_code": r.exit_code})

    alerts = wazuh.wait_alerts(rule_description_like="sudo", min_count=1, timeout_seconds=60)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "desc": a.description} for a in alerts])
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(alerts), expected_hits=1,
                            wazuh_max_level=max((a.rule_level for a in alerts), default=0))
    rec.set_ai_score(score)
    rec.assertion("sudo_abuse_detected", len(alerts) >= 1, f"alerts={len(alerts)}")
    assert len(alerts) >= 1
    rec.finish("PASS", f"sudo 异常触发 {len(alerts)} 条告警")
