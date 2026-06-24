"""SOC-ATT-017 — 新增本地用户 (T1136)

执行：在被测主机执行 useradd / adduser 创建一个测试账号
验收：Wazuh 应触发 5902 (new user added) 或类似规则
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-017"
MITRE = "T1136"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_add_local_user(ssh_host, wazuh, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    test_user = "soc_test_user"
    add = ssh_host.run(f"sudo useradd -m {test_user} 2>&1; id {test_user} || true")
    cleanup = ssh_host.run(f"sudo userdel -r {test_user} 2>&1 || true")
    rec.client({"add_exit": add.exit_code, "cleanup_exit": cleanup.exit_code})

    alerts = wazuh.wait_alerts(rule_description_like="user added", min_count=1, timeout_seconds=60)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "desc": a.description} for a in alerts])
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(alerts), expected_hits=1,
                            wazuh_max_level=max((a.rule_level for a in alerts), default=0))
    rec.set_ai_score(score)
    rec.assertion("user_added_detected", len(alerts) >= 1, f"alerts={len(alerts)}")
    assert len(alerts) >= 1
    rec.finish("PASS", f"useradd 触发 {len(alerts)} 条告警")
