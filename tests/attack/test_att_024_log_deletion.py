"""SOC-ATT-024 — 删除日志文件尝试 (T1070)

执行：尝试 truncate / rm /var/log/auth.log（受控，立即恢复）
验收：Wazuh FIM 或 audit 应能识别删除/截断
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-024"
MITRE = "T1070"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_log_deletion_detected(ssh_host, wazuh, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "warning": "dry-run 模式下不会真的截断 auth.log"})
    # 不真的删 /var/log/auth.log；改为创建一个测试文件并删除以触发 FIM
    cmd = (
        "sudo touch /var/log/soc-test-marker.log && "
        "sudo truncate -s 0 /var/log/soc-test-marker.log && "
        "sudo rm -f /var/log/soc-test-marker.log"
    )
    r = ssh_host.run(cmd, timeout=30)
    rec.client({"exit_code": r.exit_code})

    alerts = wazuh.wait_alerts(rule_description_like="Integrity", min_count=1, timeout_seconds=60)
    if not alerts:
        alerts = wazuh.wait_alerts(rule_description_like="Log file", min_count=1, timeout_seconds=30)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "desc": a.description} for a in alerts])
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(alerts), expected_hits=1,
                            wazuh_max_level=max((a.rule_level for a in alerts), default=0))
    rec.set_ai_score(score)
    rec.assertion("log_change_detected", len(alerts) >= 1, f"alerts={len(alerts)}")
    assert len(alerts) >= 1
    rec.finish("PASS", f"日志文件变更触发 {len(alerts)} 条告警")
