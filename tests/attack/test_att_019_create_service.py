"""SOC-ATT-019 — 创建/修改系统服务 (T1543)

执行：在被测主机创建一个伪 systemd unit 并 enable
验收：Wazuh 应能识别 /etc/systemd/system/ 下的新文件 (FIM 5900x / Integrity)
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-019"
MITRE = "T1543"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_create_systemd_service(ssh_host, wazuh, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    svc = "soc-test-fake.service"
    create = ssh_host.run(
        f"echo '[Unit]\\nDescription=SOC test\\n[Service]\\nExecStart=/bin/true' | "
        f"sudo tee /etc/systemd/system/{svc} >/dev/null && sudo systemctl daemon-reload"
    )
    cleanup = ssh_host.run(f"sudo rm -f /etc/systemd/system/{svc} && sudo systemctl daemon-reload")
    rec.client({"create_exit": create.exit_code, "cleanup_exit": cleanup.exit_code})

    alerts = wazuh.wait_alerts(rule_description_like="systemd", min_count=1, timeout_seconds=60)
    if not alerts:
        alerts = wazuh.wait_alerts(rule_description_like="Integrity", min_count=1, timeout_seconds=30)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "desc": a.description} for a in alerts])
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(alerts), expected_hits=1,
                            wazuh_max_level=max((a.rule_level for a in alerts), default=0))
    rec.set_ai_score(score)
    rec.assertion("service_change_detected", len(alerts) >= 1, f"alerts={len(alerts)}")
    assert len(alerts) >= 1
    rec.finish("PASS", f"系统服务变更触发 {len(alerts)} 条告警")
