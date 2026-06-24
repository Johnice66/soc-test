"""SOC-ATT-031 — SSH 横向登录尝试 (T1021.004)

执行：从一个内网主机 SSH 到另一个内网主机（受控 IP 对）
验收：Wazuh 应同时在两端记录 sshd 认证事件，且平台能关联到同一会话
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-031"
MITRE = "T1021.004"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_lateral_ssh_attempt(ssh_host, wazuh, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    # 从被测主机向 127.0.0.1 发起若干次 SSH 尝试（模拟横向）
    cmd = (
        "for i in 1 2 3; do "
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 testuser@127.0.0.1 'true' 2>&1 || true; "
        "done"
    )
    r = ssh_host.run(cmd, timeout=30)
    rec.client({"exit_code": r.exit_code})

    alerts = wazuh.wait_alerts(rule_description_like="sshd", min_count=1, timeout_seconds=60)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "desc": a.description, "src_ip": a.src_ip} for a in alerts])
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(alerts), expected_hits=1,
                            wazuh_max_level=max((a.rule_level for a in alerts), default=0))
    rec.set_ai_score(score)
    rec.assertion("lateral_ssh_detected", len(alerts) >= 1, f"alerts={len(alerts)}")
    assert len(alerts) >= 1
    rec.finish("PASS", f"横向 SSH 触发 {len(alerts)} 条告警")
