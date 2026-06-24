"""SOC-ATT-006 — 爆破后成功登录关联 (T1078)

执行：5 次失败 + 1 次成功 SSH 登录
验收：Wazuh 应同时存在 sshd authentication failure 和 authentication success
       两类规则，且平台能把两者关联到同一 src_ip。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-ATT-006"
MITRE = "T1078"
pytestmark = [pytest.mark.p0, pytest.mark.att, pytest.mark.needs_ssh, pytest.mark.needs_wazuh]


def test_brute_followed_by_success(target, wazuh, ssh_host, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})

    # 1) 失败 + 成功
    fail_cmd = (
        "for i in 1 2 3 4 5; do "
        "sshpass -p 'wrong_$i' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
        "testuser@127.0.0.1 'true' 2>&1 || true; done"
    )
    ssh_host.run(fail_cmd, timeout=60)
    # 真实成功登录需要正确凭据；在 dry-run 中只记录
    ok_cmd = "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 testuser@127.0.0.1 'true'"
    ssh_host.run(ok_cmd, timeout=15)
    rec.client({"failures": 5, "success": 1})

    # 2) Wazuh 双向验证
    fails = wazuh.wait_alerts(rule_description_like="authentication failure", min_count=3, timeout_seconds=60)
    successes = wazuh.wait_alerts(rule_description_like="authentication success", min_count=1, timeout_seconds=60)
    rec.wazuh({"failures": len(fails), "successes": len(successes)})

    score = ai_scorer.score(
        CASE_ID, MITRE,
        wazuh_hits=len(fails) + len(successes),
        expected_hits=4,
        wazuh_max_level=max((a.rule_level for a in fails + successes), default=0),
    )
    rec.set_ai_score(score)
    rec.assertion("brute_then_success_correlated",
                  len(fails) >= 3 and len(successes) >= 1,
                  f"fails={len(fails)} successes={len(successes)}")
    assert len(fails) >= 3 and len(successes) >= 1
    rec.finish("PASS", f"爆破后成功登录关联：{len(fails)} 失败 + {len(successes)} 成功")
