"""SOC-TEL-001 — Linux SSH 认证日志采集

通过率判定：findings 接口中存在 description 包含 'sshd' 的 wazuh 来源记录，
说明 Wazuh 已经把 auth.log/secure 中的 SSH 认证日志解析并转发到平台。
此用例为 HTTP-only：不强依赖 SSH 凭据。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-TEL-001"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.tel]


def test_linux_ssh_auth_collected(target, evidence_recorder):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    findings = target.get_findings(limit=200)
    sshd = [f for f in findings if "sshd" in (f.get("description") or "").lower()]
    rec.wazuh({"total": len(findings), "sshd_findings": len(sshd),
               "samples": [{"id": f.get("finding_id"), "desc": f.get("description")} for f in sshd[:3]]})
    rec.assertion("has_sshd_findings", len(sshd) >= 1, f"sshd findings = {len(sshd)}")
    assert len(sshd) >= 1, "Wazuh 没有 sshd 相关 findings → 采集链路未通"
    rec.finish("PASS", f"sshd 相关 findings {len(sshd)} 条")
