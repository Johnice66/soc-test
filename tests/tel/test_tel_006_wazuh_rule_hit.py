"""SOC-TEL-006 — Wazuh 规则命中链路

通过率判定：findings 中应至少覆盖 5 类 Wazuh 规则（参与原 pipeline step 3）。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-TEL-006"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.tel]


_RULE_CATEGORIES = {
    "web_503": lambda d: "503" in d,
    "ssh": lambda d: "sshd" in d.lower(),
    "pam": lambda d: "PAM" in d,
    "integrity": lambda d: "Integrity" in d,
    "apparmor": lambda d: "Apparmor" in d,
    "dpkg": lambda d: "dpkg" in d.lower(),
    "log_rotated": lambda d: "Log file" in d,
    "netstat": lambda d: "netstat" in d.lower(),
    "web_400": lambda d: "400" in d,
}


def test_wazuh_rule_coverage(target, evidence_recorder):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "categories": list(_RULE_CATEGORIES.keys())})
    findings = target.get_findings(limit=300)
    wazuh = [f for f in findings if f.get("data_source") == "wazuh"]
    desc = [f.get("description") or "" for f in wazuh]
    cov = {k: sum(1 for d in desc if f(d)) for k, f in _RULE_CATEGORIES.items()}
    covered = sum(1 for v in cov.values() if v)
    rec.wazuh({"wazuh_findings": len(wazuh), "coverage": cov, "covered_categories": covered})
    rec.assertion("min_5_categories", covered >= 5, f"{covered}/{len(_RULE_CATEGORIES)}")
    assert covered >= 5, f"Wazuh 规则覆盖不足：{covered}/{len(_RULE_CATEGORIES)}"
    rec.finish("PASS", f"{covered}/{len(_RULE_CATEGORIES)} 类规则覆盖；wazuh findings={len(wazuh)}")
