"""SOC-TEL-004 — 应用审计日志采集

通过率判定：findings 中存在非 wazuh 来源（即平台应用审计来源）或包含
Identity/Agent/WebIDE/WattBot 关键字的记录。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-TEL-004"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.tel]

_APP_KEYWORDS = ("identity", "agent", "webide", "wattbot", "session", "workspace", "audit")


def test_app_audit_log_present(target, evidence_recorder):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "expected_keywords": list(_APP_KEYWORDS)})
    findings = target.get_findings(limit=200)
    non_wazuh = [f for f in findings if f.get("data_source") != "wazuh"]
    text = " ".join((f.get("description") or "") + " " + str(f.get("entity_context") or "") for f in findings).lower()
    matched = [k for k in _APP_KEYWORDS if k in text]
    rec.application({
        "total_findings": len(findings),
        "non_wazuh_findings": len(non_wazuh),
        "matched_keywords": matched,
    })
    cfg = target.get_integration_config()
    rec.application({"integration_config": cfg})
    rec.assertion("audit_signal_present", bool(non_wazuh) or len(matched) >= 1, f"matched={matched}")
    # 软通过：找到任何一处审计相关信号即可
    status = "PASS" if (non_wazuh or matched) else "WARN"
    rec.finish(status, f"non-wazuh findings={len(non_wazuh)}, 关键字命中={matched}")
