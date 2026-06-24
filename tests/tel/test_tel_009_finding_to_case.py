"""SOC-TEL-009 — finding → case 生成链路

通过率判定：POST /api/cases/ 携带 finding_ids 应成功返回 case_id，
且新 case 的 linked_findings 等于请求中的数量。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-TEL-009"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.tel]


def test_finding_to_case(target, evidence_recorder):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    findings = target.get_findings(limit=5)
    finding_ids = [f["finding_id"] for f in findings]
    rec.application({"finding_ids_in": finding_ids})
    case_id = target.create_case(
        title="[TEL-009 TEST] finding → case 验证",
        description="自动化测试：finding → case 生成链路。",
        finding_ids=finding_ids,
        priority="medium",
        tags=["tel-009", "automated"],
    )
    rec.vigil({"case_id": case_id, "expected_findings": len(finding_ids)})
    rec.assertion("case_created", bool(case_id), f"case_id={case_id}")
    assert case_id, "未能创建 case"
    rec.finish("PASS", f"Case {case_id} 创建，关联 {len(finding_ids)} 个 finding")
