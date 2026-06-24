"""SOC-WF-001 — 单条 High 告警生成 case

验证：
  1) GET /api/findings/?level=high 返回 ≥1 条；
  2) 选第一条创建 case，case_id 立即可读；
  3) 该 case 与 finding 形成"高严重度 → case"的可追踪链。

不破坏：仅用 [WF-001 TEST] 前缀创建测试 case，平台层不自动执行任何响应。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-001"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]


def test_high_alert_creates_case(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})

    # 1) 拉 High 严重度的 findings
    high = target.get_findings(limit=20, severity="high")
    if not high:
        high = [f for f in target.get_findings(limit=200)
                if (f.get("severity") or f.get("level") or "").lower() in ("high", "critical")]
    rec.wazuh({"high_findings_count": len(high),
               "sample_alert_ids": [target.parse_wazuh_alert_id(f.get("finding_id", "")) for f in high[:5]]})
    rec.assertion("high_findings_present", len(high) >= 1, f"count={len(high)}")
    assert len(high) >= 1, "没有 High/Critical 严重度的 finding，平台数据为空"

    # 2) 选第一条创建 case
    src = high[0]
    fid = src["finding_id"]
    cid = target.create_case(
        title="[WF-001 TEST] Single High alert -> case",
        description=f"自动化用例：基于单条 High finding {fid} 生成 case 以验证 WF-001 流程。",
        finding_ids=[fid],
        priority="high",
        tags=["wf-001", "single-high"],
    )
    rec.vigil({"created_case_id": cid, "source_finding_id": fid,
               "source_severity": src.get("severity") or src.get("level")})
    rec.assertion("case_created", bool(cid), f"case_id={cid}")
    assert cid

    # 3) 立即读 case 详情，验证关联
    detail = target.get_case_detail(cid)
    linked = detail.get("finding_ids") or []
    rec.vigil({"case_detail_finding_ids": linked, "title": detail.get("title")})
    rec.assertion("case_links_back_to_finding", fid in linked, f"linked={linked}")
    assert fid in linked, f"case {cid} 未正确关联 finding {fid}"

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=1, expected_hits=1,
                            wazuh_max_level=12 if src.get("severity") == "critical" else 8)
    rec.set_ai_score(score)
    rec.finish("PASS", f"High finding={fid} → case={cid}，链路完整")
