"""SOC-WF-006 — 误报场景：低风险/info 类不被升级

创建一个明确标注为 'scanner-whitelist' / low priority 的 case，验证：
  1. 平台不自动升级为 high/critical
  2. 同标签下，已存在的 case 大多保持 low/medium 级别
"""
import pytest

CASE_ID = "SOC-WF-006"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf, pytest.mark.destructive]


def test_low_priority_not_escalated(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"intent": "create_low_with_scanner_tag_and_verify_no_escalation"})

    findings = target.get_findings(limit=10)
    seed = [f["finding_id"] for f in findings[:1]] if findings else []
    cid = target.create_case(
        title="[WF-006 TEST] Authorized vuln scan from corp scanner",
        description="授权漏洞扫描产生的低风险样本；预期：保持 low/medium，不升级。",
        finding_ids=seed,
        priority="low",
        tags=["wf-006", "scanner-whitelist", "false-positive-probe"],
    )
    rec.vigil({"created_case_id": cid})
    if not cid:
        rec.assertion("case_created", False, "create_case 失败")
        rec.finish("WARN", "无法创建 case（接口暂不可写）")
        score = ai_scorer.score(CASE_ID, "N/A", wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        return

    detail = target.get_case_detail(cid) or {}
    current_priority = (detail.get("priority") or "").lower()
    current_status = (detail.get("status") or "").lower()
    rec.application({"case_detail_priority": current_priority,
                     "case_detail_status": current_status,
                     "case_detail_tags": detail.get("tags")})

    # 同标签下的历史 case 大多 low/medium
    all_cases = target.list_cases(limit=50)
    same_tag = [c for c in all_cases
                if "scanner-whitelist" in (c.get("tags") or [])
                or "false-positive-probe" in (c.get("tags") or [])]
    high_among_same_tag = [c.get("case_id") for c in same_tag
                           if (c.get("priority") or "").lower() in ("high", "critical")]
    rec.gateway({"same_tag_total": len(same_tag),
                 "high_or_critical": high_among_same_tag})

    not_escalated = current_priority in ("low", "medium")
    cohort_clean = len(high_among_same_tag) <= max(1, int(len(same_tag) * 0.2))
    rec.assertion("created_case_not_escalated", not_escalated, current_priority)
    rec.assertion("cohort_mostly_low_medium", cohort_clean,
                  f"high_among_same_tag={len(high_among_same_tag)}/{len(same_tag)}")

    score = ai_scorer.score(CASE_ID, "N/A",
                            wazuh_hits=int(not_escalated and cohort_clean),
                            expected_hits=1)
    rec.set_ai_score(score)
    if not_escalated and cohort_clean:
        rec.finish("PASS", f"case={cid} priority={current_priority}，同标签队列无误升级")
    elif not_escalated:
        rec.finish("WARN", f"本 case 未升级，但同标签历史中有 {len(high_among_same_tag)} 条 high/critical")
    else:
        rec.finish("FAIL", f"case={cid} 已被升级到 {current_priority}（预期 low/medium）")
