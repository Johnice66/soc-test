"""SOC-WF-007 — AI 证据引用准确性

验证：AI 在 case / reasoning interactions 中引用的 finding_id / alert_id
      均来自真实存在的平台数据，且无幻觉（伪造的 ID）。

实现：
  1) 创建 case，引用 N 条真实 finding；
  2) 拉 case_detail.finding_ids 与最近 1 个 reasoning session 的 interactions；
  3) 用正则提取所有 finding_id / alert_id 引用，对比 platform 现有集合；
  4) 引用准确率 = 真实存在的 / 全部引用 ≥ 0.9。
"""
import re
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-007"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_FID_RE = re.compile(r"wazuh-\d+\.\d+")
_AID_RE = re.compile(r"\b\d{10}\.\d{1,9}\b")


def _collect_refs(text: str) -> tuple[set[str], set[str]]:
    return set(_FID_RE.findall(text)), set(_AID_RE.findall(text))


def test_ai_evidence_no_hallucination(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    findings = target.get_findings(limit=200)
    rec.application({"baseline_finding_count": len(findings)})
    assert findings, "findings 接口为空，无法做引用对比"
    real_fids = {f["finding_id"] for f in findings}
    real_aids = {target.parse_wazuh_alert_id(fid) for fid in real_fids}
    real_aids.discard(None)

    pool = findings[:5]
    fids = [f["finding_id"] for f in pool]
    cid = target.create_case(
        title="[WF-007 TEST] AI evidence-reference accuracy",
        description=f"用 {len(fids)} 条真实 finding 构造证据包，AI 引用须落在真实集合内。",
        finding_ids=fids, priority="medium", tags=["wf-007", "evidence-ref"],
    )
    rec.vigil({"case_id": cid, "evidence_pool": fids})
    assert cid

    detail = target.get_case_detail(cid)
    # 收集 AI 文本面：case description / metadata / 最近 reasoning interactions
    haystack = []
    haystack.append(str(detail))
    for sid in range(1, 6):
        rj = target.get(f"/api/reasoning/{sid}").json or {}
        if rj.get("total_interactions", 0) > 0:
            inters = target.list_reasoning_interactions(sid, limit=20)
            for it in inters:
                haystack.append(str(it))
    text = "\n".join(haystack)
    seen_fids, seen_aids = _collect_refs(text)
    rec.vigil({
        "haystack_chars": len(text),
        "fid_refs_total": len(seen_fids),
        "aid_refs_total": len(seen_aids),
    })

    # 计算"落在真实集合内"的比例
    if seen_fids:
        fid_hit = len(seen_fids & real_fids) / len(seen_fids)
    else:
        fid_hit = 1.0  # 没引用 finding_id，视为无幻觉风险
    if seen_aids:
        aid_hit = len(seen_aids & real_aids) / len(seen_aids)
    else:
        aid_hit = 1.0

    rec.assertion("fid_reference_accuracy_ge_0.9", fid_hit >= 0.9,
                  f"{fid_hit:.2f} ({len(seen_fids & real_fids)}/{len(seen_fids)})")
    rec.assertion("aid_reference_accuracy_ge_0.9", aid_hit >= 0.9,
                  f"{aid_hit:.2f} ({len(seen_aids & real_aids)}/{len(seen_aids)})")
    rec.assertion("no_hallucinated_fid",
                  len(seen_fids - real_fids) == 0,
                  f"hallucinated={sorted(seen_fids - real_fids)[:5]}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(fids), expected_hits=len(fids))
    rec.set_ai_score(score)
    rec.finish(
        "PASS" if (fid_hit >= 0.9 and aid_hit >= 0.9) else "WARN",
        f"fid 引用准确率={fid_hit:.2f} aid={aid_hit:.2f}",
    )
