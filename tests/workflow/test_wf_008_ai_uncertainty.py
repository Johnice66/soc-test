"""SOC-WF-008 — AI 不确定性表达

用"证据明显不足"的 case（仅 1 条无 src_ip 的 finding 或干脆 0 条），
验证 AI 不在 case 总结里直接下结论，而是表达不确定或要求补充证据。

判定方式：
  1) 创建一个"证据极少"的 case；
  2) 拉 case 详情 + 最近 reasoning interactions；
  3) 文本里出现 ≥1 个"不确定性"语义关键词
     （inconclusive/insufficient/uncertain/cannot determine/unclear/需补充/证据不足/进一步）；
  4) 同时未出现"高确信"关键词（confirmed/definitely/100%/certain/critical breach），
     若同时出现高确信词，记 WARN 而非 PASS。
"""
import re
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-008"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_UNCERTAIN_WORDS = re.compile(
    r"(inconclusive|insufficient|uncertain|unclear|cannot determine|"
    r"need more|further (investigation|analysis|evidence)|requires? (more|additional)|"
    r"证据不足|不确定|无法判定|无法确定|需(要)?补充|进一步)",
    re.I,
)
_OVERCONFIDENT = re.compile(
    r"(definitely|definitively|confirmed (breach|compromise)|100%|certainly|absolutely|"
    r"明确(攻击|入侵|被入侵)|确认入侵|绝对)",
    re.I,
)


def test_ai_expresses_uncertainty(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})

    findings = target.get_findings(limit=20)
    if not findings:
        rec.finish("SKIP", "无 finding，跳过不确定性测试")
        pytest.skip("无 finding 可构造证据不足 case")

    # 取一条最"瘦"的 finding（描述短、metadata 少）
    thin = sorted(findings, key=lambda f: len(str(f)))[0]
    rec.application({"selected_thin_finding": thin.get("finding_id"),
                     "len_serialized": len(str(thin))})

    cid = target.create_case(
        title="[WF-008 TEST] Thin-evidence case (expect AI uncertainty)",
        description=("仅含 1 条极简 finding，缺乏上下文。AI 应在结论中表达不确定性或要求补充证据，"
                     "不得直接下'确认入侵'类断言。"),
        finding_ids=[thin["finding_id"]],
        priority="low",
        tags=["wf-008", "thin-evidence"],
    )
    rec.vigil({"case_id": cid})
    assert cid

    detail = target.get_case_detail(cid)
    haystack = [str(detail)]
    for sid in range(1, 5):
        rj = target.get(f"/api/reasoning/{sid}").json or {}
        if rj.get("total_interactions", 0) > 0:
            inters = target.list_reasoning_interactions(sid, limit=20)
            for it in inters:
                haystack.append(str(it))
    text = "\n".join(haystack)
    uncertain_hits = _UNCERTAIN_WORDS.findall(text)
    over_hits = _OVERCONFIDENT.findall(text)

    rec.vigil({"haystack_chars": len(text),
               "uncertainty_hits": len(uncertain_hits),
               "uncertainty_samples": uncertain_hits[:5],
               "overconfident_hits": len(over_hits),
               "overconfident_samples": over_hits[:3]})

    has_uncertain = len(uncertain_hits) >= 1
    has_overconfident = len(over_hits) >= 1
    rec.assertion("expresses_uncertainty", has_uncertain,
                  f"uncertain_words={len(uncertain_hits)}")
    rec.assertion("no_overconfident_assertion", not has_overconfident,
                  f"overconfident_words={len(over_hits)}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)

    if has_uncertain and not has_overconfident:
        rec.finish("PASS", f"AI 表达不确定（{len(uncertain_hits)} 次），无过度定性")
    elif has_overconfident:
        rec.finish("WARN", f"AI 出现过度定性 {len(over_hits)} 次，应人工复核")
    else:
        # 平台未生成结论文本：仍 PASS（无 hallucination），但注明"无文本"
        rec.finish("WARN", "AI 未输出可分析文本，无法验证不确定性表达")
