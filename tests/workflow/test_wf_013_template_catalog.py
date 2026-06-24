"""SOC-WF-013 — workflow 模板清单完整性

新增用例。验证 /api/workflows 暴露的 workflow 模板满足生产可用性的最低要求：
  1) 总数 ≥ 3；
  2) 每个 workflow 至少 2 个 agents、5 个 tools_used；
  3) 至少存在 "incident-response" / "full-investigation" / 名字含 "brute" 三类常见 workflow 之一。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-013"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_EXPECTED_FAMILIES = ("incident-response", "full-investigation", "brute")


def test_workflow_template_catalog(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    wfs = target.list_workflows()
    rec.application({"count": len(wfs), "ids": [w.get("id") for w in wfs]})
    assert len(wfs) >= 3, f"workflow 数过少 ({len(wfs)})"

    bad = []
    summary = []
    for w in wfs:
        agents = w.get("agents") or []
        tools = w.get("tools_used") or []
        ok_agents = len(agents) >= 2
        ok_tools = len(tools) >= 5
        summary.append({
            "id": w.get("id"),
            "agents_count": len(agents),
            "tools_count": len(tools),
            "ok_agents": ok_agents,
            "ok_tools": ok_tools,
            "description_len": len(w.get("description") or ""),
        })
        if not (ok_agents and ok_tools):
            bad.append(w.get("id"))

    rec.vigil({"per_workflow": summary, "below_threshold": bad})

    family_hits = [w for w in wfs
                   if any(fam in (w.get("id", "") + w.get("name", "")).lower()
                          for fam in _EXPECTED_FAMILIES)]
    rec.application({"family_match_count": len(family_hits),
                     "family_matches": [w.get("id") for w in family_hits]})

    rec.assertion("total_workflows_ge_3", len(wfs) >= 3, f"count={len(wfs)}")
    rec.assertion("all_workflows_have_agents_and_tools", not bad,
                  f"violators={bad}")
    rec.assertion("expected_family_present", len(family_hits) >= 1,
                  f"matched={[w['id'] for w in family_hits]}")

    assert not bad, f"以下 workflow 元数据不达标: {bad}"
    assert family_hits, f"未发现常见 workflow 家族: {_EXPECTED_FAMILIES}"

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.finish("PASS", f"workflows={len(wfs)} family命中={len(family_hits)} 不达标={len(bad)}")
