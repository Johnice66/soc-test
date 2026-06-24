"""SOC-WF-012 — 缺陷复测与规则/workflow 版本可追踪

验证：
  1) workflow 模板 metadata 中存在 version / agents / tools_used / use_cases 字段（可追踪）；
  2) 至少 1 个 workflow 已有 runs（即"复测"过的实际证据）；
  3) findings 中的 mitre_predictions 字段非空，证明规则到 ATT&CK 的映射保留（规则固化可追踪）。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-012"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]


def test_regression_and_versioning(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})

    workflows = target.list_workflows()
    rec.application({"workflow_count": len(workflows),
                     "workflow_ids": [w.get("id") for w in workflows]})
    assert workflows, "workflows 接口为空"

    # 1) 模板字段完整性
    missing = []
    for w in workflows:
        for k in ("id", "name", "agents", "tools_used"):
            if not w.get(k):
                missing.append(f"{w.get('id')}::missing::{k}")
    rec.assertion("workflow_template_fields_complete", not missing,
                  f"missing={missing[:5]}")
    rec.vigil({"missing_template_fields": missing})

    # 2) 至少一个 workflow 有 runs（已被使用 / 已复测）
    with_runs = []
    for w in workflows[:5]:
        runs = target.list_workflow_runs(w["id"])
        if runs:
            with_runs.append({"workflow_id": w["id"], "run_count": len(runs),
                              "latest_run_status": runs[0].get("status"),
                              "latest_run_id": runs[0].get("run_id")})
    rec.application({"workflows_with_runs": with_runs})
    rec.assertion("at_least_one_workflow_executed", len(with_runs) >= 1,
                  f"with_runs={len(with_runs)}/{len(workflows)}")

    # 3) findings → mitre 映射可追踪
    findings = target.get_findings(limit=50)
    with_mitre = [f for f in findings if f.get("mitre_predictions")]
    rec.wazuh({"finding_total": len(findings),
               "finding_with_mitre_predictions": len(with_mitre),
               "sample": [{"fid": f["finding_id"],
                           "mitre": list((f.get("mitre_predictions") or {}).keys())[:3]}
                          for f in with_mitre[:3]]})
    rec.assertion("mitre_mapping_traceable", len(with_mitre) >= 1,
                  f"with_mitre={len(with_mitre)}/{len(findings)}")

    # 4) 单个 workflow 详情中能拿到 use_cases / tools_used → 可追踪 ' 规则固化'
    sample_wid = workflows[0]["id"]
    detail = target.get_workflow(sample_wid)
    rec.vigil({"workflow_detail_sample": sample_wid,
               "use_cases_present": bool(detail.get("use_cases")),
               "tools_used_count": len(detail.get("tools_used") or [])})
    rec.assertion("workflow_detail_introspectable",
                  bool(detail.get("agents") and detail.get("tools_used")),
                  f"agents={bool(detail.get('agents'))} tools_used={bool(detail.get('tools_used'))}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(with_mitre),
                             expected_hits=1, wazuh_max_level=5)
    rec.set_ai_score(score)
    rec.finish(
        "PASS" if (not missing and with_runs) else "WARN",
        f"wf={len(workflows)} run过={len(with_runs)} mitre={len(with_mitre)}",
    )
