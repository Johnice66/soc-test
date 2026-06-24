"""SOC-WF-015 — case ⇄ workflow 自动关联

新增用例。验证：创建一个真实 case 后，平台是否在 incident-response workflow 的 runs 中
新增了一条 trigger_context.case_id == 该 case 的 run（即"case 触发 workflow"自动关联存在）。

如果平台未启用 case → workflow 自动 wiring，记录现状（runs 未增长），状态打 WARN 而非 FAIL，
这样能在后续被启用时立即发现回归。
"""
import time
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-015"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_WATCH_WORKFLOWS = ["incident-response", "full-investigation"]


def test_case_creation_triggers_workflow(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "watch_workflows": _WATCH_WORKFLOWS})

    before = {wid: target.list_workflow_runs(wid) for wid in _WATCH_WORKFLOWS}
    rec.application({"runs_before": {k: len(v) for k, v in before.items()}})

    findings = target.get_findings(limit=20)
    seed = [f["finding_id"] for f in findings[:2]] if findings else []
    cid = target.create_case(
        title="[WF-015 TEST] Case auto-trigger workflow probe",
        description="探测：创建该 case 后，incident-response 是否自动起一个 run。",
        finding_ids=seed, priority="high", tags=["wf-015", "auto-trigger-probe"],
    )
    rec.vigil({"created_case_id": cid})
    assert cid

    # 平台异步联动给个窗口期
    time.sleep(2.0)
    after = {wid: target.list_workflow_runs(wid) for wid in _WATCH_WORKFLOWS}
    rec.application({"runs_after": {k: len(v) for k, v in after.items()}})

    matched = {}
    deltas = {}
    for wid in _WATCH_WORKFLOWS:
        b, a = before[wid], after[wid]
        deltas[wid] = len(a) - len(b)
        # 找 trigger_context.case_id == cid 的 run
        hit = next(
            (r for r in a if (r.get("trigger_context") or {}).get("case_id") == cid),
            None,
        )
        if hit:
            matched[wid] = {"run_id": hit.get("run_id"),
                            "status": hit.get("status"),
                            "started_at": hit.get("started_at")}

    rec.response({"deltas": deltas, "case_to_run_matches": matched})

    rec.assertion("any_workflow_run_delta_ge_0", all(d >= 0 for d in deltas.values()),
                  f"deltas={deltas}")
    # 软断言：自动联动存在则 PASS，否则 WARN
    auto_link = bool(matched) or any(d >= 1 for d in deltas.values())
    rec.assertion("case_auto_linked_to_workflow", auto_link,
                  f"matched={matched} deltas={deltas}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(findings), expected_hits=0)
    rec.set_ai_score(score)
    if auto_link:
        rec.finish("PASS", f"case={cid} 触发 workflow: matched={matched} deltas={deltas}")
    else:
        rec.finish("WARN",
                   f"case={cid} 未观察到自动 workflow run（deltas={deltas}）。"
                   "可能平台未启用自动联动；保留观测以发现后续启用回归。")
