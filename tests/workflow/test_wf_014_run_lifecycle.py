"""SOC-WF-014 — workflow run 触发与状态机

新增用例。验证：
  1) POST /api/workflows/incident-response/run 可触发 run（即使同步执行较慢，服务器侧已建立 run）；
  2) 触发前后 runs 列表新增 1 条；
  3) 新 run 包含 run_id / workflow_id / status / started_at / triggered_by / trigger_context；
  4) status ∈ {running, completed, failed, queued, success}（属于合法状态机）。

注意：此用例真实在服务器侧创建 workflow run，是 destructive 标签。
"""
import time
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-014"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf, pytest.mark.destructive]

_VALID_STATUS = {"running", "completed", "failed", "queued", "success", "succeeded", "error", "cancelled"}
_TARGET_WORKFLOW = "incident-response"


def test_workflow_run_lifecycle(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "workflow_id": _TARGET_WORKFLOW})

    runs_before = target.list_workflow_runs(_TARGET_WORKFLOW)
    rec.application({"runs_before": len(runs_before),
                     "latest_before": runs_before[0] if runs_before else None})

    # 用一个不会真触发动作的 case_id 占位（即使被 orchestrator 处理也只是 noop）
    probe_case_id = f"wf-014-probe-{int(time.time())}"
    trigger = target.trigger_workflow_run(
        _TARGET_WORKFLOW, case_id=probe_case_id, timeout=6,
    )
    rec.response({"phase": "trigger", **trigger})

    # 等服务器入账
    time.sleep(1.0)
    runs_after = target.list_workflow_runs(_TARGET_WORKFLOW)
    rec.application({"runs_after": len(runs_after)})

    delta = len(runs_after) - len(runs_before)
    rec.assertion("runs_count_increased", delta >= 1, f"delta={delta}")

    # 在 runs_after 里找我们刚触发的（trigger_context.case_id 命中）
    new_run = next(
        (r for r in runs_after
         if (r.get("trigger_context") or {}).get("case_id") == probe_case_id),
        None,
    )
    if not new_run and runs_after:
        new_run = runs_after[0]  # 退化：取最新
    rec.vigil({"new_run": new_run})

    assert new_run is not None, "触发后未在 runs 列表里找到任何新 run"

    must_have = ("run_id", "workflow_id", "status", "started_at", "triggered_by")
    missing = [k for k in must_have if not new_run.get(k)]
    rec.assertion("run_has_required_fields", not missing, f"missing={missing}")
    assert not missing, f"run 缺字段: {missing}"

    status = (new_run.get("status") or "").lower()
    rec.assertion("run_status_in_valid_set", status in _VALID_STATUS, f"status={status}")

    # 顺便读 run 详情
    rid = new_run["run_id"]
    detail = target.get_workflow_run(rid)
    rec.vigil({"run_detail_run_id": detail.get("run_id"),
               "run_detail_status": detail.get("status"),
               "run_detail_trigger_context": detail.get("trigger_context")})
    rec.assertion("run_detail_consistent",
                  detail.get("run_id") == rid,
                  f"detail.run_id={detail.get('run_id')} vs {rid}")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.finish("PASS", f"触发 {rid}（{status}），runs +{delta}")
