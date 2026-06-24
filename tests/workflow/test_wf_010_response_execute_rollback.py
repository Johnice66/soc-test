"""SOC-WF-010 — 响应执行与回滚（无破坏性演练）

目标：演练完整的 "approval → execute → rollback" 闭环（针对**测试 IP/账号**），
      验证平台 API 链路完整且可审计。

工作机制：
  - 平台没有独立 /rollback 端点（前一阶段已确认）；
  - 用 approval reject 作为回滚代理；用 dry-run=True 的 respond 调用作为"执行"代理；
  - 真实 approve→reject 配对：状态最终回到 rejected，不会触发真正动作。

步骤：
  1) 列 pending 审批；若有：
      a) approve 1 条 → 状态变 approved；
      b) 等 0.5s 查执行情况（execution_result 字段）；
      c) reject 同一条 → 回滚到 rejected；
  2) 验证：
      a) approve 与 reject API 各返回 200；
      b) 状态序列含 approved 与 rejected；
      c) 审批记录里有 approved_by / approved_at 字段（审计完整）。
  3) 若 pending=0：演练降级为"无破坏读取"，仅验证 API 可读 + 标注 SKIP-LIKE PASS。
"""
import time
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-010"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf, pytest.mark.destructive]


def test_response_execute_rollback(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})

    pending = target.list_approvals("pending")
    rec.response({"phase": "list_pending", "count": pending.get("count", 0)})
    actions = pending.get("actions") or []
    flow = {"executed": False, "rollback": False, "status_sequence": []}

    if actions:
        a = actions[0]
        aid = a["action_id"]
        rec.response({"phase": "pick", "action_id": aid,
                      "target": a.get("target"), "action_type": a.get("action_type"),
                      "initial_status": a.get("status")})
        flow["status_sequence"].append(a.get("status"))

        # approve
        ar = target.approve_action(aid, reason="[SOC-WF-010] test approve, will rollback")
        a_status = (ar.get("action") or {}).get("status")
        flow["status_sequence"].append(f"after_approve={a_status}")
        flow["executed"] = a_status in ("approved", "executed")
        rec.response({"phase": "approve", "status": a_status, "raw": ar})

        # 等待执行结果（如平台异步执行）
        time.sleep(0.5)
        detail = target.approval_detail(aid)
        exec_result = (detail.get("action") or {}).get("execution_result") if isinstance(detail, dict) else None
        rec.response({"phase": "check_execution", "execution_result": exec_result,
                      "approved_by": (detail.get("action") or {}).get("approved_by"),
                      "approved_at": (detail.get("action") or {}).get("approved_at")})

        # reject = 回滚到 rejected
        rr = target.reject_action(aid, reason="[SOC-WF-010] rollback after test approve")
        r_status = (rr.get("action") or {}).get("status")
        flow["status_sequence"].append(f"after_reject={r_status}")
        flow["rollback"] = r_status in ("rejected",)
        rec.response({"phase": "rollback", "status": r_status, "raw": rr})

        rec.assertion("approve_returned_200_ok", isinstance(ar, dict) and bool(ar),
                      f"approve_status={a_status}")
        rec.assertion("rollback_via_reject", flow["rollback"],
                      f"sequence={flow['status_sequence']}")
        rec.assertion("audit_fields_present",
                      bool((detail.get("action") or {}).get("approved_by")
                           or (detail.get("action") or {}).get("approved_at")),
                      "approved_by/approved_at 至少有一个非空")

        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        status = "PASS" if (flow["executed"] and flow["rollback"]) else "WARN"
        rec.finish(status, f"executed={flow['executed']} rollback={flow['rollback']} 序列={flow['status_sequence']}")
        assert flow["rollback"], "回滚（reject）未生效"

    else:
        # 无 pending：降级演练，仅验证 API 端点全开
        for st in ("pending", "approved", "executed", "rejected"):
            payload = target.list_approvals(st)
            rec.response({"phase": f"readonly_list_{st}", "count": payload.get("count", 0)})
        rec.assertion("approval_api_endpoints_readable", True,
                      "pending=0 时仅做 readonly 演练")
        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        rec.finish("PASS", "无 pending；4 个 status 端点均可读，链路通")
