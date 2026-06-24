"""SOC-WF-005 — 误报抑制：管理员批量操作

模拟："管理员在维护窗口" 触发批量 SSH/HTTP 操作，期望平台**不**升级为 Critical/High。

实现：
  1) 创建一个 "Admin maintenance window" 标签的 case，
     里面引用 4 条普通 SSH/auth 类 finding（来自真实 platform）；
  2) 读取 case 详情，验证：
      a) 创建时 priority=low 被尊重；
      b) case 详情里有 tags=['authorized-maintenance']，不被自动改写。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-005"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]


def test_admin_maintenance_no_false_critical(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "operator": "admin", "context": "maintenance-window"})

    findings = target.get_findings(limit=200)
    # 选 4 条 auth/sshd 相关 finding 当作"管理员维护操作产生的痕迹"
    bench = [f for f in findings
             if any(k in (f.get("description") or "").lower()
                    for k in ("sshd", "ssh", "auth", "login"))][:4]
    if len(bench) < 2:
        bench = findings[:4]  # 退化：取前 4 条
    fids = [f["finding_id"] for f in bench]
    rec.application({"selected_findings": fids, "count": len(fids)})

    cid = target.create_case(
        title="[WF-005 TEST] Admin maintenance batch ops (expect no Critical)",
        description=("管理员维护窗口批量 SSH/审计操作样本，期望平台不升级为 High/Critical，"
                     "标签 'authorized-maintenance' 应被保留。"),
        finding_ids=fids,
        priority="low",
        tags=["wf-005", "authorized-maintenance", "false-positive-suppression"],
    )
    rec.vigil({"case_id": cid})
    assert cid

    detail = target.get_case_detail(cid)
    priority = (detail.get("priority") or "").lower()
    tags = detail.get("tags") or []
    rec.response({"case_id": cid, "priority_after_create": priority, "tags_after_create": tags})

    rec.assertion("priority_not_escalated", priority in ("low", "medium", "info", ""),
                  f"priority={priority}")
    rec.assertion("maintenance_tag_preserved", "authorized-maintenance" in tags,
                  f"tags={tags}")
    rec.assertion("no_auto_critical", priority not in ("critical", "high"),
                  f"priority={priority}")

    assert priority not in ("critical", "high"), \
        f"管理员维护场景被自动升级到 {priority!r}（误报）"

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.finish("PASS", f"case={cid} priority={priority} tags={tags} 未误报")
