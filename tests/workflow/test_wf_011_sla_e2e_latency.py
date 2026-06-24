"""SOC-WF-011 — 端到端 SLA 延迟度量

测量平台关键 API 的响应延迟，作为端到端 SLA 的近似指标。

测量项：
  1) findings 列表 ≤ 2s
  2) cases 列表 ≤ 2s
  3) 创建 case 端到端 ≤ 4s
  4) 创建 case 后立即读详情 ≤ 2s
  5) approvals 列表 ≤ 2s

SLA 验收：5 项中至少 4 项达标。
"""
import time
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-011"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_TARGETS_MS = {
    "findings_list": 2000,
    "cases_list": 2000,
    "case_create_e2e": 4000,
    "case_detail_read": 2000,
    "approvals_list": 2000,
}


def _ms(fn):
    t0 = time.perf_counter()
    result = fn()
    return (time.perf_counter() - t0) * 1000, result


def test_e2e_latency_sla(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "targets_ms": _TARGETS_MS})

    measurements: dict[str, float] = {}

    measurements["findings_list"], findings = _ms(lambda: target.get_findings(limit=20))
    measurements["cases_list"], _ = _ms(lambda: target.list_cases(limit=20))

    seed_fids = [f["finding_id"] for f in findings[:2]] if findings else []
    measurements["case_create_e2e"], cid = _ms(lambda: target.create_case(
        title="[WF-011 TEST] SLA latency probe",
        description="自动化 SLA 探测用 case。",
        finding_ids=seed_fids, priority="low", tags=["wf-011", "sla-probe"],
    ))
    measurements["case_detail_read"], detail = _ms(lambda: target.get_case_detail(cid) if cid else {})
    measurements["approvals_list"], _ = _ms(lambda: target.list_approvals("pending"))

    pass_count = 0
    rows = []
    for key, ms in measurements.items():
        target_ms = _TARGETS_MS[key]
        ok = ms <= target_ms
        if ok:
            pass_count += 1
        rows.append({"metric": key, "ms": round(ms, 1), "target_ms": target_ms, "ok": ok})
        rec.assertion(f"sla_{key}_le_{target_ms}ms", ok, f"{ms:.1f}ms")

    rec.gateway({"measurements": rows, "pass_count": pass_count, "total": len(rows)})

    sla_ok = pass_count >= 4
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(findings), expected_hits=1)
    rec.set_ai_score(score)
    rec.finish("PASS" if sla_ok else "WARN",
               f"SLA pass {pass_count}/{len(rows)}: {[(r['metric'], r['ms']) for r in rows]}")
    assert sla_ok, f"SLA 未通过: {rows}"
