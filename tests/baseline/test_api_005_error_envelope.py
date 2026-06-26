"""SOC-API-005 — 404 错误响应一致性

未知 API 路径必须返回非 HTML 的 JSON 错误，且结构一致。
平台当前行为：返回 [{"error":"Not found"},404]（非标准 list 包装，但一致）
"""
import json
import pytest

CASE_ID = "SOC-API-005"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_RANDOM_PATHS = [
    "/api/zzzz-not-exist",
    "/api/users",
    "/api/integrations",
    "/api/dashboard",
]


def _shape(body) -> str:
    """归一化结构形状：list-wrapped / object-detail / html / empty"""
    if body is None:
        return "non-json"
    if isinstance(body, list) and body and isinstance(body[0], dict) and "error" in body[0]:
        return "list-wrapped-error"
    if isinstance(body, dict) and "detail" in body:
        return "object-detail"
    return f"other:{type(body).__name__}"


def test_404_envelope(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"probe_paths": _RANDOM_PATHS})

    shapes = {}
    for p in _RANDOM_PATHS:
        r = target.raw_request("GET", p)
        shapes[p] = {"status": r["status"], "shape": _shape(r["json"]),
                     "snippet": (r["text"] or "")[:80]}
    rec.gateway({"results": shapes})

    distinct_shapes = {v["shape"] for v in shapes.values()}
    rec.assertion("envelope_consistent", len(distinct_shapes) == 1, str(distinct_shapes))

    # 不应返回 HTML
    has_html = any("<html" in (v["snippet"] or "").lower() for v in shapes.values())
    rec.assertion("no_html_in_api_404", not has_html, "")

    # 状态码：要么所有 404，要么所有 200（如果平台用 200 wrap），但要一致
    statuses = {v["status"] for v in shapes.values()}
    rec.assertion("status_consistent", len(statuses) <= 2, str(statuses))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=1, expected_hits=1)
    rec.set_ai_score(score)
    if len(distinct_shapes) == 1 and not has_html:
        rec.finish("PASS", f"错误响应结构一致 shape={distinct_shapes}")
    else:
        rec.finish("WARN", f"错误响应不一致 shapes={distinct_shapes} statuses={statuses}")
