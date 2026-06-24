"""SOC-AI-005 — 外部伪造 X-User-* 可信头 (T1556 部分映射)

执行：构造 X-User-Id / X-Workspace-Id / X-User-Role=admin 等"可信头"
      访问敏感 API，验证服务端是否真把请求来源信任为 admin。
"""
import pytest
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-AI-005"
MITRE = "T1556"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]


_FORGED_HEADERS = {
    "X-User-Id": "1",
    "X-User-Role": "admin",
    "X-Workspace-Id": "default",
    "X-Tenant-Id": "anthropic",
    "X-Forwarded-User": "admin",
    "X-Auth-User": "admin",
}
_SENSITIVE = [
    "/api/config/integrations",
    "/api/orchestrator/status",
    "/api/cases/",
]


def test_forged_trusted_header_not_honored(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID), "forged": _FORGED_HEADERS})
    suspicious = []
    for p in _SENSITIVE:
        r_plain = target.get(p)
        r_forged = target.get(p, headers=_FORGED_HEADERS)
        diff = {
            "path": p,
            "status_plain": r_plain.status_code,
            "status_forged": r_forged.status_code,
            "body_diff": r_plain.body_snippet[:80] != r_forged.body_snippet[:80],
        }
        rec.gateway(diff)
        # 危险：明显的 body 差异 + 都是 200 → 可信头被服务端采信
        if diff["body_diff"] and r_plain.status_code == 200 and r_forged.status_code == 200:
            suspicious.append(p)
    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    rec.assertion("trusted_headers_not_honored", len(suspicious) == 0, f"suspicious={suspicious}")
    rec.finish(
        "PASS" if not suspicious else "WARN",
        f"可疑响应差异：{suspicious}" if suspicious else "可信头未被服务端采信",
    )
