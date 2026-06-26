"""SOC-API-003 — /api/health 数据契约

GET /api/health 必须返回 status='healthy', version, storage.backend, storage.database_available。
对 SOC 运维至关重要：监控告警依赖它。
"""
import pytest

CASE_ID = "SOC-API-003"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]


def test_health_contract(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    r = target.raw_request("GET", "/api/health")
    body = r["json"] or {}
    rec.gateway({"status": r["status"], "body": body})

    rec.assertion("status_200", r["status"] == 200, str(r["status"]))
    rec.assertion("status_healthy", body.get("status") == "healthy", str(body.get("status")))
    rec.assertion("has_version", bool(body.get("version")), str(body.get("version")))

    storage = body.get("storage") or {}
    rec.assertion("storage_backend", bool(storage.get("backend")), str(storage))
    rec.assertion("database_available", storage.get("database_available") is True,
                  str(storage.get("database_available")))

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=1, expected_hits=1)
    rec.set_ai_score(score)
    all_ok = all(a["ok"] for a in rec.data.assertions)
    if all_ok:
        rec.finish("PASS", f"健康端点字段全部合规 version={body.get('version')}")
    else:
        rec.finish("FAIL", f"健康端点字段不合规: {body}")
