from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from console_backend.app import create_app
from console_backend.config import ROOT, Settings


ADMIN_PASSWORD = "admin-password-for-tests"


@pytest.fixture()
def client(tmp_path: Path):
    settings = Settings(
        root=ROOT,
        database_path=tmp_path / "console.db",
        reports_path=tmp_path / "reports",
        temp_path=tmp_path / "tmp",
        admin_username="admin",
        admin_password=ADMIN_PASSWORD,
    )
    app = create_app(settings, start_runner=False)
    with TestClient(app) as test_client:
        yield test_client, app, settings


def login(client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def env_payload(name: str = "测试环境") -> dict:
    return {
        "name": name,
        "base_url": "http://192.168.1.193:16001",
        "timeout_seconds": 10,
        "retries": 2,
        "ssh_host": "192.168.1.193",
        "ssh_port": 22,
        "wazuh_api_host": "192.168.1.193",
        "wazuh_api_port": 55000,
        "wazuh_indexer_host": "192.168.1.193",
        "wazuh_indexer_port": 9200,
        "verify_tls": False,
        "dry_run_default": True,
        "max_parallelism": 1,
        "notes": "",
    }


def create_environment(client: TestClient, csrf: str) -> dict:
    response = client.post("/api/environments", json=env_payload(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201
    return response.json()


def test_auth_csrf_and_environment_crud(client):
    http, _, _ = client
    assert http.get("/api/environments").status_code == 401
    csrf = login(http)
    assert http.post("/api/environments", json=env_payload()).status_code == 403
    environment = create_environment(http, csrf)
    assert environment["base_url"] == "http://192.168.1.193:16001"
    payload = env_payload()
    payload["notes"] = "更新"
    response = http.put(f"/api/environments/{environment['id']}", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json()["notes"] == "更新"


def test_rbac_blocks_viewer_mutation(client):
    http, _, _ = client
    csrf = login(http)
    response = http.post("/api/users", json={"username": "viewer01", "password": "viewer-password-123", "role": "viewer"}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201
    http.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    viewer_csrf = login(http, "viewer01", "viewer-password-123")
    assert http.get("/api/environments").status_code == 200
    assert http.post("/api/environments", json=env_payload(), headers={"X-CSRF-Token": viewer_csrf}).status_code == 403
    assert http.get("/api/users").status_code == 403


def test_login_rate_limit(client):
    http, _, _ = client
    for _ in range(5):
        assert http.post("/api/auth/login", json={"username": "rate-limit-user", "password": "wrong"}).status_code == 401
    assert http.post("/api/auth/login", json={"username": "rate-limit-user", "password": "wrong"}).status_code == 429


def test_transient_secrets_are_not_persisted(client):
    http, app, settings = client
    csrf = login(http)
    environment = create_environment(http, csrf)
    secret = "do-not-persist-this-secret"
    response = http.post("/api/runs", json={
        "environment_id": environment["id"],
        "preset": "http_only",
        "dry_run": True,
        "credentials": {"platform": {"bearer": secret}},
    }, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 202
    run_id = response.json()["id"]
    assert secret.encode() not in settings.database_path.read_bytes()
    row = app.state.db.one("SELECT * FROM runs WHERE id=?", (run_id,))
    assert secret not in json.dumps(row)
    assert secret in app.state.runner._credentials[run_id]["platform"]["bearer"]
    assert http.post(f"/api/runs/{run_id}/cancel", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert app.state.db.one("SELECT status FROM runs WHERE id=?", (run_id,))["status"] == "cancelled"
    assert run_id not in app.state.runner._credentials


def test_destructive_requires_admin_confirmation_and_no_dry_run(client):
    http, _, _ = client
    csrf = login(http)
    environment = create_environment(http, csrf)
    base = {"environment_id": environment["id"], "preset": "p0", "include_destructive": True}
    assert http.post("/api/runs", json={**base, "dry_run": True, "confirmation": environment["name"]}, headers={"X-CSRF-Token": csrf}).status_code == 422
    assert http.post("/api/runs", json={**base, "dry_run": False, "confirmation": "wrong"}, headers={"X-CSRF-Token": csrf}).status_code == 422
    assert http.post("/api/runs", json={**base, "dry_run": False, "confirmation": environment["name"]}, headers={"X-CSRF-Token": csrf}).status_code == 202


def test_rejects_unknown_custom_case_and_path_escape(client, tmp_path: Path):
    http, app, _ = client
    csrf = login(http)
    environment = create_environment(http, csrf)
    response = http.post("/api/runs", json={"environment_id": environment["id"], "preset": "custom", "case_ids": ["; rm -rf /"]}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 422
    run_id = "20260629-000000-dead"
    app.state.db.execute(
        "INSERT INTO runs(id,environment_id,environment_snapshot,preset,status,requested_by,created_at,artifact_path,log_path) VALUES(?,?,?,?,?,?,?,?,?)",
        (run_id, environment["id"], json.dumps(environment), "http_only", "completed", 1, "now", str(tmp_path / "outside"), str(tmp_path / "outside/run.log")),
    )
    assert http.get(f"/api/runs/{run_id}/report").status_code == 400


def test_real_runner_removes_temp_secret_from_all_artifacts(tmp_path: Path):
    secret = "synthetic-secret-never-persist-9842"
    settings = Settings(
        root=ROOT,
        database_path=tmp_path / "console.db",
        reports_path=tmp_path / "reports",
        temp_path=tmp_path / "runtime",
        admin_username="admin",
        admin_password=ADMIN_PASSWORD,
    )
    app = create_app(settings, start_runner=True)
    with TestClient(app) as http:
        csrf = login(http)
        environment = create_environment(http, csrf)
        response = http.post("/api/runs", json={
            "environment_id": environment["id"],
            "preset": "custom",
            "case_ids": ["SOC-MATRIX-001"],
            "credentials": {"platform": {"bearer": secret}},
        }, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 202
        run_id = response.json()["id"]
        for _ in range(100):
            run = http.get(f"/api/runs/{run_id}").json()
            if run["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        assert run["status"] == "completed"
        assert run["totals"]["PASS"] == 1
    persisted = settings.database_path.read_bytes()
    for path in settings.reports_path.rglob("*"):
        if path.is_file():
            persisted += path.read_bytes()
    assert secret.encode() not in persisted
    assert not any(settings.temp_path.iterdir())
