from __future__ import annotations

import json
from pathlib import Path

import yaml

from console_backend.catalog import discover_cases
from console_backend.config import ROOT, Settings
from console_backend.db import Database, utcnow
from console_backend.runner import LocalRunner
from scripts.generate_report import generate


def write_run(path: Path, target: str) -> None:
    (path / "evidence").mkdir(parents=True)
    (path / "run-config.snapshot.yaml").write_text(
        yaml.safe_dump({"target": {"base_url": target}}, sort_keys=False), encoding="utf-8"
    )
    (path / "evidence/CASE.json").write_text(json.dumps({
        "case_id": "CASE", "mitre": "N/A", "status": "PASS", "message": "ok",
        "duration_ms": 1, "time_window": {}, "evidence": {}, "assertions": [], "observability": {},
    }), encoding="utf-8")


def test_reports_use_each_run_target_snapshot(tmp_path: Path):
    first = tmp_path / "run-a"
    second = tmp_path / "run-b"
    write_run(first, "http://10.0.0.1:16001")
    write_run(second, "http://10.0.0.2:16001")
    assert generate(first)["target"] == "http://10.0.0.1:16001"
    assert generate(second)["target"] == "http://10.0.0.2:16001"
    assert json.loads((first / "report.json").read_text())["target"] != json.loads((second / "report.json").read_text())["target"]


def test_catalog_maps_custom_case_to_exact_pytest_node():
    cases = {case["case_id"]: case for case in discover_cases(ROOT)}
    assert cases["SOC-MATRIX-001"]["nodeid"].endswith("::test_all_p0_cases_are_implemented_or_deferred")
    assert cases["PIPELINE-STEP-1"]["nodeid"].endswith("::test_step1_docker_panel_detection")
    assert cases["PIPELINE-STEP-6"]["nodeid"].endswith("::test_step6_dry_run_response")


def test_p0_command_excludes_infrastructure_unless_enabled(tmp_path: Path):
    settings = Settings(root=ROOT, database_path=tmp_path / "db.sqlite", reports_path=tmp_path / "reports", temp_path=tmp_path / "tmp")
    runner = LocalRunner(Database(settings.database_path), settings)
    command = runner._command({"preset": "p0", "include_destructive": 0, "include_infrastructure": 0})
    expression = command[len(command) - 1]
    assert "not destructive" in expression
    assert "not needs_ssh" in expression
    enabled = runner._command({"preset": "p0", "include_destructive": 0, "include_infrastructure": 1})
    assert "needs_ssh" not in enabled[len(enabled) - 1]


def test_runner_restart_marks_unrecoverable_jobs_failed(tmp_path: Path):
    settings = Settings(root=ROOT, database_path=tmp_path / "db.sqlite", reports_path=tmp_path / "reports", temp_path=tmp_path / "tmp")
    db = Database(settings.database_path)
    db.initialize()
    password_hash = "unused"
    user_id = db.execute("INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)", ("admin", password_hash, "admin", 1, utcnow()))
    env_id = db.execute("INSERT INTO environments(name,base_url,created_at,updated_at) VALUES(?,?,?,?)", ("env", "http://127.0.0.1", utcnow(), utcnow()))
    db.execute(
        "INSERT INTO runs(id,environment_id,environment_snapshot,preset,status,requested_by,created_at,artifact_path,log_path) VALUES(?,?,?,?,?,?,?,?,?)",
        ("queued-run", env_id, json.dumps({"name": "env"}), "http_only", "queued", user_id, utcnow(), str(tmp_path / "reports/queued-run"), str(tmp_path / "reports/queued-run/run.log")),
    )
    runner = LocalRunner(db, settings)
    runner.start()
    runner.stop()
    row = db.one("SELECT status,error FROM runs WHERE id='queued-run'")
    assert row == {"status": "failed", "error": "控制器重启，临时凭据已销毁"}
