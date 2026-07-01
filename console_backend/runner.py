from __future__ import annotations

import json
import os
import queue
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .catalog import discover_cases
from .config import Settings
from .db import Database, utcnow


TERMINAL = {"completed", "failed", "cancelled"}


class LocalRunner:
    """单机串行 Runner；接口保持独立，后续可替换为远程实现。"""

    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._credentials: dict[str, dict[str, Any]] = {}
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._cancelled: set[str] = set()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        self.settings.reports_path.mkdir(parents=True, exist_ok=True)
        self.settings.temp_path.mkdir(parents=True, exist_ok=True)
        self.db.execute(
            "UPDATE runs SET status='failed',finished_at=?,error=? WHERE status IN ('queued','running')",
            (utcnow(), "控制器重启，临时凭据已销毁"),
        )
        self._thread = threading.Thread(target=self._loop, name="soc-local-runner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        with self._lock:
            run_ids = list(self._processes)
        for run_id in run_ids:
            self.cancel(run_id)
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=5)

    def submit(self, run_id: str, credentials: dict[str, Any]) -> None:
        with self._lock:
            self._credentials[run_id] = credentials
        self._queue.put(run_id)

    def cancel(self, run_id: str) -> bool:
        row = self.db.one("SELECT status FROM runs WHERE id=?", (run_id,))
        if not row or row["status"] in TERMINAL:
            return False
        with self._lock:
            self._cancelled.add(run_id)
            process = self._processes.get(run_id)
            self._credentials.pop(run_id, None)
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.db.execute(
            "UPDATE runs SET status='cancelled',finished_at=?,error=? WHERE id=?",
            (utcnow(), "用户取消运行", run_id),
        )
        return True

    def _loop(self) -> None:
        while not self._stopping.is_set():
            run_id = self._queue.get()
            if run_id is None:
                return
            with self._lock:
                cancelled = run_id in self._cancelled
            if not cancelled:
                self._execute(run_id)

    def _command(self, run: dict[str, Any]) -> list[str]:
        base = [sys.executable, "-m", "pytest", "-v", "--tb=short"]
        preset = run["preset"]
        destructive = bool(run["include_destructive"])
        if preset == "http_only":
            return base + ["tests/", "-m", "not needs_ssh and not needs_wazuh and not destructive"]
        if preset == "p0":
            expression = "(p0 or pipeline)"
            if not destructive:
                expression += " and not destructive"
            if not bool(run["include_infrastructure"]):
                expression += " and not needs_ssh and not needs_wazuh"
            return base + ["tests/", "-m", expression]
        if preset == "pipeline":
            return base + ["tests/pipeline/"]
        if preset == "custom":
            selected = set(json.loads(run["case_ids"]))
            catalog = {case["case_id"]: case for case in discover_cases(self.settings.root)}
            if not selected or not selected.issubset(catalog):
                raise ValueError("自定义用例包含未知 ID")
            nodeids = sorted({catalog[case_id]["nodeid"] for case_id in selected})
            return base + nodeids
        raise ValueError("未知测试预设")

    def _runtime_config(self, run: dict[str, Any], credentials: dict[str, Any], temp_dir: Path) -> dict:
        snapshot = json.loads(run["environment_snapshot"])
        source = yaml.safe_load((self.settings.root / "config/target.yaml").read_text(encoding="utf-8"))
        source["target"] = {
            "name": snapshot["name"],
            "base_url": snapshot["base_url"],
            "timeout_seconds": snapshot["timeout_seconds"],
            "retries": snapshot["retries"],
        }
        source["wazuh"] = {
            "manager_port": snapshot["wazuh_api_port"],
            "indexer_port": snapshot["wazuh_indexer_port"],
            "alerts_index_pattern": "wazuh-alerts-*",
        }
        source.setdefault("runtime", {})["dry_run_default"] = bool(run["dry_run"])
        private_key = credentials.get("ssh_host", {}).pop("private_key", "")
        if private_key:
            key_path = temp_dir / "ssh_key"
            key_path.write_text(private_key, encoding="utf-8")
            key_path.chmod(0o600)
            credentials["ssh_host"]["private_key_path"] = str(key_path)
        source["credentials"] = credentials
        return source

    @staticmethod
    def _secret_values(credentials: dict[str, Any]) -> list[str]:
        values: list[str] = []
        stack: list[Any] = [credentials]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, str) and len(value) >= 4:
                values.append(value)
        return sorted(values, key=len, reverse=True)

    def _execute(self, run_id: str) -> None:
        run = self.db.one("SELECT * FROM runs WHERE id=?", (run_id,))
        if not run:
            return
        with self._lock:
            credentials = self._credentials.pop(run_id, {})
        temp_dir = self.settings.temp_path / run_id
        run_dir = Path(run["artifact_path"])
        log_path = Path(run["log_path"])
        temp_dir.mkdir(parents=True, exist_ok=False)
        run_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        config_path = temp_dir / "run.yaml"
        process: subprocess.Popen[str] | None = None
        try:
            runtime = self._runtime_config(run, credentials, temp_dir)
            config_path.write_text(yaml.safe_dump(runtime, allow_unicode=True, sort_keys=False), encoding="utf-8")
            config_path.chmod(0o600)
            command = self._command(run)
            env = os.environ.copy()
            env.update({
                "SOC_TEST_RUN_CONFIG": str(config_path),
                "SOC_TEST_RUN_ID": run_id,
                "SOC_TEST_RUN_DIR": str(run_dir),
                "NO_PROXY": "*",
                "no_proxy": "*",
                "PYTHONDONTWRITEBYTECODE": "1",
            })
            self.db.execute("UPDATE runs SET status='running',started_at=? WHERE id=?", (utcnow(), run_id))
            process = subprocess.Popen(
                command,
                cwd=str(self.settings.root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            with self._lock:
                self._processes[run_id] = process
            secrets_to_hide = self._secret_values(credentials)
            with log_path.open("w", encoding="utf-8") as log:
                assert process.stdout is not None
                for line in process.stdout:
                    for secret in secrets_to_hide:
                        line = line.replace(secret, "[REDACTED]")
                    log.write(line)
                    log.flush()
            exit_code = process.wait()
            with self._lock:
                cancelled = run_id in self._cancelled
            if cancelled:
                return
            report_path = run_dir / "report.json"
            totals = None
            if report_path.exists():
                totals = json.loads(report_path.read_text(encoding="utf-8")).get("totals")
            status = "completed" if exit_code == 0 else "failed"
            self.db.execute(
                "UPDATE runs SET status=?,finished_at=?,exit_code=?,totals=?,error=? WHERE id=?",
                (status, utcnow(), exit_code, json.dumps(totals) if totals else None,
                 "" if exit_code == 0 else "pytest 执行失败，请查看运行日志", run_id),
            )
        except Exception as exc:
            self.db.execute(
                "UPDATE runs SET status='failed',finished_at=?,error=? WHERE id=?",
                (utcnow(), str(exc)[:500], run_id),
            )
        finally:
            credentials.clear()
            with self._lock:
                self._processes.pop(run_id, None)
                self._credentials.pop(run_id, None)
                self._cancelled.discard(run_id)
            shutil.rmtree(temp_dir, ignore_errors=True)


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
