from __future__ import annotations

import io
import json
import os
import socket
import time
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .catalog import PRESETS, discover_cases
from .config import Settings
from .db import Database, utcnow
from .runner import LocalRunner, new_run_id
from .security import create_session, delete_session, hash_password, session_user, token_hash, verify_password


ROLES = {"admin", "operator", "viewer"}
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginInput(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserInput(StrictModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)
    role: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError("角色无效")
        return value


class UserPatch(StrictModel):
    password: Optional[str] = Field(default=None, min_length=12, max_length=256)
    role: Optional[str] = None
    active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ROLES:
            raise ValueError("角色无效")
        return value


class EnvironmentInput(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    base_url: str = Field(min_length=8, max_length=500)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=2, ge=0, le=5)
    ssh_host: str = Field(default="", max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    wazuh_api_host: str = Field(default="", max_length=255)
    wazuh_api_port: int = Field(default=55000, ge=1, le=65535)
    wazuh_indexer_host: str = Field(default="", max_length=255)
    wazuh_indexer_port: int = Field(default=9200, ge=1, le=65535)
    verify_tls: bool = False
    dry_run_default: bool = True
    max_parallelism: int = Field(default=1, ge=1, le=1)
    notes: str = Field(default="", max_length=1000)

    @field_validator("base_url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Base URL 必须是无凭据的 http/https 地址")
        if parsed.query or parsed.fragment:
            raise ValueError("Base URL 不能包含查询参数或片段")
        return value.rstrip("/")


class PlatformSecrets(StrictModel):
    username: str = ""
    password: str = ""
    cookie: str = ""
    bearer: str = ""


class ServiceSecrets(StrictModel):
    username: str = ""
    password: str = ""


class SSHSecrets(ServiceSecrets):
    private_key: str = ""
    victim_account: str = "testuser"
    attacker_source_ip: str = ""


class TransientSecrets(StrictModel):
    platform: PlatformSecrets = Field(default_factory=PlatformSecrets)
    ssh: SSHSecrets = Field(default_factory=SSHSecrets)
    wazuh_api: ServiceSecrets = Field(default_factory=ServiceSecrets)
    wazuh_indexer: ServiceSecrets = Field(default_factory=ServiceSecrets)


class RunInput(StrictModel):
    environment_id: int
    preset: str
    case_ids: list[str] = Field(default_factory=list, max_length=200)
    include_infrastructure: bool = False
    include_destructive: bool = False
    dry_run: bool = True
    confirmation: str = ""
    credentials: TransientSecrets = Field(default_factory=TransientSecrets)

    @field_validator("preset")
    @classmethod
    def valid_preset(cls, value: str) -> str:
        if value not in PRESETS:
            raise ValueError("测试预设无效")
        return value


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {key: user[key] for key in ("id", "username", "role", "active", "created_at") if key in user}


def _environment(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in ("verify_tls", "dry_run_default"):
        result[key] = bool(result[key])
    return result


def _run(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["environment_snapshot"] = json.loads(result["environment_snapshot"])
    result["case_ids"] = json.loads(result["case_ids"])
    result["totals"] = json.loads(result["totals"]) if result.get("totals") else None
    result["include_infrastructure"] = bool(result["include_infrastructure"])
    result["include_destructive"] = bool(result["include_destructive"])
    result["dry_run"] = bool(result["dry_run"])
    return result


def create_app(settings: Settings | None = None, start_runner: bool = True) -> FastAPI:
    cfg = settings or Settings()
    db = Database(cfg.database_path)
    runner = LocalRunner(db, cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.initialize()
        if cfg.admin_password and not db.one("SELECT id FROM users WHERE username=?", (cfg.admin_username,)):
            db.execute(
                "INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                (cfg.admin_username, hash_password(cfg.admin_password), "admin", 1, utcnow()),
            )
        if start_runner:
            runner.start()
        yield
        if start_runner:
            runner.stop()

    app = FastAPI(title="SOC 测试控制台 API", version="1.0.0", lifespan=lifespan)
    app.state.db = db
    app.state.runner = runner
    app.state.settings = cfg

    def current_user(soc_session: str = Cookie(default="")) -> dict[str, Any]:
        user = session_user(db, soc_session)
        if not user:
            raise HTTPException(status_code=401, detail="未登录或会话已过期")
        return user

    def roles(*allowed: str) -> Callable:
        def dependency(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
            if user["role"] not in allowed:
                raise HTTPException(status_code=403, detail="权限不足")
            return user
        return dependency

    def csrf_guard(
        user: dict[str, Any] = Depends(current_user),
        soc_csrf: str = Cookie(default=""),
        x_csrf_token: str = Header(default=""),
    ) -> dict[str, Any]:
        if not soc_csrf or not x_csrf_token or soc_csrf != x_csrf_token:
            raise HTTPException(status_code=403, detail="CSRF 校验失败")
        if token_hash(x_csrf_token) != user["csrf_hash"]:
            raise HTTPException(status_code=403, detail="CSRF 校验失败")
        return user

    def mutation_roles(*allowed: str) -> Callable:
        def dependency(user: dict[str, Any] = Depends(csrf_guard)) -> dict[str, Any]:
            if user["role"] not in allowed:
                raise HTTPException(status_code=403, detail="权限不足")
            return user
        return dependency

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/login")
    def login(payload: LoginInput, request: Request, response: Response) -> dict[str, Any]:
        key = f"{request.client.host if request.client else 'unknown'}:{payload.username.lower()}"
        now = time.monotonic()
        attempts = LOGIN_ATTEMPTS[key]
        while attempts and now - attempts[0] > 300:
            attempts.popleft()
        if len(attempts) >= 5:
            raise HTTPException(status_code=429, detail="登录尝试过多，请稍后重试")
        user = db.one("SELECT * FROM users WHERE username=? AND active=1", (payload.username,))
        if not user or not verify_password(payload.password, user["password_hash"]):
            attempts.append(now)
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        attempts.clear()
        session, csrf = create_session(db, user["id"], cfg.session_hours)
        response.set_cookie("soc_session", session, httponly=True, secure=cfg.secure_cookie, samesite="strict")
        response.set_cookie("soc_csrf", csrf, httponly=False, secure=cfg.secure_cookie, samesite="strict")
        db.audit(user["id"], "login", "session", "self")
        return {"user": _public_user(user), "csrf_token": csrf}

    @app.post("/api/auth/logout")
    def logout(
        response: Response,
        user: dict[str, Any] = Depends(csrf_guard),
        soc_session: str = Cookie(default=""),
    ) -> dict[str, bool]:
        delete_session(db, soc_session)
        response.delete_cookie("soc_session")
        response.delete_cookie("soc_csrf")
        db.audit(user["id"], "logout", "session", "self")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        return _public_user(user)

    @app.get("/api/users")
    def list_users(user: dict[str, Any] = Depends(roles("admin"))) -> list[dict[str, Any]]:
        return [_public_user(row) for row in db.all("SELECT * FROM users ORDER BY username")]

    @app.post("/api/users", status_code=201)
    def create_user(payload: UserInput, actor: dict[str, Any] = Depends(mutation_roles("admin"))) -> dict[str, Any]:
        try:
            user_id = db.execute(
                "INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                (payload.username, hash_password(payload.password), payload.role, 1, utcnow()),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail="用户名已存在") from exc
        db.audit(actor["id"], "create", "user", str(user_id), {"role": payload.role})
        return _public_user(db.one("SELECT * FROM users WHERE id=?", (user_id,)) or {})

    @app.patch("/api/users/{user_id}")
    def patch_user(user_id: int, payload: UserPatch, actor: dict[str, Any] = Depends(mutation_roles("admin"))) -> dict[str, Any]:
        target = db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not target:
            raise HTTPException(status_code=404, detail="用户不存在")
        changes = payload.model_dump(exclude_none=True)
        if user_id == actor["id"] and changes.get("active") is False:
            raise HTTPException(status_code=409, detail="不能停用当前账号")
        columns: list[str] = []
        values: list[Any] = []
        for key, value in changes.items():
            columns.append("password_hash=?" if key == "password" else f"{key}=?")
            values.append(hash_password(value) if key == "password" else int(value) if key == "active" else value)
        if columns:
            db.execute(f"UPDATE users SET {','.join(columns)} WHERE id=?", tuple(values + [user_id]))
        db.audit(actor["id"], "update", "user", str(user_id), {k: v for k, v in changes.items() if k != "password"})
        return _public_user(db.one("SELECT * FROM users WHERE id=?", (user_id,)) or {})

    @app.get("/api/environments")
    def list_environments(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
        return [_environment(row) for row in db.all("SELECT * FROM environments ORDER BY name")]

    @app.post("/api/environments", status_code=201)
    def create_environment(payload: EnvironmentInput, actor: dict[str, Any] = Depends(mutation_roles("admin", "operator"))) -> dict[str, Any]:
        values = payload.model_dump()
        now = utcnow()
        keys = list(values)
        try:
            env_id = db.execute(
                f"INSERT INTO environments({','.join(keys)},created_at,updated_at) VALUES({','.join('?' for _ in keys)},?,?)",
                tuple(int(v) if isinstance(v, bool) else v for v in values.values()) + (now, now),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail="环境名称已存在") from exc
        db.audit(actor["id"], "create", "environment", str(env_id), {"name": payload.name, "base_url": payload.base_url})
        return _environment(db.one("SELECT * FROM environments WHERE id=?", (env_id,)) or {})

    @app.put("/api/environments/{environment_id}")
    def update_environment(environment_id: int, payload: EnvironmentInput, actor: dict[str, Any] = Depends(mutation_roles("admin", "operator"))) -> dict[str, Any]:
        if not db.one("SELECT id FROM environments WHERE id=?", (environment_id,)):
            raise HTTPException(status_code=404, detail="环境不存在")
        values = payload.model_dump()
        assignments = ",".join(f"{key}=?" for key in values)
        try:
            db.execute(
                f"UPDATE environments SET {assignments},updated_at=? WHERE id=?",
                tuple(int(v) if isinstance(v, bool) else v for v in values.values()) + (utcnow(), environment_id),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail="环境名称已存在") from exc
        db.audit(actor["id"], "update", "environment", str(environment_id), {"name": payload.name, "base_url": payload.base_url})
        return _environment(db.one("SELECT * FROM environments WHERE id=?", (environment_id,)) or {})

    @app.delete("/api/environments/{environment_id}")
    def delete_environment(environment_id: int, actor: dict[str, Any] = Depends(mutation_roles("admin"))) -> dict[str, bool]:
        if db.one("SELECT id FROM runs WHERE environment_id=? LIMIT 1", (environment_id,)):
            raise HTTPException(status_code=409, detail="环境已有运行记录，不能删除")
        db.execute("DELETE FROM environments WHERE id=?", (environment_id,))
        db.audit(actor["id"], "delete", "environment", str(environment_id))
        return {"ok": True}

    @app.post("/api/environments/{environment_id}/probe")
    def probe_environment(environment_id: int, actor: dict[str, Any] = Depends(mutation_roles("admin", "operator"))) -> dict[str, Any]:
        env = db.one("SELECT * FROM environments WHERE id=?", (environment_id,))
        if not env:
            raise HTTPException(status_code=404, detail="环境不存在")
        result: dict[str, Any] = {}
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(env["base_url"] + "/api/health", timeout=min(env["timeout_seconds"], 10), verify=bool(env["verify_tls"]))
            result["http"] = {"ok": response.status_code < 500, "status": response.status_code}
        except requests.RequestException as exc:
            result["http"] = {"ok": False, "error": type(exc).__name__}
        for name, host_key, port_key in (
            ("ssh", "ssh_host", "ssh_port"),
            ("wazuh_api", "wazuh_api_host", "wazuh_api_port"),
            ("wazuh_indexer", "wazuh_indexer_host", "wazuh_indexer_port"),
        ):
            host = env[host_key]
            if not host:
                result[name] = {"ok": False, "configured": False}
                continue
            try:
                with socket.create_connection((host, env[port_key]), timeout=3):
                    result[name] = {"ok": True, "configured": True}
            except OSError as exc:
                result[name] = {"ok": False, "configured": True, "error": type(exc).__name__}
        db.audit(actor["id"], "probe", "environment", str(environment_id), result)
        return result

    @app.get("/api/test-presets")
    def test_presets(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        return PRESETS

    @app.get("/api/test-cases")
    def test_cases(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
        return discover_cases(cfg.root)

    def runtime_credentials(payload: RunInput, env: dict[str, Any]) -> dict[str, Any]:
        raw = payload.credentials.model_dump()
        return {
            "platform": {"enabled": bool(any(raw["platform"].values())), **raw["platform"]},
            "ssh_host": {"enabled": payload.include_infrastructure, "host": env["ssh_host"], "port": env["ssh_port"], "dry_run": payload.dry_run, **raw["ssh"]},
            "wazuh_api": {"enabled": payload.include_infrastructure, "host": env["wazuh_api_host"], "port": env["wazuh_api_port"], "verify_tls": bool(env["verify_tls"]), **raw["wazuh_api"]},
            "wazuh_indexer": {"enabled": payload.include_infrastructure, "host": env["wazuh_indexer_host"], "port": env["wazuh_indexer_port"], "verify_tls": bool(env["verify_tls"]), **raw["wazuh_indexer"]},
        }

    @app.post("/api/runs", status_code=202)
    def create_run(payload: RunInput, actor: dict[str, Any] = Depends(mutation_roles("admin", "operator"))) -> dict[str, Any]:
        env = db.one("SELECT * FROM environments WHERE id=?", (payload.environment_id,))
        if not env:
            raise HTTPException(status_code=404, detail="环境不存在")
        catalog = {case["case_id"]: case for case in discover_cases(cfg.root)}
        if payload.preset == "custom":
            if not payload.case_ids or not set(payload.case_ids).issubset(catalog):
                raise HTTPException(status_code=422, detail="自定义用例包含未知 ID")
            required = {marker for case_id in payload.case_ids for marker in catalog[case_id]["markers"]}
            if {"needs_ssh", "needs_wazuh"} & required and not payload.include_infrastructure:
                raise HTTPException(status_code=422, detail="所选用例需要 SSH/Wazuh 临时凭据")
            if "destructive" in required and not payload.include_destructive:
                raise HTTPException(status_code=422, detail="所选用例包含破坏性测试")
        if payload.include_infrastructure:
            secrets_payload = payload.credentials.model_dump()
            if not (env["ssh_host"] and env["wazuh_api_host"] and env["wazuh_indexer_host"]):
                raise HTTPException(status_code=422, detail="环境未完整配置 SSH/Wazuh 地址")
            if not (secrets_payload["ssh"]["username"] and (secrets_payload["ssh"]["password"] or secrets_payload["ssh"]["private_key"])):
                raise HTTPException(status_code=422, detail="缺少 SSH 临时凭据")
            if not all(secrets_payload[name]["username"] and secrets_payload[name]["password"] for name in ("wazuh_api", "wazuh_indexer")):
                raise HTTPException(status_code=422, detail="缺少 Wazuh 临时凭据")
        if payload.include_destructive:
            if actor["role"] != "admin":
                raise HTTPException(status_code=403, detail="仅管理员可运行破坏性测试")
            if payload.dry_run or payload.confirmation != env["name"]:
                raise HTTPException(status_code=422, detail="破坏性测试必须关闭 Dry Run 并输入环境名称确认")
        run_id = new_run_id()
        run_dir = (cfg.reports_path / run_id).resolve()
        snapshot = _environment(env)
        db.execute(
            "INSERT INTO runs(id,environment_id,environment_snapshot,preset,case_ids,include_infrastructure,include_destructive,dry_run,status,requested_by,created_at,artifact_path,log_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, env["id"], json.dumps(snapshot, ensure_ascii=False), payload.preset,
             json.dumps(payload.case_ids), int(payload.include_infrastructure), int(payload.include_destructive), int(payload.dry_run), "queued",
             actor["id"], utcnow(), str(run_dir), str(run_dir / "run.log")),
        )
        credentials = runtime_credentials(payload, env)
        runner.submit(run_id, credentials)
        db.audit(actor["id"], "create", "run", run_id, {
            "environment": env["name"], "preset": payload.preset,
            "include_infrastructure": payload.include_infrastructure,
            "include_destructive": payload.include_destructive,
        })
        return _run(db.one("SELECT * FROM runs WHERE id=?", (run_id,)) or {})

    @app.get("/api/runs")
    def list_runs(limit: int = Query(default=50, ge=1, le=200), user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
        return [_run(row) for row in db.all("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,))]

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        row = db.one("SELECT * FROM runs WHERE id=?", (run_id,))
        if not row:
            raise HTTPException(status_code=404, detail="运行不存在")
        return _run(row)

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str, actor: dict[str, Any] = Depends(mutation_roles("admin", "operator"))) -> dict[str, bool]:
        if not runner.cancel(run_id):
            raise HTTPException(status_code=409, detail="运行不存在或已结束")
        db.audit(actor["id"], "cancel", "run", run_id)
        return {"ok": True}

    def safe_run_path(run_id: str, filename: str) -> Path:
        row = db.one("SELECT artifact_path FROM runs WHERE id=?", (run_id,))
        if not row:
            raise HTTPException(status_code=404, detail="运行不存在")
        base = Path(row["artifact_path"]).resolve()
        reports = cfg.reports_path.resolve()
        if reports not in base.parents:
            raise HTTPException(status_code=400, detail="运行路径非法")
        return base / filename

    @app.get("/api/runs/{run_id}/events")
    def run_events(run_id: str, user: dict[str, Any] = Depends(current_user)) -> StreamingResponse:
        log_path = safe_run_path(run_id, "run.log")

        def stream():
            offset = 0
            while True:
                if log_path.exists():
                    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        for line in handle:
                            yield f"data: {json.dumps({'type': 'log', 'line': line.rstrip()}, ensure_ascii=False)}\n\n"
                        offset = handle.tell()
                row = db.one("SELECT status,totals,error FROM runs WHERE id=?", (run_id,))
                if not row:
                    return
                yield f"data: {json.dumps({'type': 'status', **row}, ensure_ascii=False)}\n\n"
                if row["status"] in {"completed", "failed", "cancelled"}:
                    return
                time.sleep(1)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/runs/{run_id}/report")
    def run_report(run_id: str, format: str = Query(default="json", pattern="^(json|markdown)$"), user: dict[str, Any] = Depends(current_user)):
        path = safe_run_path(run_id, "report.json" if format == "json" else "report.md")
        if not path.exists():
            raise HTTPException(status_code=404, detail="报告尚未生成")
        if format == "markdown":
            return FileResponse(path, media_type="text/markdown; charset=utf-8", filename=f"{run_id}-report.md")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/api/runs/{run_id}/evidence-bundle")
    def evidence_bundle(run_id: str, user: dict[str, Any] = Depends(current_user)) -> StreamingResponse:
        run_dir = safe_run_path(run_id, "").resolve()
        if not run_dir.exists():
            raise HTTPException(status_code=404, detail="运行产物不存在")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in run_dir.rglob("*"):
                if path.is_file() and path.name != "run.yaml":
                    archive.write(path, path.relative_to(run_dir))
        output.seek(0)
        return StreamingResponse(output, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{run_id}-evidence.zip"'})

    @app.get("/api/audit-events")
    def audit_events(limit: int = Query(default=100, ge=1, le=500), user: dict[str, Any] = Depends(roles("admin"))) -> list[dict[str, Any]]:
        rows = db.all(
            "SELECT a.*,u.username actor FROM audit_events a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT ?",
            (limit,),
        )
        for row in rows:
            row["detail"] = json.loads(row["detail"])
        return rows

    return app


app = create_app()
