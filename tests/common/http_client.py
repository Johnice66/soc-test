"""
平台 REST/SSE/WS HTTP 客户端
- 复用并扩展 ai_soc_pipeline_test.py 的 PipelineTest._get/_post
- 注入 X-Request-Id 便于和网关/Wazuh 日志关联
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import requests
import yaml


@dataclass
class HTTPResult:
    method: str
    path: str
    status_code: int
    request_id: str
    elapsed_ms: float
    body_snippet: str
    json: Optional[Any] = None


class HTTPClient:
    """平台 HTTP 客户端，所有调用统一记录 request_id 便于证据关联。"""

    def __init__(
        self,
        base_url: str,
        timeout: float = 10,
        retries: int = 2,
        cookie: str = "",
        bearer: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        # 关键：被测平台是内网 IP，绕开系统代理
        self.session.trust_env = False
        self.session.proxies = {"http": "", "https": ""}
        self.session.headers.update({"Content-Type": "application/json"})
        if cookie:
            self.session.headers["Cookie"] = cookie
        if bearer:
            self.session.headers["Authorization"] = f"Bearer {bearer}"
        # 调用日志（供 EvidenceRecorder 取走）
        self.call_log: list[HTTPResult] = []
        # 用例期间的 findings / case_ids 缓存（供 observability 默认 attach）
        self.last_findings: list[dict] = []
        self.last_case_ids: list[str] = []

    @classmethod
    def from_yaml(cls, target_yaml: str, credentials: dict | None = None) -> "HTTPClient":
        with open(target_yaml, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        return cls.from_config(cfg, credentials)

    @classmethod
    def from_config(cls, cfg: dict, credentials: dict | None = None) -> "HTTPClient":
        t = cfg["target"]
        creds = (credentials or {}).get("platform", {}) if credentials else {}
        return cls(
            base_url=t["base_url"],
            timeout=t.get("timeout_seconds", 10),
            retries=t.get("retries", 2),
            cookie=creds.get("cookie", ""),
            bearer=creds.get("bearer", ""),
        )

    def _request(self, method: str, path: str, **kwargs) -> HTTPResult:
        url = f"{self.base_url}{path}"
        rid = f"soc-test-{uuid.uuid4().hex[:12]}"
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("X-Request-Id", rid)
        t0 = time.perf_counter()
        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                resp = self.session.request(
                    method, url, headers=headers, timeout=self.timeout, **kwargs
                )
                break
            except requests.RequestException as exc:
                last_exc = exc
                if attempt == self.retries:
                    raise
                time.sleep(0.5 * (attempt + 1))
        elapsed_ms = (time.perf_counter() - t0) * 1000
        try:
            body_json = resp.json()
        except Exception:
            body_json = None
        result = HTTPResult(
            method=method,
            path=path,
            status_code=resp.status_code,
            request_id=rid,
            elapsed_ms=round(elapsed_ms, 1),
            body_snippet=resp.text[:300],
            json=body_json,
        )
        self.call_log.append(result)
        return result

    def get(self, path: str, **kw) -> HTTPResult:
        return self._request("GET", path, **kw)

    def post(self, path: str, json_data: dict | None = None, **kw) -> HTTPResult:
        return self._request("POST", path, json=json_data, **kw)

    def put(self, path: str, json_data: dict | None = None, **kw) -> HTTPResult:
        return self._request("PUT", path, json=json_data, **kw)

    def delete(self, path: str, **kw) -> HTTPResult:
        return self._request("DELETE", path, **kw)

    # ---------- 高级辅助 ----------
    def get_findings(self, limit: int = 100, **filters) -> list[dict]:
        # 支持 q=, mitre=, src_ip= 等过滤；platform 实际接受这些 query
        qs = "&".join([f"limit={limit}"] + [f"{k}={v}" for k, v in filters.items() if v is not None])
        r = self.get(f"/api/findings/?{qs}")
        if r.json:
            findings = (r.json.get("findings") or [])[:limit]
            # 缓存：用于 observability 自动 attach
            self.last_findings = findings
            return findings
        return []

    def create_case(
        self,
        title: str,
        description: str,
        finding_ids: list[str],
        priority: str = "high",
        tags: list[str] | None = None,
    ) -> Optional[str]:
        payload = {
            "title": title,
            "description": description,
            "priority": priority,
            "finding_ids": finding_ids,
            "tags": tags or ["automated-test"],
        }
        r = self.post("/api/cases/", json_data=payload)
        cid = (r.json or {}).get("case_id") if r.status_code == 200 else None
        if cid:
            self.last_case_ids = getattr(self, "last_case_ids", [])
            self.last_case_ids.append(cid)
        return cid

    def get_orchestrator_status(self) -> dict:
        return self.get("/api/orchestrator/status").json or {}

    def get_reasoning(self, session_id: int) -> dict:
        return self.get(f"/api/reasoning/{session_id}").json or {}

    def get_integration_config(self) -> dict:
        return self.get("/api/config/integrations").json or {}

    # ---------- case ⇄ finding 关联 ----------
    def get_case_detail(self, case_id: str) -> dict:
        return self.get(f"/api/cases/{case_id}").json or {}

    def list_cases(self, limit: int = 20) -> list[dict]:
        r = self.get(f"/api/cases/?limit={limit}")
        return (r.json or {}).get("cases", [])

    def get_case_iocs(self, case_id: str) -> dict:
        return self.get(f"/api/cases/{case_id}/iocs").json or {}

    # ---------- 审批单 ----------
    def list_approvals(self, status: str | None = None) -> dict:
        path = "/api/approvals" + (f"?status={status}" if status else "")
        return self.get(path).json or {"count": 0, "actions": []}

    def approval_detail(self, action_id: str) -> dict:
        return self.get(f"/api/approvals/{action_id}").json or {}

    def approve_action(self, action_id: str, reason: str = "") -> dict:
        return self.post(f"/api/approvals/{action_id}/approve", json_data={"reason": reason}).json or {}

    def reject_action(self, action_id: str, reason: str = "") -> dict:
        return self.post(f"/api/approvals/{action_id}/reject", json_data={"reason": reason}).json or {}

    # ---------- 通用裸请求（带 headers 返回） ----------
    def raw_request(
        self,
        method: str,
        path: str,
        headers: dict | None = None,
        json_data: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        """需要拿到响应头/原始字节时用这个；同样写入 call_log 供证据采集。
        返回 {status, headers, text, json, elapsed_ms, request_id}。
        """
        url = f"{self.base_url}{path}"
        rid = f"soc-test-{uuid.uuid4().hex[:12]}"
        h = {"X-Request-Id": rid}
        h.update(headers or {})
        t0 = time.perf_counter()
        try:
            resp = self.session.request(
                method, url, headers=h, json=json_data,
                timeout=timeout or self.timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            self.call_log.append(HTTPResult(
                method=method, path=path, status_code=-1, request_id=rid,
                elapsed_ms=round(elapsed, 1), body_snippet=str(exc)[:300], json=None,
            ))
            return {"status": -1, "headers": {}, "text": str(exc)[:300],
                    "json": None, "elapsed_ms": round(elapsed, 1), "request_id": rid}
        elapsed = (time.perf_counter() - t0) * 1000
        try:
            body_json = resp.json()
        except Exception:
            body_json = None
        self.call_log.append(HTTPResult(
            method=method, path=path, status_code=resp.status_code, request_id=rid,
            elapsed_ms=round(elapsed, 1), body_snippet=resp.text[:300], json=body_json,
        ))
        return {
            "status": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "text": resp.text,
            "json": body_json,
            "elapsed_ms": round(elapsed, 1),
            "request_id": rid,
        }

    # ---------- 鉴权策略探测 ----------
    def probe_auth_policy(self) -> dict:
        """返回 token/auth 策略的多个探测信号，用于报告里整理出'鉴权策略说明'。"""
        login_schema = self.post("/api/auth/login", json_data={})
        login_wrong = self.post("/api/auth/login", json_data={"username_or_email": "_probe", "password": "_wrong"})
        me = self.get("/api/users/me")
        auth_me = self.get("/api/auth/me")
        csrf = self.get("/api/auth/csrf-token")
        return {
            "/api/auth/login (empty)": {"status": login_schema.status_code, "body": login_schema.body_snippet[:200]},
            "/api/auth/login (wrong)": {"status": login_wrong.status_code, "body": login_wrong.body_snippet[:120]},
            "/api/users/me (anon)": {"status": me.status_code, "body": me.body_snippet[:120]},
            "/api/auth/me (anon)": {"status": auth_me.status_code, "body": auth_me.body_snippet[:120]},
            "/api/auth/csrf-token": {"status": csrf.status_code, "body": csrf.body_snippet[:120]},
        }

    # ---------- workflow（编排）相关 ----------
    def list_workflows(self) -> list[dict]:
        return (self.get("/api/workflows").json or {}).get("workflows", [])

    def get_workflow(self, workflow_id: str) -> dict:
        return self.get(f"/api/workflows/{workflow_id}").json or {}

    def list_workflow_runs(self, workflow_id: str) -> list[dict]:
        return (self.get(f"/api/workflows/{workflow_id}/runs").json or {}).get("runs", [])

    def get_workflow_run(self, run_id: str) -> dict:
        return self.get(f"/api/workflows/runs/{run_id}").json or {}

    def trigger_workflow_run(self, workflow_id: str, case_id: str | None = None,
                             extra: dict | None = None, timeout: float = 8) -> dict:
        """POST /api/workflows/<id>/run。orchestrator 同步执行可能较慢，自带短 timeout。
        即使 timeout，run 也已经在服务器侧创建，可后续通过 list_workflow_runs 找到。
        返回 {triggered: bool, status_code, body, exception}.
        """
        body = {}
        if case_id:
            body["case_id"] = case_id
        if extra:
            body.update(extra)
        # 临时把 timeout 调小，单独发 POST，不污染 self.timeout
        url = f"{self.base_url}/api/workflows/{workflow_id}/run"
        rid = f"soc-test-{uuid.uuid4().hex[:12]}"
        headers = {"X-Request-Id": rid, "Content-Type": "application/json"}
        t0 = time.perf_counter()
        try:
            resp = self.session.post(url, headers=headers, json=body, timeout=timeout)
            elapsed = (time.perf_counter() - t0) * 1000
            self.call_log.append(HTTPResult(
                method="POST", path=f"/api/workflows/{workflow_id}/run",
                status_code=resp.status_code, request_id=rid,
                elapsed_ms=round(elapsed, 1), body_snippet=resp.text[:300],
                json=(resp.json() if resp.content else None),
            ))
            return {"triggered": resp.status_code in (200, 201, 202),
                    "status_code": resp.status_code, "body": resp.text[:300]}
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            # 失败也记录一条假 HTTPResult 便于在证据中看到
            self.call_log.append(HTTPResult(
                method="POST", path=f"/api/workflows/{workflow_id}/run",
                status_code=-1, request_id=rid,
                elapsed_ms=round(elapsed, 1), body_snippet=str(exc)[:300], json=None,
            ))
            return {"triggered": False, "status_code": -1, "exception": str(exc)[:200]}

    # ---------- reasoning interactions ----------
    def list_reasoning_interactions(self, session_id: int, limit: int = 100) -> list[dict]:
        r = self.get(f"/api/reasoning/{session_id}/interactions?limit={limit}")
        return (r.json or {}).get("interactions", [])

    # ---------- 真伪 SSE 探测 ----------
    def probe_sse_real(self, path: str, timeout: float = 4) -> dict:
        """探测某 path 是否是真正的 SSE（content-type: text/event-stream），
        而不是平台 SPA 包装的 JSON 404。返回 {status, content_type, is_real_sse, first_event}.
        """
        url = f"{self.base_url}{path}"
        try:
            with self.session.get(url, stream=True, timeout=timeout,
                                  headers={"Accept": "text/event-stream"}) as r:
                ct = r.headers.get("content-type", "")
                is_sse = "text/event-stream" in ct
                first_event = ""
                if is_sse:
                    for line in r.iter_lines(decode_unicode=True):
                        if line:
                            first_event = line[:200]
                            break
                return {
                    "path": path,
                    "status": r.status_code,
                    "content_type": ct,
                    "is_real_sse": is_sse,
                    "first_event": first_event,
                }
        except Exception as e:
            return {"path": path, "status": -1, "content_type": "", "is_real_sse": False, "error": str(e)[:120]}

    # ---------- 工具：解析 alert_id / rule 关键字 ----------
    @staticmethod
    def parse_wazuh_alert_id(finding_id: str) -> str | None:
        """finding_id 形如 'wazuh-1782205405.49895' → alert_id = '1782205405.49895'"""
        if not finding_id or not finding_id.startswith("wazuh-"):
            return None
        return finding_id[len("wazuh-"):]

    # ---------- SSE 简易客户端 ----------
    def open_sse(self, path: str, headers: dict | None = None, max_events: int = 5, timeout: float = 10):
        """打开 SSE 流，最多读 max_events 条事件后关闭。返回 (status, events[])。"""
        url = f"{self.base_url}{path}"
        h = dict(self.session.headers)
        h.update(headers or {})
        h["Accept"] = "text/event-stream"
        events: list[str] = []
        try:
            with self.session.get(url, headers=h, stream=True, timeout=timeout) as resp:
                if resp.status_code != 200:
                    return resp.status_code, events
                t0 = time.time()
                for raw in resp.iter_lines(decode_unicode=True):
                    if raw is None:
                        continue
                    if raw:
                        events.append(raw)
                    if len(events) >= max_events or (time.time() - t0) > timeout:
                        break
                return 200, events
        except requests.RequestException as exc:
            return -1, [str(exc)]

    # ---------- WebSocket Upgrade 探测 ----------
    def probe_ws_upgrade(self, path: str, headers: dict | None = None, timeout: float = 5) -> dict:
        """只发一次未携带认证的 WebSocket Upgrade 请求，返回 status + headers。"""
        url = f"{self.base_url}{path}"
        h = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        }
        h.update(headers or {})
        try:
            resp = self.session.get(url, headers=h, timeout=timeout, allow_redirects=False)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:200],
            }
        except requests.RequestException as exc:
            return {"status_code": -1, "error": str(exc)[:200]}
