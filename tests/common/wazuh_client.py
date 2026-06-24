"""
Wazuh Manager API (55000) + Wazuh Indexer (OpenSearch 9200) 客户端
凭据缺失时构造方法直接抛 RuntimeError，由 fixture 转成 pytest.skip
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class WazuhAlert:
    alert_id: str
    rule_id: int
    rule_level: int
    description: str
    agent_ip: Optional[str]
    src_ip: Optional[str]
    full_log: str
    timestamp: str


class WazuhClient:
    def __init__(
        self,
        api_host: str = "",
        api_port: int = 55000,
        api_user: str = "",
        api_pass: str = "",
        indexer_host: str = "",
        indexer_port: int = 9200,
        indexer_user: str = "",
        indexer_pass: str = "",
        verify_tls: bool = False,
        alerts_index: str = "wazuh-alerts-*",
    ) -> None:
        self.api_base = f"https://{api_host}:{api_port}" if api_host else ""
        self.api_user = api_user
        self.api_pass = api_pass
        self.indexer_base = f"https://{indexer_host}:{indexer_port}" if indexer_host else ""
        self.indexer_auth = (indexer_user, indexer_pass) if indexer_user else None
        self.verify_tls = verify_tls
        self.alerts_index = alerts_index
        self._jwt: Optional[str] = None

    # ---------- Manager API (55000) ----------
    def _auth(self) -> str:
        if not self.api_base:
            raise RuntimeError("wazuh_api 未配置")
        if self._jwt:
            return self._jwt
        r = requests.post(
            f"{self.api_base}/security/user/authenticate",
            auth=(self.api_user, self.api_pass),
            verify=self.verify_tls,
            timeout=10,
        )
        r.raise_for_status()
        self._jwt = (r.json().get("data") or {}).get("token", "")
        if not self._jwt:
            raise RuntimeError(f"Wazuh API 认证失败：{r.text[:200]}")
        return self._jwt

    def list_rules(self, rule_ids: list[int] | None = None) -> list[dict]:
        token = self._auth()
        params = {"limit": 500}
        if rule_ids:
            params["rule_ids"] = ",".join(str(i) for i in rule_ids)
        r = requests.get(
            f"{self.api_base}/rules",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            verify=self.verify_tls,
            timeout=15,
        )
        if r.status_code != 200:
            return []
        return (r.json().get("data", {}).get("affected_items") or [])

    # ---------- Indexer (9200) ----------
    def query_alerts(
        self,
        rule_ids: list[int] | None = None,
        rule_description_like: str | None = None,
        agent_ip: str | None = None,
        src_ip: str | None = None,
        since_seconds: int = 600,
        size: int = 100,
    ) -> list[WazuhAlert]:
        if not self.indexer_base:
            raise RuntimeError("wazuh_indexer 未配置")
        must: list[dict] = []
        must.append({"range": {"@timestamp": {"gte": f"now-{since_seconds}s"}}})
        if rule_ids:
            must.append({"terms": {"rule.id": [str(i) for i in rule_ids]}})
        if rule_description_like:
            must.append({"match": {"rule.description": rule_description_like}})
        if agent_ip:
            must.append({"term": {"agent.ip": agent_ip}})
        if src_ip:
            must.append({"term": {"data.srcip": src_ip}})
        body = {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"must": must}},
        }
        r = requests.post(
            f"{self.indexer_base}/{self.alerts_index}/_search",
            json=body,
            auth=self.indexer_auth,
            verify=self.verify_tls,
            timeout=15,
        )
        if r.status_code != 200:
            return []
        hits = r.json().get("hits", {}).get("hits", [])
        out: list[WazuhAlert] = []
        for h in hits:
            s = h.get("_source", {})
            out.append(
                WazuhAlert(
                    alert_id=h.get("_id", ""),
                    rule_id=int((s.get("rule") or {}).get("id") or 0),
                    rule_level=int((s.get("rule") or {}).get("level") or 0),
                    description=(s.get("rule") or {}).get("description", ""),
                    agent_ip=(s.get("agent") or {}).get("ip"),
                    src_ip=(s.get("data") or {}).get("srcip"),
                    full_log=s.get("full_log", "")[:500],
                    timestamp=s.get("@timestamp", ""),
                )
            )
        return out

    def wait_alerts(
        self,
        *,
        rule_ids: list[int] | None = None,
        rule_description_like: str | None = None,
        min_count: int = 1,
        timeout_seconds: int = 60,
        poll_seconds: int = 5,
        **kw,
    ) -> list[WazuhAlert]:
        """轮询 Indexer 直到出现 >= min_count 条匹配 alert 或超时。"""
        t_end = time.time() + timeout_seconds
        while True:
            alerts = self.query_alerts(
                rule_ids=rule_ids, rule_description_like=rule_description_like, **kw
            )
            if len(alerts) >= min_count:
                return alerts
            if time.time() > t_end:
                return alerts
            time.sleep(poll_seconds)
