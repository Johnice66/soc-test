"""SOC-WEB-003 — Server 头版本信息暴露

`Server: nginx/1.24.0 (Ubuntu)` 会泄漏精确版本与 OS。这是低风险信息泄漏，
PASS 条件：不返回精确版本号（仅 'nginx'/'Apache' 等通用名）。
WARN 条件：暴露精确版本但不暴露 OS。
FAIL 条件：精确版本 + OS 都暴露。
"""
import re
import pytest

CASE_ID = "SOC-WEB-003"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]

_VER_RE = re.compile(r"\d+\.\d+(\.\d+)?")
_OS_RE = re.compile(r"\((ubuntu|debian|centos|redhat|alpine|win|darwin)", re.I)


def test_server_disclosure(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    r = target.raw_request("GET", "/")
    server = r["headers"].get("server", "")
    rec.gateway({"server_header": server, "all_headers": r["headers"]})

    has_version = bool(_VER_RE.search(server))
    has_os = bool(_OS_RE.search(server))
    rec.assertion("server_header_present", bool(server), server)
    rec.assertion("version_not_leaked", not has_version, server)
    rec.assertion("os_not_leaked", not has_os, server)

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    if not has_version and not has_os:
        rec.finish("PASS", f"Server 头未暴露版本/OS: {server!r}")
    elif has_version and not has_os:
        rec.finish("WARN", f"Server 头暴露精确版本: {server!r}（建议改 'nginx' / 删除）")
    else:
        rec.finish("WARN", f"Server 头暴露版本+OS: {server!r}（建议屏蔽）")
