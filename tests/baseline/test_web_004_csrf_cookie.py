"""SOC-WEB-004 — CSRF cookie 属性核查

平台在多数 GET 响应中 set-cookie: csrf_token=...。属性必须包括：
  - Path=/         必须
  - SameSite=Strict 或 Lax 必须
  - Secure         强建议（HTTPS 部署时强制；HTTP 部署仅 WARN）
  - HttpOnly       对 csrf token 可选（一般 csrf 需要 JS 读，故通常不设）
"""
import re
import pytest

CASE_ID = "SOC-WEB-004"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.baseline]


def _parse_setcookie(line: str) -> dict:
    """简化：把 'csrf_token=xxx; Path=/; SameSite=strict; Secure' 解析为 dict"""
    out = {}
    parts = [p.strip() for p in line.split(";") if p.strip()]
    if parts:
        k, _, v = parts[0].partition("=")
        out["name"] = k
        out["value_present"] = bool(v)
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            out[k.strip().lower()] = v.strip()
        else:
            out[p.strip().lower()] = True
    return out


def test_csrf_cookie_attrs(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    r = target.raw_request("GET", "/api/health")
    sc = r["headers"].get("set-cookie", "")
    rec.gateway({"set_cookie_raw": sc})

    csrf = None
    if sc and "csrf" in sc.lower():
        csrf = _parse_setcookie(sc)
    rec.application({"parsed": csrf})

    if not csrf:
        rec.assertion("csrf_cookie_present", False, "无 csrf cookie")
        rec.finish("WARN", "未找到 csrf cookie；若平台依赖其它防护需另行核实")
        score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
        rec.set_ai_score(score)
        return

    has_path = csrf.get("path") == "/"
    has_samesite = csrf.get("samesite", "").lower() in ("strict", "lax")
    has_secure = csrf.get("secure") is True

    rec.assertion("csrf_cookie_present", True, csrf.get("name", ""))
    rec.assertion("csrf_path_root", has_path, str(csrf.get("path")))
    rec.assertion("csrf_samesite_set", has_samesite, str(csrf.get("samesite")))
    rec.assertion("csrf_secure_flag", has_secure, "Secure 必须")

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=0, expected_hits=0)
    rec.set_ai_score(score)
    if has_path and has_samesite and has_secure:
        rec.finish("PASS", "csrf cookie 属性合规：Path/SameSite/Secure")
    elif has_path and has_samesite:
        rec.finish("WARN", "csrf cookie 缺 Secure（HTTP 部署可暂忽略，HTTPS 必须）")
    else:
        rec.finish("FAIL", f"csrf cookie 属性不合规: {csrf}")
