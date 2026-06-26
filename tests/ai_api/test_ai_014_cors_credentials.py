"""SOC-AI-014 — CORS 通配与凭据组合核查

发送 Origin: https://evil.example 的预检 (OPTIONS) 与 GET 请求，检查：
  1. Access-Control-Allow-Origin 不能是 `*`，也不能直接回写 evil.example
  2. 若 Access-Control-Allow-Credentials: true 与 ACAO=* 同时出现 → FAIL
  3. 若 Vary: Origin 缺失 → WARN（缓存可能跨源串）
"""
import pytest

CASE_ID = "SOC-AI-014"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]

_EVIL = "https://evil.example.com"
_TARGET = "/api/health"


def test_cors_evil_origin(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"origin": _EVIL, "target": _TARGET})

    pre = target.raw_request("OPTIONS", _TARGET,
                              headers={"Origin": _EVIL,
                                       "Access-Control-Request-Method": "GET"})
    get = target.raw_request("GET", _TARGET, headers={"Origin": _EVIL})

    pre_h = pre["headers"]
    get_h = get["headers"]
    rec.gateway({
        "preflight": {"status": pre["status"], "acao": pre_h.get("access-control-allow-origin"),
                      "acac": pre_h.get("access-control-allow-credentials"),
                      "vary": pre_h.get("vary")},
        "get":        {"status": get["status"], "acao": get_h.get("access-control-allow-origin"),
                       "acac": get_h.get("access-control-allow-credentials"),
                       "vary": get_h.get("vary")},
    })

    acao_pre = pre_h.get("access-control-allow-origin", "")
    acao_get = get_h.get("access-control-allow-origin", "")
    acac_pre = (pre_h.get("access-control-allow-credentials", "") or "").lower()
    acac_get = (get_h.get("access-control-allow-credentials", "") or "").lower()
    vary_get = (get_h.get("vary", "") or "").lower()

    # 任一处把 evil 写进 ACAO 都不合规
    echoes_evil = _EVIL in (acao_pre + " " + acao_get)
    wildcard_with_creds = (acao_pre == "*" and acac_pre == "true") or \
                          (acao_get == "*" and acac_get == "true")
    vary_origin_ok = "origin" in vary_get

    rec.assertion("no_evil_origin_echoed", not echoes_evil, f"{acao_pre} / {acao_get}")
    rec.assertion("no_wildcard_with_credentials", not wildcard_with_creds, "")
    rec.assertion("vary_origin_set", vary_origin_ok, vary_get)

    score = ai_scorer.score(CASE_ID, "N/A",
                            wazuh_hits=int(not (echoes_evil or wildcard_with_creds)),
                            expected_hits=1)
    rec.set_ai_score(score)
    if not echoes_evil and not wildcard_with_creds and vary_origin_ok:
        rec.finish("PASS", "CORS 不回写 evil origin，无 wildcard+credentials，Vary: Origin 已设")
    elif not echoes_evil and not wildcard_with_creds:
        rec.finish("WARN", "CORS 安全但缺 Vary: Origin（缓存风险）")
    else:
        rec.finish("FAIL", f"CORS 配置不安全 echoes_evil={echoes_evil} wildcard_with_creds={wildcard_with_creds}")
