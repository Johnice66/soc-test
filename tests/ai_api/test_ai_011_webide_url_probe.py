"""SOC-AI-011 — WattBot/WebIDE 一次性 URL 探测

匿名探测潜在的 WattBot/WebIDE/ticket 端点是否返回真实 ticket / URL。任何端点
返回 200 + 看似 token 的字符串（长 hex / base64 段）→ FAIL。
"""
import re
import pytest

CASE_ID = "SOC-AI-011"
MITRE = "T1550.001"
pytestmark = [pytest.mark.p0, pytest.mark.ai_api]

_PROBE_PATHS = [
    "/api/webide/ticket",
    "/api/webide/url",
    "/api/wattbot/ticket",
    "/api/wattbot/webui-url",
    "/api/ticket",
    "/api/tickets/generate",
]
_TOKEN_RE = re.compile(r"[A-Za-z0-9\-_]{32,}")


def test_webide_url_probe(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"probe_paths": _PROBE_PATHS})

    results = []
    leaks = []
    for p in _PROBE_PATHS:
        r = target.raw_request("GET", p)
        body_text = r["text"] or ""
        has_token = bool(_TOKEN_RE.search(body_text)) and r["status"] == 200 \
                    and "error" not in body_text.lower()
        results.append({"path": p, "status": r["status"],
                        "len": len(body_text), "has_token_like": has_token,
                        "snippet": body_text[:120]})
        if has_token:
            leaks.append(p)
    rec.gateway({"results": results, "leaks": leaks})

    rec.assertion("no_anon_ticket_endpoint", not leaks, str(leaks))

    score = ai_scorer.score(CASE_ID, MITRE,
                            wazuh_hits=0 if leaks else 1, expected_hits=1)
    rec.set_ai_score(score)
    if not leaks:
        rec.finish("PASS", f"探测 {len(_PROBE_PATHS)} 条端点，无匿名 ticket 暴露")
    else:
        rec.finish("FAIL", f"匿名可拿 ticket-like 内容: {leaks}")
