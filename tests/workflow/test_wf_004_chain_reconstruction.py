"""SOC-WF-004 — 攻击链 case 还原（登录 → 提权 → 持久化）

不依赖 SSH/Wazuh：取平台已有 findings，看是否能在 case detail / reasoning interactions
中观察到"多 MITRE 技术 ID 共现"（登录类 T1110.* / 提权类 T1068|T1548 / 持久化类 T1136|T1543）。
任一三选二满足 → PASS；只命中一类 → WARN；都没命中 → FAIL。
"""
import re
import pytest

CASE_ID = "SOC-WF-004"
MITRE = "T1078"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_TECH_GROUPS = {
    "initial_access": re.compile(r"T1110(\.\d+)?|T1078(\.\d+)?|T1190"),
    "privilege_esc": re.compile(r"T1068|T1548(\.\d+)?|T1055"),
    "persistence":   re.compile(r"T1136(\.\d+)?|T1543(\.\d+)?|T1098|T1547"),
}


def _hit_groups(text: str) -> set[str]:
    out = set()
    for name, pat in _TECH_GROUPS.items():
        if pat.search(text):
            out.add(name)
    return out


def test_chain_reconstruction(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"tech_groups": list(_TECH_GROUPS.keys())})

    findings = target.get_findings(limit=50)
    finding_techs = []
    blob = ""
    for f in findings:
        mp = f.get("mitre_predictions") or {}
        if isinstance(mp, dict):
            finding_techs.extend(list(mp.keys()))
        blob += " " + str(mp) + " " + (f.get("description") or "")

    cases = target.list_cases(limit=20)
    for c in cases:
        blob += " " + (c.get("title") or "") + " " + (c.get("description") or "") \
                + " " + str(c.get("tags") or [])

    # reasoning interactions 中也含 MITRE 引用
    r1 = target.raw_request("GET", "/api/reasoning/1/interactions?limit=20")
    inter = (r1["json"] or {}).get("interactions", []) if isinstance(r1["json"], dict) else []
    for it in inter:
        blob += " " + str(it)[:2000]

    hit_groups = _hit_groups(blob)
    rec.gateway({"findings_count": len(findings), "cases_count": len(cases),
                 "interactions_count": len(inter),
                 "hit_groups": sorted(hit_groups),
                 "all_techs_in_findings": sorted(set(finding_techs))[:20]})

    rec.assertion("hit_at_least_one_group", bool(hit_groups), str(hit_groups))

    score = ai_scorer.score(CASE_ID, MITRE,
                            wazuh_hits=len(hit_groups),
                            expected_hits=2)
    rec.set_ai_score(score)
    if len(hit_groups) >= 2:
        rec.finish("PASS", f"链路证据涵盖 ≥2 类技术: {hit_groups}")
    elif len(hit_groups) == 1:
        rec.finish("WARN", f"只观察到一类技术: {hit_groups}（攻击链未完整还原）")
    else:
        rec.finish("FAIL", "未在 findings/cases/reasoning 中观察到登录/提权/持久化任一类 MITRE")
