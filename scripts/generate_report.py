#!/usr/bin/env python3
"""把 reports/<run_id>/evidence/*.json 聚合成 report.md + report.json

被 pytest_sessionfinish 钩子自动调用，也可独立运行：
  python scripts/generate_report.py [run_dir]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import yaml


STATUS_ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "SKIP": "⏭️", "INFO": "ℹ️", "RUNNING": "🔄"}
ROOT = Path(__file__).resolve().parent.parent


def _target_url(run_dir: Path) -> str:
    snapshot = run_dir / "run-config.snapshot.yaml"
    source = snapshot if snapshot.exists() else ROOT / "config/target.yaml"
    config = yaml.safe_load(source.read_text(encoding="utf-8"))
    return config["target"]["base_url"]


def _load_evidence(run_dir: Path) -> list[dict]:
    out = []
    ev_dir = run_dir / "evidence"
    if not ev_dir.exists():
        return out
    for p in sorted(ev_dir.glob("*.json")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                out.append(json.load(f))
        except Exception as e:
            print(f"[warn] 无法解析 {p}: {e}", file=sys.stderr)
    return out


def _summary_table(records: list[dict]) -> str:
    if not records:
        return "_（无证据文件）_"
    lines = ["| # | 用例 ID | MITRE | 状态 | 耗时 (ms) | AI 评分 | 摘要 |",
             "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(records, 1):
        ai = r.get("ai_score") or {}
        ai_total = ai.get("total") if isinstance(ai, dict) else ""
        if not ai_total and isinstance(ai, dict):
            # 重新计算（防止 dataclass property 没序列化）
            keys = ["detection_trigger", "attck_mapping", "evidence_reference",
                    "chain_reconstruction", "risk_rating",
                    "false_positive_suppression", "response_suggestion",
                    "hallucination_control"]
            vals = [ai.get(k, 0) for k in keys if k in ai]
            ai_total = round(sum(vals) / len(vals), 2) if vals else ""
        icon = STATUS_ICON.get(r.get("status", ""), "?")
        lines.append(
            f"| {i} | {r.get('case_id','')} | {r.get('mitre','N/A')} | {icon} {r.get('status','')} | "
            f"{round(r.get('duration_ms',0))} | {ai_total} | {r.get('message','')[:80]} |"
        )
    return "\n".join(lines)


def _observability_overview(records: list[dict]) -> str:
    """跨用例汇总 8 类可观测性指标。"""
    if not records:
        return "_（无证据文件）_"
    totals = {
        "request_ids": 0, "wazuh_rule_keys": 0, "wazuh_alert_ids": 0,
        "case_finding_links": 0, "approvals": 0, "rollback_records": 0,
        "sse_probes": 0, "sse_real": 0, "auth_signals": 0,
    }
    cases_with = {k: 0 for k in totals}
    for r in records:
        obs = r.get("observability") or {}
        for k in ["request_ids", "wazuh_rule_keys", "wazuh_alert_ids",
                  "case_finding_links", "approvals", "rollback_records", "sse_probes"]:
            n = len(obs.get(k) or [])
            totals[k] += n
            if n:
                cases_with[k] += 1
        sse = obs.get("sse_probes") or []
        sse_real = sum(1 for p in sse if p.get("is_real_sse"))
        totals["sse_real"] += sse_real
        ap = obs.get("auth_policy") or {}
        if ap:
            totals["auth_signals"] += len(ap)
            cases_with["auth_signals"] = cases_with.get("auth_signals", 0) + 1

    rows = [
        ("request_id 透传", totals["request_ids"], cases_with["request_ids"], "每次 HTTP 请求注入的 X-Request-Id"),
        ("rule_id / mitre 关键字", totals["wazuh_rule_keys"], cases_with["wazuh_rule_keys"], "由 finding.mitre_predictions + description 推断"),
        ("alert_id", totals["wazuh_alert_ids"], cases_with["wazuh_alert_ids"], "从 finding_id 'wazuh-<unix>.<id>' 解析"),
        ("case ⇄ finding 关联", totals["case_finding_links"], cases_with["case_finding_links"], "GET /api/cases/{id} 返回的 finding_ids 完整列表"),
        ("审批单", totals["approvals"], cases_with["approvals"], "GET /api/approvals?status=… 拉的真实记录"),
        ("响应回滚记录", totals["rollback_records"], cases_with["rollback_records"], "平台无 /rollback API；以 approval reject 作代理"),
        ("SSE 事件 (真 SSE)", f"{totals['sse_real']}/{totals['sse_probes']}", cases_with["sse_probes"], "多数 /api/*/stream 返回 application/json，非真 SSE"),
        ("token 鉴权策略信号", totals["auth_signals"], cases_with.get("auth_signals", 0), "/api/auth/login、/api/users/me、/api/auth/me 的 401 行为"),
    ]
    lines = ["| 类别 | 累计条数 | 覆盖用例数 | 说明 |", "|---|---|---|---|"]
    for name, total, n_cases, note in rows:
        lines.append(f"| {name} | {total} | {n_cases}/{len(records)} | {note} |")
    return "\n".join(lines)


def _evidence_section(r: dict) -> str:
    parts = [f"### {r.get('case_id','')} — {r.get('mitre','N/A')}",
             "",
             f"- 状态：**{STATUS_ICON.get(r.get('status',''),'?')} {r.get('status','')}**",
             f"- 摘要：{r.get('message','')}",
             f"- 时间窗：{r.get('time_window',{}).get('start','')} ~ {r.get('time_window',{}).get('end','')}",
             f"- 耗时：{round(r.get('duration_ms',0))} ms",
             ""]
    ai = r.get("ai_score") or {}
    if ai:
        parts.append("**AI 研判评分（0-5 分）**")
        parts.append("")
        for k in ["detection_trigger", "attck_mapping", "evidence_reference",
                  "chain_reconstruction", "risk_rating",
                  "false_positive_suppression", "response_suggestion",
                  "hallucination_control"]:
            if k in ai:
                parts.append(f"- {k}: {ai[k]}")
        parts.append("")

    ev = r.get("evidence", {}) or {}
    for layer in ["client", "gateway", "application", "wazuh", "vigil_ai", "response"]:
        items = ev.get(layer, [])
        if not items:
            continue
        parts.append(f"**{layer} 层证据（{len(items)} 条）**")
        parts.append("")
        parts.append("```json")
        parts.append(json.dumps(items[:5], ensure_ascii=False, indent=2, default=str))
        if len(items) > 5:
            parts.append(f"... 省略 {len(items) - 5} 条")
        parts.append("```")
        parts.append("")
    assertions = r.get("assertions") or []
    if assertions:
        parts.append("**断言**")
        for a in assertions:
            mark = "✓" if a.get("ok") else "✗"
            parts.append(f"- {mark} {a.get('name','')} — {a.get('detail','')}")
        parts.append("")

    obs = r.get("observability") or {}
    if obs:
        parts.append("**可观测性核查（8 类）**")
        parts.append("")
        parts.append("| 字段 | 取得 | 说明 |")
        parts.append("|---|---|---|")
        rids = obs.get("request_ids") or []
        parts.append(f"| request_id | {len(rids)} 个 | 样本：`{', '.join(rids[:3]) or '—'}` |")
        rks = obs.get("wazuh_rule_keys") or []
        parts.append(f"| rule_id / mitre | {len(rks)} 条 | 样本：{('; '.join(rks[:3]) or '—')[:120]} |")
        aids = obs.get("wazuh_alert_ids") or []
        parts.append(f"| alert_id | {len(aids)} 条 | 样本：`{', '.join(aids[:3]) or '—'}` |")
        cfs = obs.get("case_finding_links") or []
        cf_repr = "; ".join(f"{x.get('case_id')}→{x.get('count')}fid" for x in cfs[:3]) or "—"
        parts.append(f"| case⇄finding 关联 | {len(cfs)} 条 | {cf_repr} |")
        apv = obs.get("approvals") or []
        if apv:
            counts = (apv[0].get("counts") if apv and isinstance(apv[0], dict) else {}) or {}
            parts.append(f"| 审批单 | pending={counts.get('pending',0)}/approved={counts.get('approved',0)}/executed={counts.get('executed',0)}/rejected={counts.get('rejected',0)} | `/api/approvals` |")
        else:
            parts.append("| 审批单 | — | 未采集 |")
        rbs = obs.get("rollback_records") or []
        rb_repr = "; ".join(x.get("proxy", "") for x in rbs[:2]) or "—"
        parts.append(f"| 响应回滚记录 | {len(rbs)} 条 | {rb_repr} |")
        sse = obs.get("sse_probes") or []
        sse_real = [p for p in sse if p.get("is_real_sse")]
        parts.append(f"| SSE 事件 | 真 SSE = {len(sse_real)} / 探测 {len(sse)} 条路径 | 多数路径返回 `application/json`，非真 SSE |")
        auth = obs.get("auth_policy") or {}
        auth_repr = "; ".join(f"{k.split()[-1]}={v.get('status') if isinstance(v, dict) else ''}" for k, v in list(auth.items())[:3])
        parts.append(f"| token 鉴权策略 | {len(auth)} 条信号 | {auth_repr or '—'} |")
        parts.append("")
        # 附完整 JSON 段
        parts.append("<details><summary>展开可观测性原始数据</summary>")
        parts.append("")
        parts.append("```json")
        parts.append(json.dumps(obs, ensure_ascii=False, indent=2, default=str)[:4000])
        parts.append("```")
        parts.append("</details>")
        parts.append("")

    return "\n".join(parts)


def generate(run_dir: Path) -> dict:
    records = _load_evidence(run_dir)
    target_url = _target_url(run_dir)
    totals = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "RUNNING": 0}
    for r in records:
        totals[r.get("status", "")] = totals.get(r.get("status", ""), 0) + 1

    md = []
    md.append(f"# AI-SOC 测试报告 — run {run_dir.name}")
    md.append("")
    md.append(f"**目标平台：** {target_url}")
    md.append(f"**生成时间：** {datetime.utcnow().isoformat()}Z")
    md.append(f"**用例总数：** {len(records)}  |  ✅ PASS: {totals.get('PASS',0)}  |  ⚠️ WARN: {totals.get('WARN',0)}  |  ❌ FAIL: {totals.get('FAIL',0)}  |  ⏭️ SKIP: {totals.get('SKIP',0)}")
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 用例总览")
    md.append("")
    md.append(_summary_table(records))
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 可观测性覆盖一览（8 类信息）")
    md.append("")
    md.append(_observability_overview(records))
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 逐条用例详情")
    md.append("")
    for r in records:
        md.append(_evidence_section(r))
        md.append("")
        md.append("---")
        md.append("")

    (run_dir / "report.md").write_text("\n".join(md), encoding="utf-8")

    summary = {
        "run_id": run_dir.name,
        "target": target_url,
        "generated_at": datetime.utcnow().isoformat(),
        "totals": totals,
        "cases": records,
    }
    (run_dir / "report.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    return summary


def generate_for_latest(reports_root: str) -> dict | None:
    root = Path(reports_root)
    if not root.exists():
        return None
    runs = [p for p in root.iterdir() if p.is_dir() and (p / "evidence").exists()]
    if not runs:
        return None
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return generate(runs[0])


def main() -> int:
    if len(sys.argv) > 1:
        rd = Path(sys.argv[1])
    else:
        # 找最新的 reports/<run_id>
        root = Path(__file__).resolve().parent.parent / "reports"
        runs = [p for p in root.iterdir() if p.is_dir() and (p / "evidence").exists()]
        if not runs:
            print("没有可生成的报告（reports/<run_id>/evidence/ 为空）", file=sys.stderr)
            return 1
        runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        rd = runs[0]
    summary = generate(rd)
    print(f"已生成：{rd / 'report.md'}")
    print(f"统计：{summary['totals']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
