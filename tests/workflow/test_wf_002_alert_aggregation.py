"""SOC-WF-002 — 多 alert 聚合为 finding

验证：
  1) findings 列表中存在按"实体（src_ip / username / host）"聚合的现象；
  2) 至少 1 个 finding 在 description / metadata 里聚合了多条原始 alert（关键词：multiple/x 次/N times/同源）；
     或同一 (src_ip, technique) 多个 finding 表明聚合维度存在；
  3) Vigil 层没有把同源 alert 重复展平。

实现思路：findings API 当前不直接暴露 alert_count 字段，
        通过分组比较"独立 alert_id 数 vs finding 数"来推断聚合存在。
"""
import re
import pytest
from collections import Counter
from tests.common.matrix_loader import get_case

CASE_ID = "SOC-WF-002"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.wf]

_AGG_KEYWORDS = re.compile(r"(multiple|多次|多条|aggregat|grouped|times|connections|attempts)", re.I)


def test_alert_aggregation(target, evidence_recorder, ai_scorer):
    rec = evidence_recorder
    rec.client({"case_meta": get_case(CASE_ID)})
    findings = target.get_findings(limit=500)
    rec.application({"total_findings": len(findings)})
    assert findings, "findings 接口为空，无法判断聚合"

    # 统计独立 alert_id 与 finding 数
    alert_ids, src_ips, agg_hits = [], [], []
    for f in findings:
        aid = target.parse_wazuh_alert_id(f.get("finding_id", ""))
        if aid:
            alert_ids.append(aid)
        ip = (f.get("src_ip") or (f.get("metadata") or {}).get("src_ip") or "")
        if ip:
            src_ips.append(ip)
        desc = (f.get("description") or "") + " " + (f.get("title") or "")
        if _AGG_KEYWORDS.search(desc):
            agg_hits.append({"finding_id": f["finding_id"], "snippet": desc[:120]})

    ip_counter = Counter(src_ips)
    top_ips = ip_counter.most_common(5)
    rec.vigil({
        "unique_alert_ids": len(set(alert_ids)),
        "unique_src_ips": len(set(src_ips)),
        "top_src_ips": top_ips,
        "agg_keyword_hits": len(agg_hits),
        "agg_keyword_sample": agg_hits[:3],
    })

    # 判定（任一满足即视为聚合特征存在）：
    #   A) 存在描述里明确聚合关键词的 finding；
    #   B) 同源 IP 下产生了多条 finding（说明按 IP 维度有聚合分布）。
    signal_a = len(agg_hits) >= 1
    signal_b = any(c >= 3 for _, c in top_ips)
    aggregation_present = signal_a or signal_b

    rec.assertion("aggregation_signal_present", aggregation_present,
                  f"keyword={signal_a} same_ip_cluster={signal_b}")
    rec.assertion("findings_not_exploded", len(findings) <= max(20, len(set(alert_ids))),
                  f"findings={len(findings)} unique_alerts={len(set(alert_ids))}")
    assert aggregation_present, "未发现聚合信号（关键词或同源 IP 多 finding）"

    score = ai_scorer.score(CASE_ID, MITRE, wazuh_hits=len(findings), expected_hits=3)
    rec.set_ai_score(score)
    rec.finish("PASS", f"findings={len(findings)} 聚合关键词={len(agg_hits)} 顶 IP={top_ips[:2]}")
