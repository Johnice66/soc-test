# 04 — 证据链 6 层模型（原理文档）

> 对应 docx 第 9 节 / TABLE 8。这是 AI-SOC 测试**最重要**的概念：测试通过与否，不仅看 assert，更看证据是否充分。本文档讲清楚每层是什么、为什么是 6 层、代码里如何用。

---

## 为什么是 6 层

AI-SOC 的核心命题是：**把一次攻击行为，从客户端发起、网关转发、应用处理、Wazuh 检测、AI 研判、响应闭环，串成一条可解释、可审计、可回溯的链路**。任何一层缺证据，整个 case 都不可信。

docx TABLE 8 把这条链路最低公约数定为 6 层：

```
攻击发起 → 网关 → 应用 → Wazuh 检测 → AI 研判 → 响应
   ▲         ▲       ▲        ▲          ▲         ▲
 client   gateway  app    wazuh     vigil_ai   response
```

每层都有"必备字段"：缺哪一类字段，对应那层证据不完整。

| 层 | 必备字段（最低集） | 含义 |
|---|---|---|
| **client** | 请求/连接参数、消息序列、关闭码、源 IP、测试脚本版本、时间戳 | "我是谁、我做了什么" |
| **gateway** | request_id、route、upstream、status、latency、auth_result、limit_result | "请求过了哪个网关、路由到哪、被限流没" |
| **application** | Identity/Agent/WattBot/WebIDE 审计事件、K8s 对象、资源状态 | "应用层看到的、做了什么业务动作" |
| **wazuh** | decoder、rule_id、level、alert_id、Index 文档 ID、原始日志摘要 | "Wazuh 把这事识别成什么规则、什么级别" |
| **vigil_ai** | finding_id、case_id、workflow、AI 报告、证据引用、置信度、响应建议 | "Vigil 怎么聚合、AI 怎么研判" |
| **response** | 审批人、dry-run 结果、执行动作、回滚动作、执行日志、最终状态 | "最后做没做、能不能回滚" |

---

## 代码如何对应

文件：[tests/common/evidence.py](../tests/common/evidence.py)

```python
@dataclass
class CaseEvidence:
    case_id: str
    mitre: str
    run_id: str
    started_at: str
    finished_at: str
    status: str          # PASS / WARN / FAIL / SKIP
    time_window: {start, end}
    evidence: {
        "client":      [...],   # 添加：rec.client(dict_or_obj)
        "gateway":     [...],   # 添加：rec.gateway(...)
        "application": [...],   # 添加：rec.application(...)
        "wazuh":       [...],   # 添加：rec.wazuh(...)
        "vigil_ai":    [...],   # 添加：rec.vigil(...)
        "response":    [...],   # 添加：rec.response(...)
    }
    ai_score: dict | None       # 添加：rec.set_ai_score(score)
    assertions: list[dict]      # 添加：rec.assertion(name, ok, detail)
```

### 在用例里如何用

```python
def test_my_case(target, wazuh, ssh_host, evidence_recorder):
    rec = evidence_recorder
    # 1) client 层：我做了什么
    rec.client({"command": "ssh testuser@... wrong_pw x5", "src_ip": "..."} )
    # 2) 执行
    ssh_host.run("...")
    # 3) wazuh 层：Wazuh 检测到了什么
    alerts = wazuh.wait_alerts(rule_description_like="sshd", min_count=5)
    rec.wazuh([{"id": a.alert_id, "rule": a.rule_id, "level": a.rule_level} for a in alerts])
    # 4) vigil_ai 层：finding/case/AI
    findings = target.get_findings()
    case_id = target.create_case(...)
    rec.vigil({"case_id": case_id, "linked_findings": len(findings)})
    # 5) response 层
    rec.response({"action": "block_ip", "dry_run": True, "executed": False})
    # 6) 断言 + 收尾
    rec.assertion("wazuh_alerts_ge_5", len(alerts) >= 5, f"{len(alerts)}")
    assert len(alerts) >= 5
    rec.finish("PASS", f"触发 {len(alerts)} 条告警")
```

`rec.finish()` 写出 `reports/<run_id>/evidence/<case_id>.json`，结构完全对应上面的 dataclass。

---

## 字段不全时怎么办

docx 第 13 节 "风险控制" 规定：**证据链丢失、时间不同步、无法关联 case_id/run_id 时，本轮结果不得作为正式验收证据**。所以：

| 情况 | 处理 |
|---|---|
| 某层完全没拿到证据 | 用例仍可 PASS，但报告里那一层是空数组，需在 finish 的 message 里说明原因 |
| 时间戳缺失 / 不同步 | EvidenceRecorder 自动用 `datetime.utcnow()`，所有用例统一 UTC，避免本地时区漂移 |
| Wazuh 查不到对应 alert | 不要"虚构 alert_id 让用例过"。直接让用例 FAIL 或 WARN，让人工查为什么没采到 |
| AI 没产生 reasoning session | `evidence.vigil_ai` 为空 + AIScorer.detection_trigger 拿到 0 分；这是真实状况的反映 |

---

## 6 层之外：可观测性 8 类（自动附加）

除了六层证据，每条用例还会在 fixture teardown 时自动收集 **8 类平台可观测性信息**，写在 `evidence.observability` 字段下，由 [tests/common/observability.py](../tests/common/observability.py) 实现，**用例无需写一行代码即可获得**：

| 类别 | 来源 | 字段路径 |
|---|---|---|
| `request_id` | 每次 HTTP 调用注入 `X-Request-Id`，从 `HTTPClient.call_log` 抓 | `observability.request_ids[]` |
| `rule_id` / mitre 推断 | `finding.mitre_predictions` + `finding.description` | `observability.wazuh_rule_keys[]` |
| `alert_id` | 从 `finding_id="wazuh-<unix>.<id>"` 解析出 `<unix>.<id>` | `observability.wazuh_alert_ids[]` |
| `case ⇄ finding` 关联 | `GET /api/cases/<id>` 返回的 `finding_ids[]` | `observability.case_finding_links[]` |
| 审批单 | `GET /api/approvals?status=pending\|approved\|executed\|rejected` | `observability.approvals[].counts/sample_*` |
| 响应回滚记录 | 平台无独立 `/rollback` 端点；以 `approval reject` 作代理 | `observability.rollback_records[]` |
| SSE 事件 | 探测 `/api/orchestrator/stream` 等 6 条路径，判断 `content-type: text/event-stream` | `observability.sse_probes[]` |
| token 鉴权策略信号 | `/api/auth/login` 空体/错凭据响应、`/api/users/me` 401、`/api/auth/me` 401、`/api/auth/csrf-token` | `observability.auth_policy` |

**全局摘要**：报告 Markdown 顶部"可观测性覆盖一览（8 类信息）"表格汇总 19 个用例的累计统计。**逐条摘要**：每条用例段落里有"可观测性核查（8 类）"小表 + 折叠 JSON。

> SSE 与 token 鉴权探测在 session 级 cache，跨 26 条用例只发一次请求，避免压测。

## 与旧版 ai_soc_pipeline_report.md 的兼容

旧版报告把六步串起来用 Markdown 表格表达。本版的 `report.md` 是从 `evidence/*.json` 反向聚合的，**字段是六层证据 + AI 评分的超集**：

- 旧版 "STEP X" → 新版用例 ID（`PIPELINE-STEP-1` ~ `PIPELINE-STEP-6`）
- 旧版 "结论" 段 → 新版 `finish(status, message)` 的 message + assertions 列表
- 旧版没有的：六层证据各自的 JSON、AI 评分 7 维度、`run_id` 与时间窗

迁移规则：任何旧报告里能看到的字段，在新版的 `report.json` 里都能找到；新版多出的字段是为下一步**自动化对比**（reports/A.json vs reports/B.json）准备的。
