# 01 — 方案速览

> 浓缩 `AI-SOC测试方案_MITRE_ATTCK映射版_Wazuh_Vigil.docx` v2.0，保留与本仓库代码强相关的内容。完整原文见 docx 自身。

## 1. 三层测试模型

| 层 | 目标 | 用例命名前缀 | 数量 |
|---|---|---|---|
| L1 — MITRE ATT&CK 攻击场景覆盖 | 证明 AI-SOC 能覆盖真实攻击链：侦察、初始访问、凭据访问、执行、持久化、提权、防御规避、发现、横向移动、命令控制、外传、影响 | `SOC-ATT-*` | 48 |
| L2 — AI-SOC 流程闭环 | 证明日志能进 Wazuh、Wazuh 产生 alert、Vigil 接收聚合为 finding/case、AI 基于证据研判、响应进入审批/执行/回滚 | `SOC-TEL-*` + `SOC-WF-*` | 22 |
| L3 — AI 平台与 Agent 运行时安全补充 | 覆盖 ATT&CK 不能完全表达的 AI 特有风险：Agent 事件流、工具审批、Prompt 注入、长连接权限收敛、WebIDE/WattBot ticket | `SOC-AI-*` | 30 |
| **合计** | | | **100** |

## 2. 五大用例类

| 一级分类 | 用例数 | P0 数 | 代表场景 |
|---|---|---|---|
| 遥测采集与基础链路 (TEL) | 10 | 8 | 日志采集、Wazuh 规则命中、custom-vigil 转发、alert→finding→case |
| MITRE 攻击场景 (ATT) | 48 | 20 | SSH 爆破、提权、持久化、横向、外联、外传、破坏 |
| AI 平台/API 安全 (AI 001~014) | 14 | 11 | WebSocket/SSE 鉴权、可信头、WebIDE/WattBot ticket、登出收敛 |
| Agent/Socket 运行时安全 (AI 015~030) | 16 | 7 | Socket 资源滥用、SSE 背压、Agent 幂等、HITL、Prompt 注入 |
| SOC 工作流与 AI 研判 (WF) | 12 | 8 | 攻击链 case 还原、误报抑制、AI 评分、dry-run 审批、SLA |

## 3. 从 100 条 → 本轮 20 条

落地原则（详见 [08_p0_case_index.md](08_p0_case_index.md)）：
- **覆盖 5 大类，每类至少 2 条**
- **覆盖 12 个 MITRE 战术中 ≥ 6 个**
- **三个触达面均匀**：HTTP-only ×10、需 Wazuh ×3、需 SSH+Wazuh ×7
- **优先 P0**

筛选公式（伪代码）：
```
selected = []
for category in [TEL, ATT, AI_API, AI_SOCKET, WF]:
    cases = matrix[priority == P0 and category == category]
    selected += top_k_by(cases, key=lambda c: (
        coverage_breadth(c),
        attack_phase_diversity(c),
        is_smoke_testable_via_http_only(c),
    ))
```

## 4. 验收闸门（docx TABLE 10 节选）

| 指标 | 阈值 |
|---|---|
| 关键日志源采集覆盖率 | ≥ 95% |
| Critical/High 规则命中率 | 100% |
| 端到端时延（事件 → Vigil case） | Critical ≤ 15 s；High ≤ 60 s |
| 同主体/规则/时间窗去重 | ≥ 90% |
| AI 研判攻击链与证据引用 | ≥ 4 / 5 |
| 关键幻觉 | 0 |
| 未审批高危响应成功执行 | 0 |
