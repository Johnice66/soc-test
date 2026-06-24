# 06 — MITRE ATT&CK 映射原理（原理文档）

> 对应 docx 第 5、7 节 + xlsx "MITRE覆盖统计" sheet。回答两个问题：(1) 为什么不是所有用例都强行映射 ATT&CK；(2) 本仓库 20 条用例覆盖了哪些战术/技术。

---

## 映射类型：三档

docx 第 7 节明确写："不要为了'覆盖 ATT&CK'而强行映射所有用例。ATT&CK 描述的是攻击者行为，SOC 产品工程链路和 AI 运行时安全控制不能完全由 ATT&CK 表达。"

因此本方案的用例**映射方式分三档**：

| 档位 | 标志 | 含义 | 评价方式 |
|---|---|---|---|
| MITRE 主线用例 | `mitre_mainline: 是` | 直接映射到 ATT&CK 战术/技术 | 检测率、攻击链还原、响应闭环 |
| 部分映射用例 | `mitre_mainline: 部分映射` | 映射到最接近的技术，同时保留 `soc_domain` | 安全控制是否有效、AI 解释是否谨慎 |
| SOC 流程验证用例 | `mitre_mainline: 否`（`tech_id: N/A`） | 不强行映射 ATT&CK | 链路完整性、证据质量、SLA |

举例：

| 用例 ID | 场景 | 档位 | 理由 |
|---|---|---|---|
| `SOC-ATT-004` | SSH 密码猜测 | 主线 → `T1110.001` | 经典 Credential Access 战术 |
| `SOC-AI-009` | WebIDE 一次性 ticket 重放 | 部分映射 → `T1550.001` | ATT&CK 用 token 重放近似，但 WebIDE ticket 是平台特有 |
| `SOC-AI-025` | Prompt 注入诱导工具越权 | 部分映射 → `T1059` | 命令脚本执行最接近，但 prompt injection 不是 ATT&CK 一级技术 |
| `SOC-TEL-001` | Linux SSH 认证日志采集 | 流程验证（`N/A`） | 这是采集链路验证，不是攻击行为 |
| `SOC-WF-003` | 攻击链 case 还原 | 主线 → `T1078`（攻击行为部分） | 用 Valid Accounts 作为攻击链终点 |

---

## 本仓库 20 条用例的 MITRE 覆盖

按战术分组：

| 战术 (Tactic) | 已覆盖技术 | 用例 |
|---|---|---|
| Reconnaissance / Initial Access | T1190 | SOC-AI-001 |
| Credential Access | T1110.001 | SOC-ATT-004 |
| Initial Access (Valid Accounts) | T1078 | SOC-ATT-006、SOC-WF-003 |
| Defense Evasion | T1070、T1556 | SOC-ATT-024、SOC-AI-005 |
| Persistence | T1136、T1543 | SOC-ATT-017、SOC-ATT-019 |
| Privilege Escalation | T1548 | SOC-ATT-022 |
| Lateral Movement | T1021.004、T1550.001、T1550.004 | SOC-ATT-031、SOC-ATT-010、SOC-AI-009、SOC-AI-012 |
| Execution | T1059 | SOC-AI-025、SOC-AI-029 |
| SOC 流程（无 ATT&CK 映射） | N/A | TEL ×4、SOC-WF-009 |

合计：覆盖 **8 个战术**、**11 个技术**（含子技术）。

---

## 完整覆盖统计（xlsx 全 100 条）

> 来源：xlsx "MITRE 覆盖统计" sheet。完整 100 条用例的覆盖更广，本仓库本轮只是子集。

| 战术 | 覆盖技术数 | 用例数 | 代表技术 |
|---|---|---|---|
| Collection | 3 | 5 | T1005、T1552、T1560 |
| Command and Control | 3 | 3 | T1071、T1071.001 |
| Credential Access | 7 | 7 | T1003、T1110.001、T1110.003 |
| Defense Evasion | 3 | 4 | T1070、T1556、T1562 |
| Discovery | ≥4 | ≥4 | T1046、T1057、T1087、T1016 |
| Execution | ≥2 | ≥2 | T1059、T1059.001、T1059.004 |
| Exfiltration | 2 | 2 | T1567、T1041 |
| Impact | ≥3 | ≥3 | T1485、T1486、T1499.* |
| Initial Access | 2 | 2 | T1078、T1190 |
| Lateral Movement | ≥3 | ≥3 | T1021、T1021.004、T1550.* |
| Persistence | ≥3 | ≥3 | T1098、T1136、T1543、T1547、T1053 |
| Privilege Escalation | 1 | 1 | T1548 |
| Reconnaissance | 1 | 1 | T1595 |

---

## 为什么 `SOC-AI-*` 大量是"部分映射"

AI/Agent/Socket 这一层的风险，本质是"被保护对象本身是 AI 平台"时出现的新风险面：

- **长连接会话收敛**（登出后 WebSocket 是否断开）—— ATT&CK 没有"长连接会话权限收敛"这个技术
- **Prompt 注入**—— 攻击者面是 LLM 上下文，最近映射只能到 T1059（脚本执行）
- **WebIDE 一次性 ticket**—— 类似 token 滥用 T1550.001，但 ticket 时效是平台特性，不是 ATT&CK 描述的对象

所以 `SOC-AI-*` 用 `mitre_mainline: 部分映射` 的标签是工程上诚实的选择。

---

## 不要做什么

docx 明确禁止的事：

1. 不要为了"覆盖率好看"，把流程验证用例硬塞 ATT&CK 标签
2. 不要把同一个攻击行为映射到 5 个战术只为分数高
3. 不要在 AI 研判输出里幻觉出 ATT&CK 标签（`hallucination_control` 维度专门防这个）

本仓库的 `config/test_matrix.yaml` 严格保留了 `tech_id` 与 `mitre_mainline` 两个字段，任何用例的归类都来自 xlsx 而非自动推断。
