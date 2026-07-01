# 下一阶段计划：AI-SOC 测试套件

## 项目现状总结

### 已完成的规模
| 维度 | 现状 |
|---|---|
| 总测试函数 | **57 个** (6 pipeline + 20 P0 + 11 workflow + 20 HTTP-only) |
| 测试分类 | 覆盖 5 大类 + 1 个基线类 (TEL/ATT/AI_API/AI_SOCKET/WF/baseline) |
| 证据模型 | 六层证据链 (client/gateway/application/wazuh/vigil_ai/response) |
| 可观测性 | 8 类自动采集 (request_id/rule_id/alert_id/case-finding/approvals/rollback/SSE/auth) |
| AI 评分 | 7 维度评分 (detection/ATT&CK/evidence/chain/risk/false_positive/response/hallucination) |
| 报告产物 | 每次运行自动生成 `report.md` + `report.json` + `evidence/<case_id>.json` |
| xlsx 矩阵 | 100 条原始用例 → 已扩展至 114 条 (test_matrix.yaml) |

### 最新一轮测试结果 (2026-06-26 HTTP-only 子集)
- **14 PASS / 5 WARN / 1 FAIL / 0 SKIP**
- 1 FAIL: **SOC-AI-003** — 匿名可读取 `/api/reasoning/1` 完整会话数据 (真实 IDOR 漏洞)
- 5 WARN: CORS 缺 `Vary: Origin`、伪造 Bearer 错误消息 3 种、安全头 11/15、Server 暴露 nginx/1.24.0、攻击链证据仅 1 类技术

---

## 下一阶段建议 (按优先级排序)

### 优先级 1: 解决已知 FAIL (阻塞项)

**SOC-AI-003 修复验证**
- 现状: 匿名 GET `/api/reasoning/{1..3}` 返回完整 AI 会话内容 (含 token cost、interactions) — 这是真实的 broken authentication / IDOR
- 动作: 需要平台侧先加 user/session 校验，修复后重新跑用例，预期转 PASS
- 当前用例代码已把漏洞"钉死"，无需修改测试代码

### 优先级 2: P1/P2 用例扩展 (80 条未落地)

根据 xlsx 矩阵，还有约 **80 条 P1/P2/P3** 用例未落地。建议按分类分批推进：

| 分类 | 总用例 | 已落地 | 待落地 | 建议优先级 |
|---|---|---|---|---|
| TEL (遥测) | 10 | 4 | 6 | 中 |
| ATT (攻击) | 48 | 8 | 40 | 高 |
| AI/API (001~014) | 14 | 10 | 4 | 中 |
| AI/Socket (015~030) | 16 | 3 | 13 | 低 |
| WF (工作流) | 12 | 13 | 0 | 已完成 |

**建议优先落地 ATT 类的 P1 用例**，因为 MITRE ATT&CK 是测试方案的主线，目前 48 条中只落地了 8 条 (16.7%)，覆盖率偏低。优先选择：
- 只需 HTTP 触达的用例 (降低门槛，无需 SSH/Wazuh)
- 覆盖不同 MITRE 战术的用例 (如 T1059 命令执行、T1566 钓鱼、T1505 服务端脚本等)

### 优先级 3: CI 集成

README 中明确标注 "本轮未做: CI 集成"。建议：
- 添加 GitHub Actions workflow (`.github/workflows/test.yml`)，每次 push 自动跑 HTTP-only 子集
- 将报告产物作为 CI artifact 上传
- 设置 FAIL 时 CI 标红，WARN 时标黄 (可选)

### 优先级 4: 基础设施完善

1. **Allure HTML 报告**: `requirements.txt` 已包含 `pytest-html`，但未启用。可考虑切换到 Allure 获取更丰富的可视化报告
2. **真实恶意样本测试**: 当前 L3/L4 破坏性用例 (DoS/洪泛) 未做，这些需要更谨慎的测试环境
3. **测试数据隔离**: 部分用例会创建真实 case (如 WF-006、WF-010、WF-014)，当前依赖人工清理。可考虑自动清理机制

### 优先级 5: 代码质量

1. **测试用例模板标准化**: 当前 57 个测试函数风格基本一致，但部分用例缺少 `MITRE` 常量和 `pytestmark` 标记。可统一检查
2. **`credentials.yaml.example` 指令完善**: 补充更多凭据字段说明，降低新成员上手门槛
3. **`test_matrix.yaml` 与实际代码同步**: 当前 matrix 114 条，但实际落地 57 条。可考虑在 matrix 中增加 `implemented: true/false` 字段

---

## 建议的下一阶段执行顺序

| 步骤 | 内容 | 预计工作量 |
|---|---|---|
| 1 | 联系平台侧修复 SOC-AI-003 IDOR 漏洞，修复后验证 → PASS | 小 (等待平台) |
| 2 | 新增 10-15 条 ATT 类 P1 HTTP-only 用例 | 中 |
| 3 | 新增 GitHub Actions CI 流水线 (跑 HTTP-only 子集) | 小 |
| 4 | 在 test_matrix.yaml 中增加 `implemented` 字段，标记 57 条已落地用例 | 小 |
| 5 | 新增 5-10 条 TEL 类 P1 用例 | 中 |
| 6 | 新增 5 条 AI_API 类 P1 用例 | 中 |

---

## 关键决策点 (需要确认)

1. **P1 用例扩展方向**: 优先 ATT 攻击场景 (MITRE 覆盖) 还是优先 TEL 遥测链路？还是 HTTP-only 优先？
2. **CI 集成**: 是否需要 GitHub Actions？是否需要报告产物上传？
3. **破坏性用例**: L3/L4 (DoS/洪泛) 是否需要？如需，需要什么级别的测试环境？

---

## 不做的事 (明确排除)

- 不重构现有代码框架 (框架已稳定，57 个用例运行良好)
- 不修改 docs/ 下的 8 篇文档 (除非新增用例需要更新 08_p0_case_index.md)
- 不修改证据模型 (六层证据链 + 8 类可观测性已足够)
- 不修改 AI 评分模型 (7 维度已覆盖 docx 需求)