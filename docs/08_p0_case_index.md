# 08 — P0 用例索引（20 条 + 第二批新增 8 条 workflow）

> 一站式查 20 条 P0 → 文件路径 → MITRE → 触达面 → 验收指标。

---

## 总览

| # | 用例 ID | 一级分类 | 场景 | MITRE | 触达面 | 文件 |
|---|---|---|---|---|---|---|
| 1 | SOC-TEL-001 | TEL | Linux SSH 认证日志采集 | N/A | HTTP | [tel/test_tel_001_linux_ssh_auth.py](../tests/tel/test_tel_001_linux_ssh_auth.py) |
| 2 | SOC-TEL-004 | TEL | 应用审计日志采集 | N/A | HTTP | [tel/test_tel_004_app_audit.py](../tests/tel/test_tel_004_app_audit.py) |
| 3 | SOC-TEL-006 | TEL | Wazuh 规则命中链路 | N/A | HTTP | [tel/test_tel_006_wazuh_rule_hit.py](../tests/tel/test_tel_006_wazuh_rule_hit.py) |
| 4 | SOC-TEL-009 | TEL | finding → case 生成 | N/A | HTTP | [tel/test_tel_009_finding_to_case.py](../tests/tel/test_tel_009_finding_to_case.py) |
| 5 | SOC-ATT-004 | ATT | SSH 密码猜测 | T1110.001 | SSH + Wazuh + HTTP | [attack/test_att_004_ssh_password_guess.py](../tests/attack/test_att_004_ssh_password_guess.py) |
| 6 | SOC-ATT-006 | ATT | 爆破后成功登录关联 | T1078 | SSH + Wazuh + HTTP | [attack/test_att_006_brute_then_success.py](../tests/attack/test_att_006_brute_then_success.py) |
| 7 | SOC-ATT-010 | ATT | 令牌重放访问 API | T1550.001 | HTTP | [attack/test_att_010_token_replay.py](../tests/attack/test_att_010_token_replay.py) |
| 8 | SOC-ATT-017 | ATT | 新增本地用户 | T1136 | SSH + Wazuh | [attack/test_att_017_add_local_user.py](../tests/attack/test_att_017_add_local_user.py) |
| 9 | SOC-ATT-019 | ATT | 创建/修改系统服务 | T1543 | SSH + Wazuh | [attack/test_att_019_create_service.py](../tests/attack/test_att_019_create_service.py) |
| 10 | SOC-ATT-022 | ATT | 异常提权尝试 | T1548 | SSH + Wazuh | [attack/test_att_022_privilege_escalation.py](../tests/attack/test_att_022_privilege_escalation.py) |
| 11 | SOC-ATT-024 | ATT | 删除日志文件尝试 | T1070 | SSH + Wazuh | [attack/test_att_024_log_deletion.py](../tests/attack/test_att_024_log_deletion.py) |
| 12 | SOC-ATT-031 | ATT | SSH 横向登录尝试 | T1021.004 | SSH + Wazuh | [attack/test_att_031_lateral_ssh.py](../tests/attack/test_att_031_lateral_ssh.py) |
| 13 | SOC-AI-001 | AI/API | 未认证 WebSocket Upgrade | T1190(部分) | HTTP/WS | [ai_api/test_ai_001_unauth_ws_upgrade.py](../tests/ai_api/test_ai_001_unauth_ws_upgrade.py) |
| 14 | SOC-AI-005 | AI/API | 伪造 X-User-* 可信头 | T1556(部分) | HTTP | [ai_api/test_ai_005_forged_trusted_header.py](../tests/ai_api/test_ai_005_forged_trusted_header.py) |
| 15 | SOC-AI-009 | AI/API | WebIDE 一次性 ticket 重放 | T1550.001(部分) | HTTP | [ai_api/test_ai_009_webide_ticket_replay.py](../tests/ai_api/test_ai_009_webide_ticket_replay.py) |
| 16 | SOC-AI-012 | AI/API | 登出后长连接未失效 | T1550.004(部分) | HTTP/SSE | [ai_api/test_ai_012_logout_keeps_stream.py](../tests/ai_api/test_ai_012_logout_keeps_stream.py) |
| 17 | SOC-AI-025 | AI/Socket | Prompt 注入诱导工具越权 | T1059(部分) | HTTP | [ai_socket/test_ais_025_prompt_injection.py](../tests/ai_socket/test_ais_025_prompt_injection.py) |
| 18 | SOC-AI-029 | AI/Socket | 高危工具调用审批缺失 | T1059(部分) | HTTP | [ai_socket/test_ais_029_high_risk_tool_approval.py](../tests/ai_socket/test_ais_029_high_risk_tool_approval.py) |
| 19 | SOC-WF-003 | WF | 攻击链 case 还原 | T1078 | HTTP（+ AI 评分） | [workflow/test_wf_003_attack_chain_case.py](../tests/workflow/test_wf_003_attack_chain_case.py) |
| 20 | SOC-WF-009 | WF | 自动响应 dry-run 审批 | N/A | HTTP | [workflow/test_wf_009_dry_run_approval.py](../tests/workflow/test_wf_009_dry_run_approval.py) |

---

## 第二批新增 workflow 用例（8 条）

| # | 用例 ID | 场景 | 触达 API | 关键断言 | 文件 |
|---|---|---|---|---|---|
| 21 | SOC-WF-001 | High 告警 → case 生成 | `/api/findings?severity=high` + `/api/cases` | case 与 finding 双向关联 | [workflow/test_wf_001_high_alert_to_case.py](../tests/workflow/test_wf_001_high_alert_to_case.py) |
| 22 | SOC-WF-002 | 多 alert 聚合为 finding | `/api/findings` 统计 | 聚合关键词或同源 IP 多 finding 二取一 | [workflow/test_wf_002_alert_aggregation.py](../tests/workflow/test_wf_002_alert_aggregation.py) |
| 23 | SOC-WF-005 | 管理员维护误报抑制 | `/api/cases` create+get | priority 不被升级到 High/Critical | [workflow/test_wf_005_admin_batch_ops.py](../tests/workflow/test_wf_005_admin_batch_ops.py) |
| 24 | SOC-WF-007 | AI 证据引用准确性 | `/api/reasoning/*` + case 详情 | 引用 finding_id 100% 真实存在 | [workflow/test_wf_007_ai_evidence_reference.py](../tests/workflow/test_wf_007_ai_evidence_reference.py) |
| 25 | SOC-WF-008 | AI 不确定性表达 | 同上 | thin-evidence 文本中含 ≥1 不确定词 | [workflow/test_wf_008_ai_uncertainty.py](../tests/workflow/test_wf_008_ai_uncertainty.py) |
| 26 | SOC-WF-010 | approve→execute→rollback | `/api/approvals/*/{approve,reject}` | 状态序列含 approved 与 rejected | [workflow/test_wf_010_response_execute_rollback.py](../tests/workflow/test_wf_010_response_execute_rollback.py) |
| 27 | SOC-WF-011 | 端到端 SLA 延迟 | findings/cases/approvals 列表 | 5 项 SLA 至少 4 项达标 | [workflow/test_wf_011_sla_e2e_latency.py](../tests/workflow/test_wf_011_sla_e2e_latency.py) |
| 28 | SOC-WF-012 | 缺陷复测与版本可追踪 | `/api/workflows` + findings.mitre | wf 元数据完整 + 已有 runs + mitre 可追踪 | [workflow/test_wf_012_regression_versioning.py](../tests/workflow/test_wf_012_regression_versioning.py) |

## 第二批"工具级"新增（3 条，框架内自定 ID）

| # | 用例 ID | 场景 | 触达 API | 关键断言 | 文件 |
|---|---|---|---|---|---|
| 29 | SOC-WF-013 | workflow 模板清单完整性 | `GET /api/workflows` | ≥3 个 wf，每个 ≥2 agents/5 tools，常见家族命中 | [workflow/test_wf_013_template_catalog.py](../tests/workflow/test_wf_013_template_catalog.py) |
| 30 | SOC-WF-014 | workflow run 触发与状态机 | `POST /api/workflows/{id}/run` | 触发后 runs +1，字段齐全，状态合法 | [workflow/test_wf_014_run_lifecycle.py](../tests/workflow/test_wf_014_run_lifecycle.py) |
| 31 | SOC-WF-015 | case → workflow 自动联动 | 创建 case 后 watch runs | 软断言（auto-link 缺失打 WARN） | [workflow/test_wf_015_case_to_workflow_link.py](../tests/workflow/test_wf_015_case_to_workflow_link.py) |

> WF-014 / WF-010 带 `destructive` mark：会在服务器侧实际生成 workflow run / 切换审批状态，但都被自动回收（reject 复位）。

---

## 加上 6 步 Pipeline 冒烟

| # | 用例 ID | 场景 | 文件 |
|---|---|---|---|
| P1 | PIPELINE-STEP-1 | Docker 管理面板探测 | [pipeline/test_e2e_pipeline.py](../tests/pipeline/test_e2e_pipeline.py)::test_step1_docker_panel_detection |
| P2 | PIPELINE-STEP-2 | Wazuh API 认证失败 | 同上::test_step2_wazuh_auth_failure |
| P3 | PIPELINE-STEP-3 | Wazuh 规则覆盖率 | 同上::test_step3_wazuh_rule_coverage |
| P4 | PIPELINE-STEP-4 | Case 生成 | 同上::test_step4_case_generation |
| P5 | PIPELINE-STEP-5 | AI 研判 | 同上::test_step5_ai_analysis |
| P6 | PIPELINE-STEP-6 | Dry-run 响应 | 同上::test_step6_dry_run_response |

合计：**37 个测试函数**（6 pipeline + 20 P0 首批 + 11 P0 workflow 新增）。

---

## 触达面统计

| 触达面 | 数量 | 用例 ID |
|---|---|---|
| HTTP-only | 13 | 6 pipeline + TEL-004/006/009 + ATT-010 + AI-001/005/009/012 + AIS-025/029 + WF-003/009 |
| 需 Wazuh | 1 | TEL-001（也用 HTTP 间接验证） |
| 需 SSH + Wazuh | 7 | ATT-004/006/017/019/022/024/031 |

> 无凭据时跑 `bash scripts/run_http_only.sh`，会跑 13 个 HTTP-only 用例。

---

## 验收阈值（与 [01_scheme_overview.md](01_scheme_overview.md) 一致）

- Critical/High 规则命中率：100%
- AI 评分 `total` 在 WF 类：≥ 4 / 5
- `hallucination_control`：≥ 3（任一用例 < 2 视为严重缺陷）
- `report.json.totals.FAIL` 必须为 0；WARN ≤ 4（首版基线）

---

## 加新用例如何做

1. 在对应目录新建 `test_<id>_<short>.py`
2. 顶部填：
   ```python
   CASE_ID = "SOC-XXX-NNN"
   MITRE = "TXXXX"   # 或 "N/A"
   pytestmark = [pytest.mark.pX, pytest.mark.<category>, pytest.mark.needs_ssh?, pytest.mark.needs_wazuh?]
   ```
3. 函数签名按需取 fixture（`target` / `wazuh` / `ssh_host` / `evidence_recorder` / `ai_scorer`）
4. 用 `rec.client/gateway/application/wazuh/vigil/response()` 写六层证据
5. 用 `rec.set_ai_score(score)` 写 AI 评分
6. `rec.finish("PASS|WARN|FAIL", message)` 收尾

文件模板可参考 [test_tel_009_finding_to_case.py](../tests/tel/test_tel_009_finding_to_case.py)（HTTP-only 最简版）或 [test_att_004_ssh_password_guess.py](../tests/attack/test_att_004_ssh_password_guess.py)（全链路版）。
