# 02 — 被测架构与数据流

> 对应 docx 第 4 节。本文档同时说明本仓库代码如何"挂载"在这条数据链路上。

## 数据流总览

```
              ┌──────────────────────┐
              │  被测主机 / 网关 / 应用  │
              │   (Linux, APISIX,    │
              │    Caddy, K8s, Agent) │
              └──────────┬───────────┘
                         │ 1) 日志采集
                         ▼
                  ┌────────────┐
                  │   Wazuh    │  decoder + rule
                  │  Manager   │──────┐
                  └──────┬─────┘      │ 2) alert
                         │            ▼
                         │      ┌──────────────┐
                         └─────►│ Wazuh Indexer│
                                │ (OpenSearch) │
                                └──────┬───────┘
                                       │ 3) custom-vigil / 直接查询
                                       ▼
                        ┌─────────────────────────┐
                        │  Vigil / DeepTempo      │
                        │  (人工智能创新平台 16001)│
                        │  ┌───────────────────┐  │
                        │  │ finding 聚合       │  │
                        │  │ case 生成          │  │
                        │  │ AI Orchestrator   │  │
                        │  │ (Triage / Invest. │  │
                        │  │  / Responder ...) │  │
                        │  │ 响应审批 + 执行    │  │
                        │  └───────────────────┘  │
                        └─────────────────────────┘
                                       │
                                       │ 4) 响应动作 (dry-run / approved)
                                       ▼
                            block_ip / isolate_host /
                            disable_account / notify
```

## 本仓库与数据流的对应关系

Web 控制台在测试套件上方增加独立控制面：

```text
浏览器 :17000 -> Nginx -> FastAPI -> SQLite（非敏感元数据）
                                  -> LocalRunner 串行队列
                                  -> pytest + 运行级 YAML(tmpfs)
                                  -> reports/<run_id>/
```

控制台与被测平台数据面隔离，不复用被测平台 Postgres。详细运行与凭据生命周期见 [09_test_console.md](09_test_console.md)。

| 数据流环节 | 本仓库代码 | 测试用例覆盖 |
|---|---|---|
| ① 日志采集 | `tests/common/ssh_runner.py` 在被测主机产生事件 | `SOC-TEL-001/004`、`SOC-ATT-*`（需 SSH 凭据） |
| ② Wazuh alert | `tests/common/wazuh_client.py` 查 Indexer 9200 | `SOC-TEL-006`、`SOC-ATT-004/017/019/022/024/031` |
| ③ finding / case | `tests/common/http_client.py` 调 `/api/findings/`、`/api/cases/` | `SOC-TEL-009`、`SOC-WF-003`、`PIPELINE-STEP-3/4` |
| ④ AI 研判 | `tests/common/ai_score.py` 拉 `/api/orchestrator/status`、`/api/reasoning/<sid>` | `SOC-WF-003`、`PIPELINE-STEP-5`、所有需要 AI 评分的用例 |
| ⑤ 响应闭环 | `tests/common/http_client.py` POST `/api/cases/.../respond` | `SOC-AI-029`、`SOC-WF-009`、`PIPELINE-STEP-6` |

## 关键 API（来源 ai_soc_pipeline_test.py 与平台探测）

| 端点 | 用途 | 用例引用 |
|---|---|---|
| `GET /` | 平台首页指纹 | pipeline step 1 |
| `GET /api/config/general` | 平台配置 | step 1、TEL-004 |
| `GET /api/config/integrations` | 集成状态（Wazuh 是否配置） | step 2、TEL-004 |
| `GET /api/findings/` | findings 列表 | TEL/ATT/WF 多数用例 |
| `POST /api/cases/` | 创建 case | TEL-009、WF-003、step 4 |
| `GET /api/orchestrator/status` | orchestrator 启用状态 | step 5、WF-003 |
| `GET /api/reasoning/<sid>` | 单个推理会话 | step 5、WF-003、AI-025 |
| `POST /api/cases/<id>/respond` | 响应动作（当前 404，但记录意图） | step 6、AI-029、WF-009 |
| `POST /api/integrations/vstrike/ui/iframe-token` | VStrike 集成探测 | step 5 |

## 六层证据来源（详见 04_evidence_model.md）

| 层 | 来自哪里 | 本仓库字段 |
|---|---|---|
| client | 测试发起端：命令、HTTP 请求参数、源 IP | `evidence.client[*]` |
| gateway | APISIX/Caddy access log、HTTP 响应头 | `evidence.gateway[*]` |
| application | 平台 API 返回体、orchestrator status、case detail | `evidence.application[*]` |
| wazuh | Wazuh decoder + rule + alert 文档 | `evidence.wazuh[*]` |
| vigil_ai | finding/case/reasoning 输出 | `evidence.vigil_ai[*]` |
| response | 响应动作请求与回执 | `evidence.response[*]` |
