# AI-SOC 测试套件

针对 **人工智能创新平台 (AI-SOC)** http://192.168.1.193:16001 的工程化、可复现的安全测试套件。

把 docx 总方案与 xlsx 用例矩阵中的 100 条用例，**用代码钉住**：每次执行都自动生成同样结构的证据包与报告，任何同事拉下代码、装好依赖、填好凭据，就能复现出和上一次一样的报告。

---

## 是什么

- **测试方法论**：MITRE ATT&CK 主线 + SOC 闭环 + AI/Agent 运行时安全（三层模型，详见 [docs/01_scheme_overview.md](docs/01_scheme_overview.md)）
- **用例规模**：100 条总用例（来源 xlsx，本仓库已扩展到 114 条）；本仓库现有 **59 个测试函数**，Excel P0 已实现 32 条，另有 22 条因测试条件不足明确暂缓（详见 [docs/08_p0_case_index.md](docs/08_p0_case_index.md)）
- **运行框架**：pytest + 自定义 EvidenceRecorder（六层证据链）+ AIScorer（七维度评分）
- **产物**：每次运行在 `reports/<时间戳>/` 下生成 `report.md`、`report.json` 和 `evidence/<用例ID>.json`
- **Web 控制台**：支持多环境配置、临时凭据、一键测试、实时日志、RBAC 与历史报告，详见 [docs/09_test_console.md](docs/09_test_console.md)

---

## 5 分钟跑起来

```bash
# 1. 装依赖
pip3 install -r requirements.txt

# 2.（可选）填凭据 —— HTTP-only 子集可跳过
cp config/credentials.yaml.example config/credentials.yaml
$EDITOR config/credentials.yaml

# 3. 冒烟（6 步 pipeline，~30 秒，只需 HTTP）
bash scripts/run_pipeline_only.sh

# 4. 完整 P0（pipeline + 20 条 P0）
bash scripts/run_all.sh

# 5. 看报告
open reports/$(ls -t reports | head -1)/report.md
```

更详细的步骤、排错、证据上传，看 **[docs/03_reproduce.md](docs/03_reproduce.md)**。

### Web 控制台

```bash
cp .env.console.example .env.console
$EDITOR .env.console  # 设置初始管理员密码
docker compose --env-file .env.console -f docker-compose.console.yml up -d --build
```

浏览器访问 `http://<控制台主机>:17000/`。控制台使用独立 Compose，不修改被测环境的 `docker-compose.yml`。

---

## 目录速查

```
soc-test/
├── README.md                # 本文件
├── requirements.txt         # Python 依赖
├── pytest.ini               # pytest 配置 + marker
├── conftest.py              # 全局 fixture（target / wazuh / ssh_host / evidence_recorder）
├── console_backend/         # FastAPI、SQLite、RBAC 与串行 Runner
├── console_frontend/        # React + TypeScript + Vite 运维工作台
├── console_tests/           # 控制台 API、隔离与安全边界测试
├── docker-compose.console.yml
│
├── config/
│   ├── target.yaml          # 目标平台 URL 与超时
│   ├── credentials.yaml     # 凭据（gitignore；首次需 cp .example 再编辑）
│   └── test_matrix.yaml     # 100 条用例的结构化矩阵（由 xlsx 转出）
│
├── docs/                    # 8 篇文档（速览、原理、复现 SOP）
│
├── tests/
│   ├── common/              # http_client / wazuh_client / ssh_runner / evidence / ai_score / matrix_loader
│   ├── pipeline/            # 6 步 e2e 冒烟（迁移自 ai_soc_pipeline_test.py）
│   ├── tel/                 # SOC-TEL-* （4 条 P0）
│   ├── attack/              # SOC-ATT-* （8 条 P0，MITRE 主线）
│   ├── ai_api/              # SOC-AI-001~014 （4 条 P0）
│   ├── ai_socket/           # SOC-AI-015~030 （2 条 P0）
│   └── workflow/            # SOC-WF-* （首批 2 + 新增 11 共 13 条 P0）
│
├── scripts/
│   ├── run_pipeline_only.sh  # 冒烟
│   ├── run_all.sh            # P0 全集
│   ├── run_http_only.sh      # 仅 HTTP-only 子集（无 SSH/Wazuh 凭据时跑）
│   ├── xlsx_to_yaml.py       # 一次性：xlsx → test_matrix.yaml
│   ├── generate_report.py    # 由 pytest hook 自动调用，也可独立运行
│   └── export_evidence_bundle.py
│
└── reports/                  # 每次运行生成 reports/<run_id>/
```

---

## 重要文档

| 主题 | 文件 |
|---|---|
| 方案速览（三层模型 + 五大类） | [docs/01_scheme_overview.md](docs/01_scheme_overview.md) |
| 架构与数据流 | [docs/02_architecture.md](docs/02_architecture.md) |
| **复现 SOP（重点）** | [docs/03_reproduce.md](docs/03_reproduce.md) |
| **证据链 6 层模型原理** | [docs/04_evidence_model.md](docs/04_evidence_model.md) |
| **AI 研判 7 维度评分原理** | [docs/05_ai_judgement_scoring.md](docs/05_ai_judgement_scoring.md) |
| **MITRE 映射原理** | [docs/06_mitre_mapping.md](docs/06_mitre_mapping.md) |
| 五大类测试边界 | [docs/07_test_categories.md](docs/07_test_categories.md) |
| 本轮 20 条 P0 索引 | [docs/08_p0_case_index.md](docs/08_p0_case_index.md) |
| **Web 测试控制台部署与原理** | [docs/09_test_console.md](docs/09_test_console.md) |

---

## 配套源资料（保留不动）

- `AI-SOC测试方案_MITRE_ATTCK映射版_Wazuh_Vigil.docx` — v2.0 总方案
- `AI-SOC测试点与测试用例矩阵_MITRE_ATTCK映射版.xlsx` — 100 条用例矩阵
- `AI-3.0安全Socket测试完整报告-初版.docx` — 旧版报告
- `ai_soc_pipeline_test.py` / `ai_soc_pipeline_report.md` — 初版脚本与报告（已被 `tests/pipeline/test_e2e_pipeline.py` 替代）

---

## 范围与限制

**已落地**：
- 6 步 e2e + 20 条首批 P0（覆盖 5 大类 / 12 个 MITRE 技术 / HTTP·Wazuh·SSH 三个触达面）
- 第二批 workflow 强化：8 条对应 WF-001/002/005/007/008/010/011/012 + 3 条针对真实 `/api/workflows` 端点的工具级 WF-013/014/015
- 8 类可观测性自动采集（request_id / rule_id / alert_id / case⇄finding / 审批 / 回滚 / SSE / token 鉴权）

**本轮未做**：P1/P2/P3 共 80 条、L3/L4 破坏性用例（DoS/洪泛）、CI 集成、Allure HTML、真实恶意样本

---

## 更新日志

### 2026-07-01（Docker 部署链路验证）
- 更新内容：完成测试控制台的实际 Docker Compose 构建、启动、重启与最小任务验证；Dockerfile 和 Compose 增加可选基础镜像、PyPI、npm 源覆盖，并为依赖安装增加有限重试和超时，官方源仍为默认值。
- 影响范围：`Dockerfile.console-api`、`console_frontend/Dockerfile`、`docker-compose.console.yml`、`.env.console.example`、`docs/09_test_console.md`。
- 验证结果：`api` 容器健康、前端 `17000` 可登录；重启后 SQLite 中的环境和会话保持；容器内探测 `http://192.168.1.193:16001` 返回 200；运行 `SOC-MATRIX-001` 为 **1 PASS / 0 FAIL**，报告见 `reports/20260701-082421-5486/`；运行快照不含凭据，`tmpfs` 无任务临时文件残留。
- 备注：本机首次构建使用已有基础镜像和已验证的国内依赖源覆盖，解决 Docker Hub/npm/PyPI 链路间歇 EOF、ECONNRESET 和下载缓慢问题；生产部署应替换为组织内部可信镜像仓库和软件源。

### 2026-06-30（Web 测试控制台）
- 更新内容：新增 React/FastAPI 测试控制台，支持多环境非敏感配置、本地账号 RBAC、CSRF、防登录爆破、串行测试队列、运行取消、SSE 日志、报告与证据包下载；pytest 改为运行级配置和报告目录隔离，临时凭据仅存在于内存和 `tmpfs`。
- 影响范围：`console_backend/`、`console_frontend/`、`console_tests/`、`conftest.py`、`scripts/generate_report.py`、独立 Compose 与控制台文档。
- 验证结果：控制台测试 **11 passed**；前端 TypeScript/Vite 生产构建通过；Compose 配置解析通过；浏览器端完成登录→创建环境→执行 `SOC-MATRIX-001`→查看报告，并验证 1280px/390px 布局无页面级溢出和控制台错误。真实 HTTP-only 回归首次因目标服务中途间歇超时为 44 passed / 5 failed，随后只重跑这 5 条为 **5 passed**；完整证据报告为 **34 PASS / 14 WARN / 1 FAIL**，见 `reports/20260630-072828-ec4c/report.md`。
- 备注：首版为单机 `LocalRunner` 串行执行；控制器重启会使未完成任务失败，因为临时凭据按设计不持久化。Docker Compose 镜像构建两次均在 Docker Hub 拉取 `node:22-alpine` 元数据时 TLS/EOF 失败，本地前后端构建和 Compose 解析不受影响。

### 2026-06-29（第四次更新：P0 覆盖治理与证据完整性）
- 更新内容：目标切换为用户确认的 `16001`；补齐 `SOC-TEL-010`，证据 JSON 落盘时统一递归脱敏并生成 SHA-256 sidecar；新增 P0 矩阵覆盖守卫，将当前缺少执行条件的 22 条 P0 显式登记；默认运行脚本排除 `destructive`。
- 影响范围：`config/target.yaml`、`config/deferred_cases.yaml`、`tests/common/evidence.py`、`tests/tel/test_tel_010_evidence_integrity.py`、`tests/baseline/test_matrix_p0_coverage.py`、`scripts/run_all.sh`、`scripts/run_http_only.sh`、相关中文文档。
- 验证结果：`bash scripts/run_http_only.sh` 在 `16001` 上收集 49 条，pytest 为 **49 passed / 10 deselected / 0 failed**；证据报告为 **38 PASS / 10 WARN / 1 FAIL**，FAIL 为 `SOC-AI-003` 匿名可读 reasoning 会话；49 份证据 JSON 的 SHA-256 sidecar 全部校验一致，伪造敏感值扫描为 0。报告见 `reports/20260629-111737/report.md`。
- 备注：暂缓用例不创建空壳测试，避免以大量 SKIP 掩盖真实实现进度；满足登记的前置条件后再实现并从暂缓清单移除。

### 2026-06-26（第二次更新：HTTP-only 第三批 20 条）
- 更新内容：新增 20 条 HTTP-only 用例（全程无需 SSH/Wazuh 凭据，0 SKIP）：
  - 平台基线 11 条：`SOC-WEB-001~004`（安全响应头 / 方法白名单 / Server 暴露 / CSRF cookie 属性）、`SOC-AUTH-001~002`（登录限流 / 伪造 Bearer 响应一致性）、`SOC-API-001~005`（findings / cases / health / orchestrator / 错误 envelope 契约）
  - 真实 xlsx ID 9 条：`SOC-AI-002/003/006/008/011/014/024`、`SOC-WF-004/006`（SSE 暴露 / reasoning IDOR / X-Workspace-Id 越权 / CSRF 刷新登出 / WebIDE ticket 探测 / CORS 凭据组合 / Agent 敏感数据扫描 / 攻击链还原 / 误报抑制）
  - HTTPClient 新增 `raw_request`（带响应头返回，可用于断言安全头/状态码）
- 影响范围：`tests/baseline/`（新目录 11 文件）、`tests/ai_api/`（新增 6 文件）、`tests/ai_socket/`（新增 1 文件）、`tests/workflow/`（新增 2 文件）、`tests/common/http_client.py`、`config/test_matrix.yaml`（total 103→114）、`pytest.ini`（新增 `baseline` marker）、`docs/08_p0_case_index.md`、本 README。
- 验证结果：参见 `reports/20260626-092144/report.md` —— **14 PASS / 5 WARN / 1 FAIL / 0 SKIP**。
  - **FAIL 1 条**：`SOC-AI-003` IDOR —— 匿名 GET `/api/reasoning/1` 返回完整会话内容（含 token cost、interactions），需平台加 user/session 校验。
  - **WARN 5 条**：CORS 缺 `Vary: Origin`；伪造 Bearer 错误消息 3 种（弱用户枚举风险）；安全响应头 11/15；`Server: nginx/1.24.0 (Ubuntu)` 暴露；攻击链证据仅 1 类技术（initial_access）。
- 备注：`SOC-WF-006` 标 `destructive`（会在平台创建一个低风险 case，title 含 `[WF-006 TEST]` 便于事后清理）。

### 2026-06-26
- 更新内容：代码首次推送至 GitHub 仓库 [Johnice66/soc-test](https://github.com/Johnice66/soc-test)（默认分支 `main`，commit `b046ff7`，共 76 个文件）。`.gitignore` 增加 `.claude/`；`config/credentials.yaml`、`reports/`、虚拟环境与缓存均已排除。
- 影响范围：`.gitignore`、远程仓库初始化（未修改任何业务代码）。
- 验证结果：`gh repo view Johnice66/soc-test` 可见；`git diff --cached --name-only | grep -iE 'cred|password|secret|\.env|token'` 无真实凭据泄漏（仅 `credentials.yaml.example` 占位符）。
- 备注：commit Author/Committer 均为 `Johnice66 <weicong.liang68@gmail.com>`，使用 `git -c user.name=... -c user.email=...` 单次覆盖，未修改全局 git config。如 GitHub 用户页未把 commit 归属到 Johnice66 账号，需在 https://github.com/settings/emails 验证该邮箱；commit 末尾 `Co-Authored-By: Claude` 会令 contributors 列表出现 Claude，可按需移除后 force-push。

### 2026-06-23
- 更新内容：在 26 个测试基础上新增 11 条 workflow 用例（WF-001/002/005/007/008/010/011/012/013/014/015），HTTPClient 增加 `list_workflows / get_workflow / list_workflow_runs / get_workflow_run / trigger_workflow_run`。`test_matrix.yaml` 同步追加 WF-013/014/015。
- 影响范围：`tests/workflow/`、`tests/common/http_client.py`、`config/test_matrix.yaml`、`docs/08_p0_case_index.md`、本 README。
- 验证结果：参见 `reports/<最新>/report.md`。
- 备注：WF-014 / WF-010 标 `destructive` —— 会触发真实 workflow run 和真实 approval 状态切换，但都被自动回收。

### 2026-06-23（上一轮）
- 更新内容：可观测性 8 类自动附加；EvidenceRecorder 新增 `observability` 字段；conftest fixture teardown 自动 attach。
- 影响范围：`tests/common/observability.py`（新）、`evidence.py`、`http_client.py`、`conftest.py`、`scripts/generate_report.py`。
- 验证结果：26 用例 19 PASS / 7 SKIP / 0 FAIL。

授权约束：所有攻击模拟仅在授权测试环境/预生产环境执行；详见 docx 第 1 节"内部使用"说明与 [docs/07_test_categories.md](docs/07_test_categories.md) 停止条件。
