# AI-SOC 测试套件

针对 **人工智能创新平台 (AI-SOC)** http://192.168.1.193:16003 的工程化、可复现的安全测试套件。

把 docx 总方案与 xlsx 用例矩阵中的 100 条用例，**用代码钉住**：每次执行都自动生成同样结构的证据包与报告，任何同事拉下代码、装好依赖、填好凭据，就能复现出和上一次一样的报告。

---

## 是什么

- **测试方法论**：MITRE ATT&CK 主线 + SOC 闭环 + AI/Agent 运行时安全（三层模型，详见 [docs/01_scheme_overview.md](docs/01_scheme_overview.md)）
- **用例规模**：100 条总用例（来源 xlsx，本仓库已扩展到 103 条）；本仓库**已落地** 6 步 e2e pipeline + **20 条首批 P0** + **11 条 workflow 新增** = **37 个测试函数**（详见 [docs/08_p0_case_index.md](docs/08_p0_case_index.md)）
- **运行框架**：pytest + 自定义 EvidenceRecorder（六层证据链）+ AIScorer（七维度评分）
- **产物**：每次运行在 `reports/<时间戳>/` 下生成 `report.md`、`report.json` 和 `evidence/<用例ID>.json`

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

---

## 目录速查

```
soc-test/
├── README.md                # 本文件
├── requirements.txt         # Python 依赖
├── pytest.ini               # pytest 配置 + marker
├── conftest.py              # 全局 fixture（target / wazuh / ssh_host / evidence_recorder）
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
