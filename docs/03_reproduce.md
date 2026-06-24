# 03 — 复现 SOP（下次完整跑一遍）

> 任何不熟悉本项目的同事，按本 SOP 走 7 步，**最终产物**：和上次结构一致的 `reports/<run_id>/report.md` + JSON 证据包。

---

## 步骤 0 — 前置条件

| 条件 | 检查命令 |
|---|---|
| Python ≥ 3.9 | `python3 --version` |
| 能访问目标平台 | `curl -fsS http://192.168.1.193:16003/ \| head -c 200` |
| （可选）能 SSH 到被测主机 | `ssh -o ConnectTimeout=3 <ssh_user>@192.168.1.193 'true'` |
| （可选）能访问 Wazuh Indexer | `curl -sk -u admin:<pass> https://192.168.1.193:9200/_cat/health` |

> **没有 SSH/Wazuh 凭据也能跑** — 用例会自动 `SKIP` 对应项，HTTP-only 子集仍可走完整链路。

---

## 步骤 1 — 装依赖

```bash
cd /Users/johnice/Desktop/nw/security/soc-test
pip3 install -r requirements.txt
```

预期输出：`Successfully installed pytest pytest-html requests pyyaml ...`

---

## 步骤 2 — 准备配置

```bash
# 凭据文件（如只跑 HTTP-only 可完全跳过）
cp config/credentials.yaml.example config/credentials.yaml
$EDITOR config/credentials.yaml
```

要填的最常用三段：

- `wazuh_indexer.enabled: true` + `host/port/username/password`
- `ssh_host.enabled: true` + `host/username/password 或 private_key_path`
- `ssh_host.dry_run: false` — 设 `true` 时 SSH 命令只记录不执行（首次跑建议开 dry-run）

> 矩阵文件 `config/test_matrix.yaml` 来自 xlsx，**已生成好**。若 xlsx 有更新，重跑：`python3 scripts/xlsx_to_yaml.py`

---

## 步骤 3 — 冒烟（6 步 pipeline，~30 秒）

```bash
bash scripts/run_pipeline_only.sh
```

预期：`6 passed`，产出 `reports/<时间戳>/report.md`。

冒烟过则证明：
- HTTP 客户端可通（绕过系统代理）
- `/api/findings/`、`/api/cases/`、`/api/orchestrator/status` 三个核心 API 可达
- EvidenceRecorder 写出 JSON、generate_report 聚合 Markdown 正常

---

## 步骤 4 — 跑 HTTP-only 子集（~30 秒）

无凭据情况下，先跑这一档：

```bash
bash scripts/run_http_only.sh
```

预期：约 13 个用例 PASS / WARN，0 FAIL（WARN 通常出现在 SOC-AI-009/012/ATT-010，说明平台目前的某些端点鉴权状态需人工复核）。

---

## 步骤 5 — 跑完整 P0（需要 SSH + Wazuh 凭据）

```bash
bash scripts/run_all.sh
```

预期：约 26 个用例（pipeline 6 + P0 20），≥ 80% PASS。需要 SSH 的 7 条 ATT 用例会真的去被测主机执行命令并查 Wazuh Indexer。

只跑某一类：

```bash
python3 -m pytest tests/ -v -m "p0 and att"          # 仅 P0 + 攻击场景
python3 -m pytest tests/attack/test_att_004_*.py -v   # 单条用例
python3 -m pytest tests/ -v -m "p0 and not needs_ssh" # P0 中不需 SSH 的
```

---

## 步骤 6 — 看报告

```bash
LATEST=$(ls -t reports | head -1)
open reports/${LATEST}/report.md            # 总报告
ls reports/${LATEST}/evidence/              # 每条用例的 JSON 证据
```

**报告字段对照**（详见 [04_evidence_model.md](04_evidence_model.md)）：
- `用例总览` 表 — 一眼扫到 PASS/WARN/FAIL/AI 评分
- `逐条用例详情` — 每条用例的六层证据 + 断言
- `report.json` — 机器可读，可导给后续 BI / 缺陷管理系统

---

## 步骤 7 — 打包证据 / 失败排查

```bash
# 打包整份证据为 zip 给 PM / 缺陷系统
python3 scripts/export_evidence_bundle.py
# 输出：reports/<run_id>.zip
```

常见失败排查：

| 现象 | 原因 | 处理 |
|---|---|---|
| 所有 HTTP 请求 timeout | 系统代理拦截 | 已在 conftest 自动设 NO_PROXY；若仍失败，手动 `export NO_PROXY='*'` |
| `wazuh fixture skipped` | credentials.yaml 中 `wazuh_indexer.enabled=false` | 填好后改 true |
| `ssh_host fixture skipped` | credentials.yaml 中 `ssh_host.enabled=false` | 同上 |
| `Wazuh API 认证失败` | 凭据/端口错误 | `curl -sk -u user:pass https://host:55000/security/user/authenticate -X POST` 单独验证 |
| `paramiko AuthenticationException` | SSH 密码/密钥错误 | `ssh -v user@host` 单独验证 |
| `requests.exceptions.SSLError` | Wazuh 自签证书 | credentials.yaml 中 `verify_tls: false`（默认） |
| Wazuh 查不到 alerts | 时间窗口不够 / agent 没上线 | 拉长 `since_seconds`、查 Wazuh agent 状态 |

---

## 复现验收标准

每次跑完，需要满足：

- [x] `reports/<run_id>/report.md` 生成
- [x] 至少 16/20 P0 用例 PASS（其余 SKIP 或 WARN，不允许框架层 FAIL）
- [x] `report.json` 中 `totals.FAIL == 0`
- [x] 重新跑一次（同样的凭据/网络），结构与 PASS 数一致（除时间戳和 Wazuh 实时数据外）

如果哪一项不满足，按 **步骤 7** 排查表定位。
