# 09 — SOC 测试控制台

## 模块用途

测试控制台为本仓库增加多环境 Web 操作入口。授权用户可以保存不同目标的非敏感连接参数，临时输入本次运行凭据，选择测试范围，观察 pytest 日志并读取证据报告。

控制台是独立控制面，不与 `../docker-compose.yml` 中的被测平台数据库或服务共用状态。当前只实现单机 `LocalRunner`，每次只运行一个任务；后续远程 Runner 可以复用现有运行模型和 API。

## 组成与依赖

| 模块 | 主要文件 | 职责 |
|---|---|---|
| React 前端 | `console_frontend/src/` | 登录、环境、用例、运行、报告和用户管理 |
| FastAPI 控制器 | `console_backend/app.py` | REST API、RBAC、CSRF、连接探测和报告下载 |
| SQLite 存储 | `console_backend/db.py` | 用户、会话、环境、运行元数据和审计日志 |
| 本地 Runner | `console_backend/runner.py` | 串行队列、pytest 子进程、取消和临时凭据销毁 |
| 用例目录 | `console_backend/catalog.py` | 从测试源码发现用例 ID、pytest marker 和精确 nodeid |
| 独立部署 | `docker-compose.console.yml` | Nginx 前端、内部 API、持久卷和凭据 `tmpfs` |

后端依赖见 `requirements-console.txt`，前端依赖锁定在 `console_frontend/package-lock.json`。

## Docker 启动

```bash
cp .env.console.example .env.console
# 必须修改 SOC_CONSOLE_ADMIN_PASSWORD
$EDITOR .env.console

docker compose --env-file .env.console -f docker-compose.console.yml up -d --build
```

打开 `http://<控制台主机>:17000/`。API 仅在 Compose 内网监听，由 Nginx 代理 `/api/`，不单独暴露宿主机端口。

如果 Docker Hub、PyPI 或 npm 官方源访问不稳定，可在 `.env.console` 中覆盖基础镜像和依赖源：

```dotenv
SOC_CONSOLE_PYTHON_IMAGE=内部仓库/python:3.12-slim
SOC_CONSOLE_NODE_IMAGE=内部仓库/node:22-alpine
SOC_CONSOLE_NGINX_IMAGE=内部仓库/nginx:1.27-alpine
SOC_CONSOLE_PIP_INDEX_URL=https://内部-PyPI/simple
SOC_CONSOLE_NPM_REGISTRY=https://内部-npm
```

未设置这些变量时仍使用 Dockerfile 中的官方默认值。依赖安装配置了有限重试和超时，首次构建完成后 Docker 会复用依赖层缓存。

停止服务：

```bash
docker compose --env-file .env.console -f docker-compose.console.yml down
```

`console_data` 保存 SQLite；测试报告写入仓库 `reports/`。删除 volume 会清除控制台账号、环境和运行索引，但不会删除绑定目录中的报告。

## 本地开发

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-console.txt

SOC_CONSOLE_ADMIN_PASSWORD='至少十二位的开发密码' \
  .venv/bin/uvicorn console_backend.app:app --host 127.0.0.1 --port 17001

cd console_frontend
npm install
npm run dev
```

Vite 开发地址为 `http://127.0.0.1:17000/`，`/api` 自动代理到 `17001`。

## 运行与数据流

1. 操作员选择环境、预设和临时凭据，前端调用 `POST /api/runs`。
2. API 只把环境快照、用例范围和状态写入 SQLite；凭据保留在 Runner 内存。
3. Runner 在 `tmpfs` 创建权限为 `0600` 的运行配置，通过 `SOC_TEST_RUN_CONFIG`、`SOC_TEST_RUN_ID` 和 `SOC_TEST_RUN_DIR` 注入 pytest。
4. `conftest.py` 写出不含 `credentials` 的 `run-config.snapshot.yaml`，每条证据进入本次独立目录。
5. Runner 逐行过滤已知秘密后写 `run.log`，SSE 接口向浏览器推送日志与状态。
6. pytest 结束后，报告从本次环境快照读取目标地址；临时配置、SSH 私钥和内存凭据立即销毁。

控制器重启后，原 `queued/running` 任务会标记为 `failed`，原因是临时凭据按设计不可恢复。用户需重新输入凭据并启动新任务。

## 权限与安全边界

| 角色 | 权限 |
|---|---|
| `admin` | 用户管理、环境管理、普通测试、破坏性测试、审计日志 |
| `operator` | 环境管理、普通测试、取消任务、查看报告 |
| `viewer` | 查看环境、用例、运行和报告 |

- 会话 Cookie 为 `HttpOnly + SameSite=Strict`，所有变更接口同时校验 CSRF Cookie/Header。
- 生产环境应通过 HTTPS 反向代理访问，并设置 `SOC_CONSOLE_SECURE_COOKIE=true`。
- 破坏性测试仅管理员可启用，必须关闭 Dry Run 并输入完整环境名称确认。
- API 不接受任意 pytest 参数；预设由服务端定义，自定义运行只接受目录中已发现的用例 ID。
- 环境记录禁止包含 URL 凭据；密码、Token、Cookie 和私钥不会进入 SQLite、审计详情或运行快照。
- “检测连接”只探测已保存的 Base URL `/api/health` 和固定 SSH/Wazuh 主机端口，不接受任意探测路径。

## API 与状态

主要接口包括 `/api/auth/*`、`/api/users`、`/api/environments`、`/api/test-cases`、`/api/test-presets`、`/api/runs` 和 `/api/audit-events`。

运行状态固定为：

```text
queued -> running -> completed | failed | cancelled
```

`completed` 只表示 pytest 进程正常完成。业务测试是否存在 WARN/FAIL 必须读取 `report.json.totals`，前端会分别展示任务状态与报告统计。

## 验证

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest console_tests -q
cd console_frontend && npm run build
SOC_CONSOLE_ADMIN_PASSWORD=placeholder docker compose -f docker-compose.console.yml config --quiet
```

`console_tests/` 当前 11 条，覆盖环境 CRUD、RBAC、CSRF、登录限速、临时凭据全产物扫描、任务取消与重启恢复、破坏性确认、路径逃逸、精确用例选择和多环境报告隔离。

2026-07-01 完成实际 Docker 部署验证：API 和前端镜像构建成功，`api` 健康检查通过，Nginx `17000` 入口可登录；创建环境后重启 Compose，登录会话和环境记录仍存在；从容器探测 `http://192.168.1.193:16001` 成功，并执行 `SOC-MATRIX-001` 得到 1 PASS。报告写入 `reports/20260701-082421-5486/`，运行快照不含凭据，任务结束后 `/run/soc-console` 无临时文件残留。
