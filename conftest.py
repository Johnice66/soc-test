"""
pytest 全局 fixture + session hook
"""
from __future__ import annotations

import os
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest
import yaml

# 让 tests/common 可 import
sys.path.insert(0, str(Path(__file__).parent))

# 测试目标是内网 IP，主动绕开系统代理，避免被 HTTP_PROXY 拦截
os.environ.setdefault("NO_PROXY", "*")
os.environ.setdefault("no_proxy", "*")

from tests.common.http_client import HTTPClient  # noqa: E402
from tests.common.wazuh_client import WazuhClient  # noqa: E402
from tests.common.ssh_runner import SSHRunner  # noqa: E402
from tests.common.evidence import EvidenceRecorder  # noqa: E402
from tests.common.ai_score import AIScorer  # noqa: E402

ROOT = Path(__file__).parent
CONFIG_DIR = ROOT / "config"


def _runtime_config_path() -> Path:
    configured = os.environ.get("SOC_TEST_RUN_CONFIG")
    return Path(configured).resolve() if configured else CONFIG_DIR / "target.yaml"


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------- session 级 ----------
@pytest.fixture(scope="session")
def target_cfg() -> dict:
    return _load_yaml(_runtime_config_path())


@pytest.fixture(scope="session")
def credentials() -> dict:
    """凭据。若 credentials.yaml 不存在，返回空 dict。"""
    runtime = _load_yaml(_runtime_config_path())
    if "credentials" in runtime:
        return runtime.get("credentials") or {}
    return _load_yaml(CONFIG_DIR / "credentials.yaml")


@pytest.fixture(scope="session")
def run_id() -> str:
    return os.environ.get("SOC_TEST_RUN_ID") or (
        datetime.utcnow().strftime("%Y%m%d-%H%M%S") + f"-{secrets.token_hex(2)}"
    )


@pytest.fixture(scope="session")
def run_dir(run_id: str, target_cfg: dict, pytestconfig) -> str:
    configured = os.environ.get("SOC_TEST_RUN_DIR")
    d = Path(configured).resolve() if configured else ROOT / "reports" / run_id
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    snapshot = {k: v for k, v in target_cfg.items() if k != "credentials"}
    (d / "run-config.snapshot.yaml").write_text(
        yaml.safe_dump(snapshot, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    pytestconfig._soc_run_dir = str(d)
    return str(d)


@pytest.fixture(scope="session")
def target(target_cfg, credentials) -> HTTPClient:
    return HTTPClient.from_config(target_cfg, credentials=credentials)


@pytest.fixture(scope="session")
def wazuh(credentials):
    """Wazuh 客户端。凭据未配置则 skip。"""
    api = credentials.get("wazuh_api") or {}
    idx = credentials.get("wazuh_indexer") or {}
    if not (api.get("enabled") or idx.get("enabled")):
        pytest.skip("wazuh_api/wazuh_indexer 凭据未配置")
    return WazuhClient(
        api_host=api.get("host", "") if api.get("enabled") else "",
        api_port=int(api.get("port", 55000)),
        api_user=api.get("username", ""),
        api_pass=api.get("password", ""),
        indexer_host=idx.get("host", "") if idx.get("enabled") else "",
        indexer_port=int(idx.get("port", 9200)),
        indexer_user=idx.get("username", ""),
        indexer_pass=idx.get("password", ""),
        verify_tls=bool(idx.get("verify_tls") or api.get("verify_tls")),
    )


@pytest.fixture(scope="session")
def ssh_host(credentials):
    """被测主机 SSH。凭据未配置则 skip。"""
    cfg = credentials.get("ssh_host") or {}
    if not cfg.get("enabled"):
        pytest.skip("ssh_host 凭据未配置（如只跑 HTTP-only 子集是正常的）")
    return SSHRunner(
        host=cfg["host"],
        port=int(cfg.get("port", 22)),
        username=cfg.get("username", ""),
        password=cfg.get("password", ""),
        private_key_path=cfg.get("private_key_path", ""),
        dry_run=bool(cfg.get("dry_run", False)),
    )


@pytest.fixture(scope="session")
def ai_scorer(target) -> AIScorer:
    return AIScorer(http_client=target)


# ---------- 用例级 ----------
@pytest.fixture()
def evidence_recorder(request, run_dir: str, run_id: str, target):
    """每个 test_ 函数自动获得一个 EvidenceRecorder；teardown 时自动附加 8 类可观测性信息。"""
    from tests.common.observability import attach_observability

    mod = request.module
    case_id = getattr(mod, "CASE_ID", request.node.name)
    mitre = getattr(mod, "MITRE", "N/A")
    rec = EvidenceRecorder(case_id=case_id, mitre=mitre, run_dir=run_dir, run_id=run_id)
    # 把当前用例的 HTTPClient 调用日志在 yield 前清空，使 request_ids 仅反映本用例
    try:
        target.call_log.clear()
        target.last_findings = []
        target.last_case_ids = []
    except Exception:
        pass
    yield rec
    # 用例若忘了 finish，先打个 WARN
    if rec.data.status == "RUNNING":
        rec.finish("WARN", "用例未显式 finish()，自动收尾")
    # 自动附加 8 类可观测性
    try:
        attach_observability(
            rec,
            target,
            findings=getattr(rec, "_hint_findings", None) or target.last_findings,
            case_ids=getattr(rec, "_hint_case_ids", None) or target.last_case_ids,
        )
        rec._write()  # 覆盖写入完整版
    except Exception as e:
        # 不影响用例 PASS/FAIL
        print(f"[obs warn] {case_id}: {e}", file=sys.stderr)


# ---------- session hook：自动生成报告 ----------
def pytest_sessionfinish(session, exitstatus):
    """所有用例跑完后，调用 scripts/generate_report.py 聚合证据。"""
    rd = getattr(session.config, "_soc_run_dir", None)
    try:
        from scripts.generate_report import generate, generate_for_latest
        if rd:
            generate(Path(rd))
        else:
            generate_for_latest(reports_root=str(ROOT / "reports"))
    except Exception as e:
        print(f"\n[warn] 报告生成失败: {e}", file=sys.stderr)
