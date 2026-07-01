from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import yaml


PRESETS = {
    "http_only": {"name": "HTTP 快速回归", "description": "不需要 SSH/Wazuh，排除破坏性用例"},
    "p0": {"name": "P0 核心用例", "description": "P0 与流水线，默认排除破坏性用例"},
    "pipeline": {"name": "端到端流水线", "description": "六步端到端冒烟测试"},
    "custom": {"name": "自定义用例", "description": "从已发现的用例中选择"},
}


def _strings(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def discover_cases(root: Path) -> list[dict[str, Any]]:
    deferred_path = root / "config/deferred_cases.yaml"
    deferred_raw = yaml.safe_load(deferred_path.read_text(encoding="utf-8")) if deferred_path.exists() else {}
    deferred = deferred_raw.get("cases", deferred_raw.get("deferred_cases", deferred_raw)) or {}
    deferred_ids = set(deferred if isinstance(deferred, dict) else [])
    cases: list[dict[str, Any]] = []
    for path in sorted((root / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        case_ids: list[str] = []
        markers: set[str] = set()
        functions = [n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
        for node in tree.body:
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if any(name.startswith("CASE_ID") for name in names):
                    case_ids.extend(v for v in _strings(node.value) if v.startswith(("SOC-", "PIPELINE-")))
                if "pytestmark" in names:
                    for attr in ast.walk(node.value):
                        if isinstance(attr, ast.Attribute) and isinstance(attr.value, ast.Attribute):
                            if isinstance(attr.value.value, ast.Name) and attr.value.value.id == "pytest":
                                markers.add(attr.attr)
        if not case_ids:
            continue
        rel = str(path.relative_to(root))
        for index, case_id in enumerate(case_ids):
            function = functions[min(index, len(functions) - 1)] if functions else path.stem
            cases.append({
                "case_id": case_id,
                "nodeid": f"{rel}::{function}" if functions else rel,
                "test_name": function,
                "markers": sorted(markers),
                "category": path.parent.name,
                "deferred": case_id in deferred_ids,
            })
    return cases
