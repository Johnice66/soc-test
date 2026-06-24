"""
test_matrix.yaml 加载器
- 把 100 条用例元数据按 case_id 索引
- 为每个 test_ 函数提供 fixture 注入：mitre / priority / strength / expected_acceptance
"""
from __future__ import annotations

import os
from typing import Optional

import yaml


_CACHE: dict | None = None


def _load(path: str = "config/test_matrix.yaml") -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not os.path.exists(path):
        _CACHE = {"cases": {}}
        return _CACHE
    with open(path, "r", encoding="utf-8") as f:
        _CACHE = yaml.safe_load(f) or {"cases": {}}
    return _CACHE


def get_case(case_id: str) -> Optional[dict]:
    return _load()["cases"].get(case_id)


def list_cases(filter_p0: bool = False, category: str | None = None) -> list[dict]:
    out = []
    for cid, meta in _load()["cases"].items():
        if filter_p0 and meta.get("priority") != "P0":
            continue
        if category and meta.get("category") != category:
            continue
        out.append({"case_id": cid, **meta})
    return out
