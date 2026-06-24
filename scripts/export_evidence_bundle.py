#!/usr/bin/env python3
"""把 reports/<run_id>/ 打包为 zip，便于上传/归档。

用法：
  python scripts/export_evidence_bundle.py [run_id]
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def main() -> int:
    if len(sys.argv) > 1:
        run_id = sys.argv[1]
    else:
        runs = sorted([p for p in REPORTS.iterdir() if p.is_dir() and p.name != ".gitkeep"],
                      key=lambda p: p.stat().st_mtime, reverse=True)
        if not runs:
            print("没有可打包的报告", file=sys.stderr)
            return 1
        run_id = runs[0].name
    src = REPORTS / run_id
    if not src.exists():
        print(f"目录不存在：{src}", file=sys.stderr)
        return 1
    out = REPORTS / f"{run_id}.zip"
    shutil.make_archive(str(out.with_suffix("")), "zip", src)
    print(f"已打包：{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
