#!/usr/bin/env bash
# 跑 6 步 e2e pipeline 冒烟测试（约 30 秒）
set -e
cd "$(dirname "$0")/.."
export NO_PROXY="*" no_proxy="*"
python3 -m pytest tests/pipeline/ -v --tb=short "$@"
LATEST=$(ls -t reports | head -1)
echo
echo "Report: reports/${LATEST}/report.md"
