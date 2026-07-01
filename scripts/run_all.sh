#!/usr/bin/env bash
# 跑全部 P0 用例（pipeline + 20 条 P0），耗时 5-10 分钟（含 SSH/Wazuh 用例）
set -e
cd "$(dirname "$0")/.."
export NO_PROXY="*" no_proxy="*"
python3 -m pytest tests/ -v --tb=short -m "(p0 or pipeline) and not destructive" "$@"
LATEST=$(ls -t reports | head -1)
echo
echo "Report: reports/${LATEST}/report.md"
echo "Evidence: reports/${LATEST}/evidence/"
