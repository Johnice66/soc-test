#!/usr/bin/env bash
# 跑 HTTP-only 子集（不需要 SSH/Wazuh 凭据），用于快速回归
set -e
cd "$(dirname "$0")/.."
export NO_PROXY="*" no_proxy="*"
python3 -m pytest tests/ -v --tb=short -m "not needs_ssh and not needs_wazuh" "$@"
LATEST=$(ls -t reports | head -1)
echo
echo "Report: reports/${LATEST}/report.md"
