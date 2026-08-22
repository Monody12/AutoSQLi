#!/usr/bin/env bash
# AutoSQLi CLI 快捷入口：./autosqli.sh -u "URL" --dump
cd "$(dirname "$0")"
if [ ! -x ".venv/bin/python" ]; then
    echo "[错误] 虚拟环境不存在，请先运行 start.sh 完成初始化"
    exit 1
fi
exec .venv/bin/python -m autosqli.cli "$@"
