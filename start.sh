#!/usr/bin/env bash
# AutoSQLi 一键启动（Linux / macOS）
cd "$(dirname "$0")"

echo "============================================"
echo "  AutoSQLi - CTF SQL 注入自动化分析平台"
echo "============================================"

# 首次运行：自动创建虚拟环境并安装依赖
if [ ! -x ".venv/bin/python" ]; then
    echo "[初始化] 首次运行，正在创建虚拟环境..."
    python3 -m venv .venv || { echo "[错误] 无法创建虚拟环境（需要 Python 3.11+）"; exit 1; }
    echo "[初始化] 正在安装依赖..."
    .venv/bin/python -m pip install --quiet -r requirements.txt \
        || { echo "[错误] 依赖安装失败"; exit 1; }
fi

echo "[启动] 图形界面（关闭：直接关窗口，或运行 stop.sh）"
echo "[提示] 命令行模式：./autosqli.sh -u \"目标URL\" --dump"
exec .venv/bin/python -m autosqli.gui
