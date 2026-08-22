#!/usr/bin/env bash
# AutoSQLi 一键停止（Linux / macOS）
cd "$(dirname "$0")"

echo "[停止] 结束 AutoSQLi 相关进程..."
pkill -f "python.*-m autosqli\.gui" 2>/dev/null && echo "[OK] 已结束 GUI 进程"
pkill -f "python.*-m autosqli\.cli" 2>/dev/null && echo "[OK] 已结束 CLI 进程"
sleep 1
echo "[完成] 所有 AutoSQLi 进程已停止。"
