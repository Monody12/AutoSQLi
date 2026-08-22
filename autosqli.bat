@echo off
cd /d "%~dp0"

rem AutoSQLi CLI entry: autosqli.bat -u "URL" --dump
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] venv missing. Run start.bat first.
    exit /b 1
)
".venv\Scripts\python.exe" -m autosqli.cli %*
