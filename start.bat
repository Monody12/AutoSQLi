@echo off
cd /d "%~dp0"

echo ============================================
echo   AutoSQLi - CTF SQLi Automation Tool
echo ============================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [INIT] First run: creating venv and installing deps...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] venv creation failed. Need Python 3.11+
        pause
        exit /b 1
    )
    ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Dependency install failed. Check network.
        pause
        exit /b 1
    )
    echo [INIT] Done.
    echo.
)

echo [START] Launching GUI in a new window...
echo   Close GUI window directly, or run stop.bat
echo   CLI mode: autosqli.bat -u "URL" --dump
echo.

start "AutoSQLi" cmd /k ".venv\Scripts\python.exe -m autosqli.gui"
exit /b 0
