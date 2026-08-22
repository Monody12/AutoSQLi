@echo off
cd /d "%~dp0"

echo ============================================
echo   AutoSQLi - Stop all related processes
echo ============================================
echo.

taskkill /FI "WINDOWTITLE eq AutoSQLi*" /T /F >nul 2>&1
if not errorlevel 1 echo [OK] AutoSQLi window processes terminated

powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*autosqli*' } | ForEach-Object { Write-Host ('[OK] Kill PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

echo.
echo [DONE] All AutoSQLi processes stopped.
ping -n 4 127.0.0.1 >nul
exit /b 0
