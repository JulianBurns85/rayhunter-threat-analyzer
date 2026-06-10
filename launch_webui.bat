@echo off
REM rayhunter-threat-analyzer Web UI launcher
REM Place this file in C:\RH\rayhunter-threat-analyzer\

set RTA_ROOT=C:\RH\rayhunter-threat-analyzer
set RTA_OUTPUT=C:\RH\MASTER\output

echo.
echo  rayhunter-threat-analyzer Web UI
echo  ===================================
echo  http://localhost:8080
echo.

pip install flask --quiet --break-system-packages 2>nul || pip install flask --quiet

python "%~dp0webui\app.py"
pause
