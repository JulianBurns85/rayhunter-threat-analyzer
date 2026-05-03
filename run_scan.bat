@echo off
chcp 65001 > NUL
cd /d C:\rayhunter-threat-analyzer-main
if not exist "reports" mkdir reports

for /f "tokens=1-6 delims=/: " %%a in ("%date% %time%") do (
    set YY=%%a
    set MM=%%b
    set DD=%%c
    set HH=%%d
    set MIN=%%e
)
set TIMESTAMP=%YY%-%MM%-%DD%_%HH%-%MIN%
set REPORT=reports\scan_%TIMESTAMP%.txt
set JREPORT=reports\scan_%TIMESTAMP%.json

echo ============================================================
echo  RAYHUNTER THREAT ANALYZER v2.0
echo  Report: %REPORT%
echo ============================================================
echo.

set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python main.py --dir C:\ray_staged_full --verbose --output "%JREPORT%" 2>&1 | PowerShell -Command "$input | Tee-Object -FilePath '%REPORT%'"

echo.
echo ============================================================
echo  Text report: %REPORT%
echo  JSON report: %JREPORT%
echo ============================================================
pause
