:: ============================================================
:: Rayhunter Threat Analyzer — Full Forensic Run
:: Run from: C:\RH\rayhunter-threat-analyzer\
:: ============================================================

cd C:\RH\rayhunter-threat-analyzer

python main.py ^
  --dir C:\RH\rayhunter-threat-analyzer ^
  --output forensic_report_2026-06-09.json ^
  --html ^
  --manifest ^
  --timeline ^
  --verbose ^
  --mcc 505 ^
  --gps-lat -38.1100 ^
  --gps-lon 145.2780 ^
  --no-opencellid

:: Output files produced:
::   forensic_report_2026-06-09.json  — full machine-readable report
::   forensic_report_2026-06-09.html  — human-readable report (open in browser)
::   manifest_*.json + manifest_*.csv — SHA-256 file manifest
::   timeline_*.json                  — cross-session event timeline
::
:: Upload all four to a private Google Drive folder, then share the link
:: in the AFP Commonwealth crime form under "further information".
::
:: NOTE: --no-opencellid skips the external API call.
:: Remove that flag if you want cell geo-lookup (needs internet + API key).
