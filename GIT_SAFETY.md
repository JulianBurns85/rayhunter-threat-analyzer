# Not pushing the whole folder — git safety for rayhunter-threat-analyzer

Your repo root holds code AND case material (captures, reports, KMLs, bug
reports, CASTNET history, the subject address). .gitignore alone is not enough,
because:
  - it only stops UNTRACKED files; anything already committed stays tracked.
  - `git add -A` can still stage a renamed/forced file.
So: ignore rules + a verify-before-push habit.

## 1. Append the ignore rules
Append `gitignore_additions.txt` to your existing `.gitignore`. In PowerShell:
```powershell
cd C:\RH\rayhunter-threat-analyzer
Get-Content gitignore_additions.txt | Add-Content .gitignore
```

## 2. Check whether anything sensitive is ALREADY tracked
The .json/.kml/.qmdl in your dir listing (rayhunter_report_*.json,
rayhunter_forensic_map_*.kml) may already be committed from earlier. Find out:
```powershell
git ls-files | Select-String -Pattern "\.qmdl$|\.pcapng$|\.ndjson$|\.kml$|rayhunter_report_|bugreport-|castnet_|exhibit|submission"
```
Anything it lists is TRACKED and ignoring it now does nothing. Untrack (keeps
the file on disk, removes from git):
```powershell
git rm --cached "rayhunter_report_1781185827.json"
git rm --cached "rayhunter_forensic_map_1781185825.kml"
# ...repeat for each, or untrack a whole folder:
git rm --cached -r evidence output archive
```
Then commit the removal:
```powershell
git commit -m "Stop tracking capture/report/evidence artifacts"
```
NOTE: this removes them from FUTURE commits, not from HISTORY. If a real IMSI/
address already went to a public remote in a past commit, that's a history-
rewrite job (git filter-repo / BFG) — tell me and I'll walk it through.

## 3. Safe-commit habit (use instead of `git add -A`)
Stage explicitly, never blanket:
```powershell
git add main.py reconcile.py cell_identity.py corpus_guard.py config.yaml
git status                      # READ the list before committing
git commit -m "..."
```
Pre-push paranoia check — dry-run what a push would send:
```powershell
git diff --cached --name-only   # exactly what's staged
```

## 4. Optional hard stop: pre-commit hook that blocks sensitive files
Create `.git\hooks\pre-commit` (no extension), make it block known patterns:
```bash
#!/bin/sh
# Abort commit if a sensitive artifact is staged.
BLOCK='\.qmdl$|\.pcapng$|\.ndjson$|\.kml$|rayhunter_report_|bugreport-|castnet_.*\.(csv|json)$|exhibit|submission|warrant'
staged=$(git diff --cached --name-only | grep -E "$BLOCK")
if [ -n "$staged" ]; then
  echo "COMMIT BLOCKED — sensitive files staged:"
  echo "$staged"
  echo "Unstage them: git restore --staged <file>"
  exit 1
fi
```
This fires even on `git add -A` — the safety net for the exact accident you're
worried about.

## 5. Best structural fix (when you have time)
Split the repo: keep code in C:\RH\rayhunter-threat-analyzer (git), move all
captures/reports/evidence to a SEPARATE non-git tree, e.g.
C:\RH\CASE_DATA\  (never `git init`'d). Point --dir and output_dir there.
Code and evidence then physically can't be in the same git tree.
That also lines up with output_dir = "C:/RH/reports and maps" being OUTSIDE
the repo root — which, conveniently, the path you picked already is. Good call.
