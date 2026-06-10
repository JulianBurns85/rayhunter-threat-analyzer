#!/bin/bash
# ============================================================
# Run this on your machine inside the rayhunter-threat-analyzer
# directory to remove case-output files from the public repo.
#
# These files are NOT tool code — they're case-specific outputs
# and submissions that don't belong in a public repository.
# ============================================================

cd /path/to/rayhunter-threat-analyzer   # adjust this path

# Remove case-output files from tracking
git rm --cached AFP_MASTER_SUBMISSION_LEX4864.txt
git rm --cached afp_master_submission.py
git rm --cached exhibit_a_dossier.txt
git rm --cached exhibit_a_june.json
git rm --cached exhibit_a_june.txt
git rm --cached exhibit_a_subsecond.json
git rm --cached exhibit_a_subsecond.txt
git rm --cached exhibit_b_june.txt
git rm --cached exhibit_b_operator_profile.txt
git rm --cached exhibit_c_campaign_timeline.txt
git rm --cached exhibit_d_fresh.json
git rm --cached exhibit_d_fresh.txt
git rm --cached exhibit_e_fresh.json
git rm --cached exhibit_e_fresh.txt
git rm --cached exhibit_f_paging.json
git rm --cached exhibit_f_paging.txt
git rm --cached exhibit_g_crnti.json
git rm --cached exhibit_g_crnti.txt
git rm --cached exhibit_h_baseline.json
git rm --cached exhibit_h_baseline.txt
git rm --cached rsrp_castnet_report.txt
git rm --cached warrant_castnet_raw.txt
git rm --cached warrant_castnet_utf8.txt
git rm --cached warrant_dossier_ssd_raw.txt
git rm --cached warrant_may_raw.txt

# Also remove the archive folder (contains hello_mofo_banner_tight.png)
git rm -r --cached archive/

# Drop in the updated .gitignore (see repo_gitignore.txt)
cp repo_gitignore.txt .gitignore
git add .gitignore

# Commit
git commit -m "chore: remove case-output files from public repo

Exhibit files, warrant documents, AFP submission drafts, and
case-specific analysis outputs are not tool code. They have been
removed from version control. All such outputs should be stored
locally and shared via secure private channel only.

Tool code (detectors, parsers, intelligence YAML, main.py) is unaffected."

git push origin main
