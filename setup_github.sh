#!/usr/bin/env bash
# ============================================================
# Rayhunter Threat Analyzer — GitHub publish setup script
# Run this ONCE from inside C:\rayhunter-threat-analyzer-V2.1.4
# ============================================================

echo "=== Rayhunter Threat Analyzer — GitHub Setup ==="
echo ""

# Files to EXCLUDE from the repo
EXCLUDE=(
  "fix_qmdl_decode_frame.py"
  "fix_qmdl_offsets.py"
  "fix_qmdl_timestamp.py"
  "main_patches.py"
  "patch_add_html_report.py"
  "patch_gui_v2.py"
  "python_check_cells.py"
  "reporter_v2_additions.py"
  "gui_py.bak_v2"
  "main_py.bak_html"
  "diagnose.py"
  "check_cells.py"
  "db_engine.py"
)

# Evidence/output files to exclude
EVIDENCE_PATTERNS=(
  "*.ndjson"
  "*.qmdl"
  "*.pcap"
  "*.pcapng"
  "rayhunter_report_*.json"
  "rayhunter_manifest_*.csv"
  "rayhunter_manifest_*.json"
  "Forensic_Manifest.csv"
  "all_capture_files.csv"
  "*.txt"
  "SESSION_SUMMARY*"
  "clean_scan_output*"
  "full_scan_output*"
  "Ray_tool_2_0_report*"
)

echo "Step 1: Initialize git repo"
git init
git branch -M main

echo ""
echo "Step 2: Configure git identity"
git config user.name "Julian Burns"
git config user.email "your-email@example.com"   # UPDATE THIS

echo ""
echo "Step 3: Stage core files only"
git add main.py
git add reporter.py
git add config.yaml
git add config_loader.py
git add requirements.txt
git add README.md
git add CHANGELOG.md
git add INSTALL.md
git add .gitignore
git add __init__.py

# Parsers
git add ndjson_parser.py pcap_parser.py qmdl_parser.py

# Detectors
git add base.py identity_harvest.py cipher_downgrade.py
git add rogue_tower.py rrc_periodicity.py handover_inject.py
git add paging_anomaly.py paging_cycle.py earfcn_anomaly.py
git add proximity_track.py earfcn.py

# Analysis
git add hardware_fingerprint.py timeline_correlator.py
git add cell_db.py known_patterns.py manifest_generator.py
git add report_differ.py watcher.py pcap_exporter.py

# Reporters
git add html_reporter.py html_reporter_v2.py

# Intelligence YAML
git add attacker_profiles.yaml behavioral_signatures.yaml
git add cipher_downgrade.yaml identity_request.yaml
git add attach_reject.yaml lau_tau_rau_reject.yaml
git add rogue_tower.yaml opensource_sdr.yaml commercial_le.yaml
git add *.yaml 2>/dev/null || true

# Test
git add test_synthetic.py
git add run_scan.bat

echo ""
echo "Step 4: Commit"
git commit -m "Initial release: Rayhunter Threat Analyzer v2.1.4

Forensic IMSI catcher detection and analysis tool built on Rayhunter captures.

Key features:
- 8 attack detectors (identity harvest, cipher downgrade, rogue tower, 
  RRC periodicity, handover injection, paging anomaly, EARFCN anomaly,
  proximity tracking)
- Hardware fingerprinting (srsRAN, Harris, PKI, Septier, Cobham profiles)
- Original finding: 210.2s srsRAN metronomic cycle fingerprint confirmed
  across 4 independent evidence streams including raw pcapng (210.217s)
- Multi-format: NDJSON + PCAP/PCAPNG + QMDL (Qualcomm DIAG)
- HTML forensic reports with SHA-256 chain-of-custody manifests
- 40M+ events processed in production use
- Australian regulatory framework (ACMA, Radiocommunications Act 1992)

Discovered during 10-month IMSI catcher investigation,
Cranbourne East, Victoria, Australia, 2026.

Co-developed with Claude (Anthropic)."

echo ""
echo "Step 5: Add remote and push"
echo "  Run these two commands manually:"
echo ""
echo "  git remote add origin https://github.com/julianburnz/rayhunter-threat-analyzer.git"
echo "  git push -u origin main"
echo ""
echo "=== Done! ==="
