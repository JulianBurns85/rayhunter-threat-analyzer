# Integration Guide — rayhunter-threat-analyzer v2.5
# Date: 2026-05-22
# This document tells you exactly what to do with every file.

---

## Step 1: Place Files

```powershell
# From your downloads, copy to these exact locations:

# Root level (alongside main.py)
Copy-Item advanced_forensics.py   C:\RH\rayhunter-threat-analyzer\
Copy-Item baseline_comparison.py  C:\RH\rayhunter-threat-analyzer\
Copy-Item bladerf_capture.py      C:\RH\rayhunter-threat-analyzer\
Copy-Item cipher_fix.py           C:\RH\rayhunter-threat-analyzer\

# Detectors
Copy-Item new_detectors.py        C:\RH\rayhunter-threat-analyzer\detectors\
Copy-Item extended_detectors.py   C:\RH\rayhunter-threat-analyzer\detectors\

# Intelligence DB
Copy-Item 06_marlin_imsi_exposing_messages.yaml  C:\RH\rayhunter-threat-analyzer\intelligence\db\attacks\
Copy-Item harris_flashcatch_profiles.yaml        C:\RH\rayhunter-threat-analyzer\intelligence\db\attackers\

# Evidence (local only, DO NOT push to GitHub)
Copy-Item forensic_analysis_22may2026.md   C:\RH\rayhunter-threat-analyzer\evidence\
Copy-Item AFP_evidence_supplement.md       C:\RH\rayhunter-threat-analyzer\evidence\
Copy-Item sha256_manifest.txt              C:\RH\rayhunter-threat-analyzer\evidence\
Copy-Item advanced_forensic_report.json    C:\RH\rayhunter-threat-analyzer\evidence\
```

---

## Step 2: Update .gitignore

Add these lines to `.gitignore` to keep sensitive evidence off GitHub:

```
# Evidence files (case-specific, not for public repo)
evidence/
advanced_forensic_report.json

# bladeRF capture data
captures/
baseline/
*.sc16q11
```

---

## Step 3: Fix Heuristic 4.1.6 in Your Existing Code

The critical fix. Open your `main.py` and find where YAICD heuristic 4.1.6 is evaluated.
It currently fires as CONFIRMED when cipher is unknown. Change it to:

### Option A: Quick Fix (modify the heuristic check)

Find the section in `main.py` that looks something like:
```python
# 4.1.6 EEA0 Null-Cipher Present
if eea0_detected or cipher_unknown:
    confirmed_heuristics.append('4.1.6')
```

Change to:
```python
# 4.1.6 EEA0 Null-Cipher Present
# FIXED 2026-05-22: Only confirm on ACTUAL EEA0, not unknown
if eea0_detected:  # Remove cipher_unknown condition
    confirmed_heuristics.append('4.1.6')
elif cipher_unknown:
    partial_heuristics.append('4.1.6')  # Partial, not confirmed
```

### Option B: Full Fix (use cipher_fix.py)

Import and use the new cipher parsing module:
```python
from cipher_fix import assess_cipher_status, corrected_heuristic_416

# After collecting PCAPNG paths:
h416_result = corrected_heuristic_416(pcapng_paths)
if h416_result['confirmed']:
    confirmed_heuristics.append('4.1.6')
elif h416_result['status'] == 'PARTIAL':
    partial_heuristics.append('4.1.6')
# If NOT_CONFIRMED, don't add it at all
```

### Also update the Finding [4] text

Find where Finding [4] is generated (likely in `cipher_downgrade.py` or `main.py`).
Change:
```
"No-auth → SMC combined with EEA0 is definitive IMSI catcher evidence."
```
To:
```
"Security Mode Command without prior Authentication. Observed cipher: EEA2/EIA2 (AES-128). 
Strong encryption without authentication is consistent with a MitM proxy (e.g., Harris 
HailStorm) that forwards authentication to the real network and derives session keys."
```

---

## Step 4: Wire New Detectors Into main.py

Add imports at the top of `main.py`:
```python
# New detectors (v2.5)
from detectors.new_detectors import (
    AuthenticationAbsenceDetector,
    MeasurementReportRateDetector,
    RRCReconfigurationPeriodicityDetector,
    extract_events_from_pcapng,
)
from detectors.extended_detectors import (
    FlashCatchDetector,
    CIDConsistencyDetector,
    CompositeEvidenceScorer,
)
```

Then in your analysis pipeline (after existing detectors run), add:
```python
# Run new detectors on PCAPs
if pcapng_files:
    for pcap_path in pcapng_files:
        events = extract_events_from_pcapng(pcap_path)
        if events:
            new_findings = run_new_detectors(events, pcap_path)
            all_findings.extend(new_findings)
```

---

## Step 5: Run cipher_fix.py Against Your Data

Before the AFP submission, run this to verify the cipher correction:

```powershell
cd C:\RH\rayhunter-threat-analyzer
python cipher_fix.py path\to\1656131.pcapng path\to\1254835__1_.pcapng path\to\1802369.pcapng
```

This will output:
- Actual EEA/EIA values for every SecurityModeCommand
- Corrected heuristic 4.1.6 assessment
- Corrected YAICD score (should go from 3.00 to 2.75 — still above 2.6 threshold)

---

## Step 6: Run Advanced Forensics

```powershell
cd C:\RH\rayhunter-threat-analyzer
python advanced_forensics.py path\to\1656131.pcapng path\to\1254835__1_.pcapng path\to\1802369.pcapng
```

This generates:
- FFT spectral analysis (210.4s dominant period, SNR 27.7x)
- Binomial p-value (10^-166)
- Autocorrelation scores
- SIB neighbor list analysis
- GUTI reallocation tracking
- Paging volume counts
- JSON report saved to `advanced_forensic_report.json`

---

## Step 7: Generate Fresh SHA-256 Manifest

On YOUR machine (not the Claude-generated one):

```powershell
cd C:\RH\rayhunter-threat-analyzer\evidence
Get-FileHash *.ndjson,*.pcapng,*.qmdl -Algorithm SHA256 | 
    Format-Table Hash, @{Name="File";Expression={Split-Path $_.Path -Leaf}} |
    Out-File sha256_manifest_final.txt
```

Or use your existing `dedup_and_hash.ps1` script.

---

## Step 8: Pre-Submission Checklist

Before copying to the AFP USB:

- [ ] Heuristic 4.1.6 corrected (no longer claims EEA0 when EEA2 observed)
- [ ] Finding [4] text updated to state actual cipher (EEA2/EIA2)
- [ ] YAICD score recalculated (2.75, still above 2.6 threshold)
- [ ] False positive disclosure included (5 withdrawn Identity Request findings)
- [ ] SHA-256 manifest generated on YOUR machine from YOUR files
- [ ] `cipher_fix.py` output included showing actual cipher parsing
- [ ] `advanced_forensic_report.json` included with FFT/p-value data
- [ ] AFP evidence supplement reviewed (device = TP-Link M7350, not Orbic)
- [ ] Evidence folder NOT pushed to GitHub
- [ ] Clean baseline capture done (when you do the drive)

---

## Step 9: GitHub Push (public tool updates only)

```powershell
cd C:\RH\rayhunter-threat-analyzer
git add detectors/new_detectors.py
git add detectors/extended_detectors.py
git add intelligence/db/attacks/06_marlin_imsi_exposing_messages.yaml
git add intelligence/db/attackers/harris_flashcatch_profiles.yaml
git add advanced_forensics.py
git add baseline_comparison.py
git add bladerf_capture.py
git add cipher_fix.py
git add .gitignore
git commit -m "v2.5: Add AuthAbsence, MeasReportRate, RRCReconfigPeriodicity, FlashCatch detectors; FFT/autocorrelation/p-value analysis; cipher parsing fix; Marlin taxonomy; bladeRF capture"
git push origin main
```

---

## File Inventory — Final Count

| # | File | Location | GitHub? |
|---|------|----------|---------|
| 1 | `cipher_fix.py` | root | Yes |
| 2 | `advanced_forensics.py` | root | Yes |
| 3 | `baseline_comparison.py` | root | Yes |
| 4 | `bladerf_capture.py` | root | Yes |
| 5 | `new_detectors.py` | `detectors/` | Yes |
| 6 | `extended_detectors.py` | `detectors/` | Yes |
| 7 | `06_marlin_imsi_exposing_messages.yaml` | `intelligence/db/attacks/` | Yes |
| 8 | `harris_flashcatch_profiles.yaml` | `intelligence/db/attackers/` | Yes |
| 9 | `forensic_analysis_22may2026.md` | `evidence/` | **NO** |
| 10 | `AFP_evidence_supplement.md` | `evidence/` | **NO** |
| 11 | `sha256_manifest.txt` | `evidence/` | **NO** |
| 12 | `advanced_forensic_report.json` | `evidence/` | **NO** |

8 files for GitHub, 4 files for evidence only.
