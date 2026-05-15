![Hello Mofo](assets/hello_mofo_banner_tight.png)

> *Hello Mofo - Ray Hunter Threat Analyzer v2.4*

# Rayhunter Threat Analyzer
> **Forensic-grade IMSI catcher detection and analysis for Rayhunter cellular captures.**
> Built by Julian Burns — Cranbourne East, Victoria, Australia — 2024–2026

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows/Linux/macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com)
[![Hello Mofo](https://img.shields.io/badge/attacker_profile-HELLO%20MOFO%20CONFIRMED-red)](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

---

## What Is This?

This is a **post-processing forensic analysis layer** for [Rayhunter](https://github.com/EFForg/rayhunter) — the EFF's open-source IMSI catcher detector.

Where Rayhunter detects and flags suspicious events in real time, the **Rayhunter Threat Analyzer** takes those raw captures (NDJSON, PCAP/PCAPNG, QMDL) and performs deep forensic analysis:

- Correlates events across multiple capture sessions and networks
- Identifies **hardware fingerprints** (Harris HailStorm/StingRay II, PKI, Septier, Cobham, srsRAN)
- Detects behavioral attack patterns over time, not just single events
- Produces forensic reports with SHA-256 chain-of-custody manifests
- Maps findings to 3GPP specifications and Australian/international law
- Scores captures against named attacker profiles including the **Hello Mofo** Cranbourne East operator profile

This tool was built during a **16-month real-world IMSI catcher investigation** in suburban Melbourne, Australia — processing captures across dual Rayhunter units monitoring Telstra (505-01) and Vodafone AU (505-03) simultaneously.

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/JulianBurns85/rayhunter-threat-analyzer.git
cd rayhunter-threat-analyzer

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install tshark (for PCAP support)
# Ubuntu/Debian:
sudo apt install tshark
# macOS:
brew install wireshark
# Windows: install Wireshark from https://wireshark.org

# 4. Optional: install pySCAT for full QMDL NAS dissection
pip install git+https://github.com/fgsect/scat.git

# 5. Full YAICD-scored forensic analysis
python main.py --dir /path/to/rayhunter/output

# 6. Deep forensic analysis with all features
python rayhunter_deep_analysis.py --dir /path/to/captures --days --output --acma
```

---

## Two Analysis Tools

### 1. `main.py` — YAICD Forensic Scorer
Full 10-heuristic IMSI catcher detection with YAICD scoring (Ziayi et al. 2021), hardware fingerprinting, and HTML report generation.

```bash
python main.py --dir C:\captures --manifest --html --output report.json
```

### 2. `rayhunter_deep_analysis.py` — Deep Forensic Analysis v2.4 (Hello Mofo Edition)
Standalone companion script with 19 analysis features. No dependencies beyond Python stdlib.

```bash
# Standard run
python rayhunter_deep_analysis.py --dir C:\captures

# Full run with timeline, saved report, and ACMA draft
python rayhunter_deep_analysis.py --dir C:\captures --days --output --acma

# Compare two capture batches
python rayhunter_deep_analysis.py --dir C:\new_captures --compare C:\old_captures

# Generate ACMA evidence update draft only
python rayhunter_deep_analysis.py --dir C:\captures --acma
```

**Features:**
| # | Feature | Flag |
|---|---------|------|
| 1 | SHA-256 evidence manifest (auto-saved) | always |
| 2 | Capture gap detection | always |
| 3 | Cell ID inventory with confirmed rogue database | always |
| 4 | Geographic distance from subject premises | always |
| 5 | Sequential CID pattern detection (same hardware indicator) | always |
| 6 | New CID alerting with OpenCelliD URLs | always |
| 7 | Hello Mofo / Harris attacker profile scoring | always |
| 8 | Transmitter movement corridor analysis | always |
| 9 | Cross-carrier simultaneous release detection (YAICD P10) | always |
| 10 | RRC periodicity analysis (Harris T3/T1 signature) | always |
| 11 | Signal strength tracking (RSRP/RSSI) | always |
| 12 | Encryption rate per file (transparent proxy indicator) | always |
| 13 | Identity request detection (IMSI/IMEI/IMEISV) | always |
| 14 | EEA0 / Security Mode detection | always |
| 15 | OpenCelliD lookup URLs for all CIDs | always |
| 16 | Day-by-day timeline with known event correlation | --days |
| 17 | Save full report to timestamped text file | --output |
| 18 | Cross-batch comparison (new/disappeared/changed CIDs) | --compare |
| 19 | Pre-formatted ACMA evidence update draft | --acma |

---

## Key Confirmed Findings — Cranbourne East Investigation

### Primary Hardware Profile: Harris Commercial IMSI Catcher

Two Harris commercial IMSI catcher devices confirmed operational at a neighbouring Cranbourne East property. All findings below are tshark-verified from raw PCAPNG binary unless noted.

| Parameter | Telstra Device (505-01) | Vodafone Device (505-03) |
|-----------|------------------------|--------------------------|
| T3 release cycle | 210.212s ±0.139s | 40.553s ±0.327s |
| T3 sample count | 333+ events, 13 sessions | 27 intervals |
| T1 hold timer | 610.6s ±0.55s (shared) | 610.6s ±0.55s (shared) |
| UEInfo harvesting | Zero | 100% correlation, 46× baseline |
| EEA0 null cipher | Zero | Zero |
| Rayhunter alerts | Zero | Zero |

**Zero null cipher events and zero Rayhunter alerts are expected** — Harris Transparent Proxy mode maintains legitimate-appearing encryption while intercepting traffic. Standard detection tools produce no alerts against this operational mode. Timing analysis and Cell ID anomaly detection are the primary reliable detection vectors.

### Hello Mofo Attacker Profile — Score 11.0 / Threshold 8.0

The `rayhunter_deep_analysis.py` tool includes a named attacker profile for the confirmed Cranbourne East operator:

```
Profile:  Hello Mofo (Cranbourne East Persistent Operator)
Hardware: Harris HailStorm / StingRay II
Score:    11.0
Verdict:  *** HELLO MOFO CONFIRMED ***

Evidence flags:
  [+] Confirmed rogue CIDs present: 8
  [+] CIDs in suspect TAC clusters: 13
  [+] Multi-carrier simultaneous operation confirmed (Telstra + Vodafone)
  [+] Cross-carrier simultaneous events: 54
  [+] Sequential CID pattern detected: 15 pairs
  [+] CIDs geo-located within 500m of subject premises: 1
```

### Confirmed Rogue Cell IDs (active as of 16 May 2026)

**Telstra AU (MCC=505 MNC=001, TAC=12385):**
`137713155` · `137713165` · `137713175` · `137713195` · `135836171` · `135836191`

**Vodafone AU (MCC=505 MNC=003, TAC=30336):**
`8409357` · `8409367` · `8409387` · `8409397` · `8435480` · `8666381` · `8666391` · `8666411`

CIDs 8666381, 8666391, 8666411 appeared immediately after the ACMA field inspection on 8 May 2026 — consistent with post-visit device reconfiguration.

### OpenCelliD Geographic Corroboration

Independent crowd-sourced verification of transmitter location:

| CID | Location | Distance from Home | Updated |
|-----|----------|-------------------|---------|
| 137713175 | **Prendergast Avenue, CE** | **331m** | Apr 24 2026 |
| 135836191 | Collison Road, CE | 912m | Oct 2025 |
| 135836171 | Casey Fields area | 2,424m | Aug 2025 |

Movement corridor: Casey Fields (Aug 2025) → Collison Road (Oct 2025) → Prendergast Avenue (Apr 2026). Consistent with a mobile or repositioned unit progressively closing on subject premises over 8 months.

### Cross-Carrier Simultaneous Operation

Zero-second simultaneous RRCConnectionRelease across Telstra and Vodafone confirmed (April 8, 2026 15:38:08 UTC). This is architecturally impossible on srsRAN or any single-carrier platform. Harris StingRay II/HailStorm hardware with independent Harpoon power amplifiers per carrier is the only commercial platform consistent with this signature.

### T1 Hold Timer — Shared Harris Signature

T1 = 610.6s ±0.55s confirmed across five independent macro connection events on both carriers (PCAPNG burst analysis, 9 May 2026). Machine-precision shared parameter = both devices managed by a single Harris RayFish Controller.

### Three-Phase Operational Timeline

| Phase | Period | T3 Timer | Interpretation |
|-------|--------|----------|----------------|
| Phase 1 | Dec 2024 – Jan 22, 2026 | 3000.4s ±0.35s | Passive survey / baseline mode |
| Phase 2 | Jan 28 – May 7, 2026 | 210.2s (Telstra) / 40.5s (Vodafone) | Active harvest mode |
| Phase 3 | May 8, 2026 onwards | Chaotic — T1 unchanged at 610.6s | Post-ACMA visit reconfiguration |

**Regulatory complaints on file:** ACMA ENQ-1851DVJH04 · TIO 2026-03-04898 · VicPol CIRS-20260331-141 · VicPol CIRS-20260413-6 · Telstra Ref 128653446 (confirmed unauthorised Cel-Fi G51)

---

## Detectors

| Detector | What It Finds | 3GPP Reference |
|----------|---------------|----------------|
| `IdentityHarvestDetector` | IMSI/IMEI/IMEISV Identity Request floods | TS 24.301 §5.4.4 |
| `CipherDowngradeDetector` | EEA0+EIA0 null-cipher in SecurityModeCommand context | TS 33.401 §5.1.3.2 |
| `RogueTowerDetector` | Rogue Cell IDs with per-carrier MNC attribution | TS 36.331 |
| `RRCPeriodicityDetector` | Metronomic T3 and T1 timer analysis | TS 36.331 §5.3.8 |
| `HandoverInjectDetector` | Suspicious handover command sequences | TS 36.331 §5.4 |
| `PagingAnomalyDetector` | Abnormal paging patterns and IMSI exposure | TS 24.301 §5.6.2 |
| `EARFCNAnomalyDetector` | Suspicious EARFCN/frequency band usage | TS 36.101 |
| `HardwareFingerprinter` | Device classification by behavioral profile | — |

---

## Hardware Fingerprints

| Device | Key Indicators | Score Modifiers |
|--------|---------------|-----------------|
| **Harris HailStorm / StingRay II** | Cross-carrier simultaneous release, T1=610.6s, UEInfo-r9, Auth Reject | +0.40 cross-carrier, +0.30 T1 |
| **Harris KingFish** | UEInfo-r9 harvesting, Auth Reject chains | +0.15 UEInfo |
| **PKI 1625** | Catch-and-release, Band 28, multi-carrier cycling | +0.30 cross-carrier |
| **Septier IMSI Catcher** | Multi-IMSI burst, specific SMC timing | — |
| **Cobham Sentry** | UMTS/LTE dual-mode indicators | — |
| **srsRAN / OpenAirInterface** | 210.2s cycle + Identity Request ONLY (no Attach Reject) | −0.40 cross-carrier (impossible) |

**Note on srsRAN discrimination:** Cross-carrier simultaneous release is architecturally impossible on srsRAN. The 210.2s release cycle alone is ambiguous — additional discriminators (T1 hold timer, cross-carrier sync, UEInfo harvesting) are required for confident attribution.

---

## Supported Input Formats

| Format | Source | Notes |
|--------|--------|-------|
| `.ndjson` | Rayhunter alert files | Primary format — full event data with PLMN per cell |
| `.pcap` / `.pcapng` | Rayhunter + Wireshark | Requires `tshark` installed for full decode |
| `.qmdl` | Qualcomm DIAG (modem) | Raw physical layer — install pySCAT for full NAS dissection |

---

## CLI Reference

```
python main.py [options]

Input:
  --file FILE, -f FILE      Input file (NDJSON, PCAP, QMDL). Repeatable.
  --dir DIR,  -d DIR        Scan directory recursively for all supported files.

Output:
  --output FILE, -o FILE    Write JSON report to file.
  --html                    Generate interactive HTML forensic report.
  --manifest                Generate SHA-256 forensic file manifest (JSON + CSV).
  --timeline                Generate cross-session event timeline.
  --export-pcap             Export flagged events as PCAPNG for tshark analysis.

Analysis:
  --mcc MCC                 Override MCC filter (e.g. 505 for Australia).
  --mnc MNC                 Override MNC (001=Telstra, 003=Vodafone AU).
  --config FILE, -c FILE    Config file (default: config.yaml).
  --verbose, -v             Verbose output including per-file event counts.

Advanced:
  --compare A.json B.json   Diff two report JSONs to track changes over time.
  --watch                   Watch mode -- re-analyze when new files appear.
  --watch-interval N        Watch polling interval in seconds (default: 30).
```

```
python rayhunter_deep_analysis.py [options]

  --dir DIR         Directory containing capture files (required)
  --days            Show full day-by-day timeline with known event correlation
  --output          Save full report to timestamped text file
  --compare OLD     Compare --dir (new) against OLD directory
  --acma            Generate pre-formatted ACMA evidence update draft
```

---

## Architecture

```
rayhunter-threat-analyzer/
├── main.py                          # Entry point -- full YAICD pipeline
├── rayhunter_deep_analysis.py       # Standalone deep analysis v2.4 (Hello Mofo Edition)
├── config.yaml                      # Detection thresholds, known rogue cells
├── requirements.txt                 # Python dependencies
│
├── assets/
│   └── hello_mofo_banner_tight.png  # Hello Mofo Edition banner
│
├── parsers/
│   ├── ndjson_parser.py
│   ├── pcap_parser.py
│   └── qmdl_parser.py
│
├── detectors/
│   ├── identity_harvest.py
│   ├── cipher_downgrade.py
│   ├── rogue_tower.py
│   ├── rrc_periodicity.py
│   ├── handover_inject.py
│   ├── paging_anomaly.py
│   ├── earfcn_anomaly.py
│   └── hardware_fingerprint.py
│
├── intelligence/
│   ├── hardware_fingerprint.py
│   └── db/
│       ├── devices/
│       └── attacks/
│
└── tests/
    └── test_synthetic.py
```

---

## Configuration

Edit `config.yaml` to tune detection thresholds:

```yaml
network:
  mcc: "505"     # Australia
  mnc: "001"     # Telstra (use 003 for Vodafone AU scans)

thresholds_v2:
  t1_hold_timer_confirmed_seconds: 610.6
  t1_hold_timer_std_dev: 0.55
  rrc_periodicity_target_telstra_seconds: 210.2
  rrc_periodicity_target_vodafone_seconds: 40.5

investigation:
  confirmed_operation_start: "2024-12-19"
  total_confirmed_days: 507

known_rogue_cells:
  "505-01-137713175":
    notes: "Prendergast Ave CE -- OpenCelliD confirmed Apr 2026"
  "505-03-8409357":
    notes: "Primary Vodafone rogue -- cross-network confirmed"
```

---

## Legal Framework (Australia)

| Finding | Applicable Law |
|---------|----------------|
| IMSI/IMEISV harvesting | Privacy Act 1988 (Cth) — APP 3; Radiocommunications Act 1992 s.189 |
| Rogue base station operation | Radiocommunications Act 1992 (Cth) s.189 |
| Unauthorised interception | Telecommunications (Interception and Access) Act 1979 (Cth) |
| Unauthorised network access | Criminal Code Act 1995 (Cth) Div 477 |

---

## Background

This tool was built during a personal investigation into confirmed IMSI catcher activity at a neighbouring property in Cranbourne East, Victoria, Australia. The investigation began in late 2024 and is ongoing as of May 2026.

**Equipment used:**
- 2x TP-Link M7350 hotspots running Rayhunter v0.10.2 firmware (dual simultaneous monitoring)
- Raspberry Pi 5 as analysis server and Tailscale gateway
- RTL-SDR V3 for RF corroboration
- TinySA for spectrum analysis

**Regulatory actions:**
- ACMA ENQ-1851DVJH04 (field visit conducted 8 May 2026)
- TIO 2026-03-04898
- VicPol CIRS-20260331-141 and CIRS-20260413-6
- Telstra Ref 128653446 — confirmed unauthorised Cel-Fi G51 repeater on network
- Data shared with Hayley Pedersen at the Electronic Frontier Foundation
- Invited to join the EFF Atlas of Surveillance project

---

## Changelog

### v2.4 — Hello Mofo Edition (16 May 2026)
- `rayhunter_deep_analysis.py` — new standalone companion script with 19 analysis features
- Hello Mofo attacker profile: named profile for Cranbourne East persistent operator (score 11.0 confirmed)
- Transmitter movement corridor analysis with geographic centroid and bearing calculations
- Cross-batch comparison mode (`--compare`)
- Pre-formatted ACMA evidence update draft generation (`--acma`)
- Signal strength tracking (RSRP/RSSI extraction)
- Auto-saved timestamped report (`--output`)
- Hello Mofo Edition banner

### v2.2 (9 May 2026)
- Heuristic scorer, RRC periodicity detector, intelligence DB structure

### v2.1 (9 May 2026)
- identity_harvest.py: correct IMEISV (type 3) vs IMSI (type 1) labelling
- cipher_downgrade.py: EEA0 requires SecurityModeCommand context
- ndjson_parser.py: per-cell MNC from SIB1 PLMN field
- hardware_fingerprint.py: Harris HailStorm primary, T1=610.6s signature added
- config.yaml: Vodafone CIDs corrected to MNC=003

---

## Contributing

Pull requests welcome. Priority areas:
- pySCAT/signalcat integration for full QMDL NAS dissection
- OpenCellID automatic cell verification
- 5G NR (NR-RRC) support
- Additional hardware fingerprint profiles
- Multi-language support (EU regulatory frameworks)

---

## Acknowledgements

- [EFF Rayhunter project](https://github.com/EFForg/rayhunter) — the foundation this tool is built on
- [SeaGlass](https://seaglass.cs.washington.edu/) — University of Washington IMSI catcher detection research
- [YAICD / AIMSICD](https://github.com/AIMSICD/AIMSICD) — Android IMSI catcher detector
- 3GPP TS 24.301, TS 33.401, TS 36.331 — the specifications that define what "normal" looks like
- Tucker et al. (NDSS 2025) — 53-message IMSI exposure taxonomy
- Dabrowski et al. (RAID 2016) — operator-side IMSI catcher detection

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built with a Raspberry Pi 5, two TP-Link hotspots, an RTL-SDR, 3 LLMs, a lot of late nights, and possibly a couple of beers*

*"For Steve..." — Hunt the Hunters*

*—Julian Burns — Cranbourne East, VIC, Australia — 2026*
