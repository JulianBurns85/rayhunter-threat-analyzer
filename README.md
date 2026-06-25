# rayhunter-threat-analyzer

Cellular surveillance detection and forensic analysis for passive RF captures.

Analyses Rayhunter output files (NDJSON · PCAP · QMDL) for IMSI catcher activity, rogue base stations, null-cipher attacks, forced handover injection, timing-based hardware fingerprinting, and related cellular surveillance techniques. Produces terminal reports, JSON output, and KML forensic maps.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-lightgrey)

---

## Overview

Most IMSI catcher detection tools stop at "something unusual is here." This tool asks the harder question: what is it, how is it operating, and can you prove it from multiple independent sources?

rayhunter-threat-analyzer runs 88 detectors across protocol, behavioral, timing, and attribution layers — then correlates findings across three completely independent evidence classes to produce the strongest possible forensic output for civilian investigation.

Built against a real-world corpus of 900,000+ cellular events collected over 18 months of continuous passive monitoring.

---

## Key Features

### 🔴 Triple-Confirmation Cross-Source Corroboration (v4.4)

The centrepiece of v4.4. Correlates rogue cell detections across three independent evidence classes:

| Source | Method | Independence |
|--------|--------|--------------|
| Passive RF corpus | Rayhunter NDJSON/PCAP/QMDL capture | Phone-side passive monitoring |
| Firmware baseband log | Shannon IMS parser — `RILC_UNSOL_IMS_SUPPORT_SERVICE` | Modem hardware layer, cannot be influenced by user-space tools |
| CASTNET network | Federated detection node API | Independent hardware node |

When the same rogue Cell ID appears across 2 sources: **DUAL CONFIRMATION** 🟠. Across all 3: **TRIPLE CONFIRMATION** 🔴 — the strongest possible forensic evidence class available without direct device examination.

---

### 10-Heuristic YAICD Framework

Formal IMSI catcher detection scoring based on Dabrowski et al. (ACSAC 2014) and Ziayi et al. (2021). Produces a scored verdict against a validated threshold, with each heuristic independently confirmed or partial.

```
YAICD score: 5.00 / threshold: 2.6  →  *** FORMAL POSITIVE DETECTION ***
```

---

### Shannon IMS Baseband Log Parser (novel — not in other open-source tools)

Parses standard Android bug reports for Samsung Shannon baseband modem IMS log entries. The modem logs which cell it registered to at the hardware layer — completely independently of any RF capture tool or user-space process.

Compatible devices: All Google Pixel 6 and later (Exynos Modem 5400/5300), Samsung Galaxy S/A series with Exynos silicon, and any Android device using the Samsung Shannon IMS stack.

```bash
# Standalone test
python detectors/shannon_ims_parser.py bugreport.txt

# Integrated — runs automatically if bug_report_dir is set in config.yaml
python main.py --dir captures/ --bug-reports /path/to/BugReports/
```

---

### 📱 Companion: Canary — On-Device IMSI Catcher Detection

[**Canary**](https://github.com/JulianBurns85/canary) is a companion Android app for GrapheneOS that brings real-time IMSI catcher detection to the device itself. Built for the Pixel 9 Pro Fold and compatible with all GrapheneOS-supported Pixel hardware.

- Real-time rogue cell alerting via the CASTNET API
- Autonomous countermeasure chain (CM defense) — confirmed operational
- ADB connection indicator and detection history export
- First-run onboarding wizard
- Built on the same detection logic as this tool

Canary

### [Argus-DB](https://github.com/kevwillow/argus-db) (kevwillow)
Provenance-tracked database of 43,000+ wireless identifiers for surveillance equipment —
IMSI catchers, ALPR cameras, drone Remote ID, body cams, gunshot detectors, trackers.
Sourced from IEEE OUI, FCC EAS, court filings (CourtListener RECAP), and procurement records.
Confidence-scored on every row. Feeds rayhunter-threat-analyzer as a 4th corroboration source
for hardware attribution. **Dataset:** ODbL-1.0 | **Docs:** CC-BY-SA-4.0 | **Pipeline:** AGPL-3.0

 closes the loop: rayhunter-threat-analyzer analyses captures in depth after the fact; Canary alerts you while it's happening.

→ [github.com/JulianBurns85/canary](https://github.com/JulianBurns85/canary)

---

## 88-Detector Analysis Pipeline

### Protocol Layer

- Cipher/identity anomaly detection (EEA0 null-cipher, pre-security IMSI, Auth-Reject harvest)
- RRC periodicity and metronomic release cycle detection (srsRAN/Harris timing signatures)
- Handover injection detection (RRCConnectionReconfiguration without MeasurementReport)
- FlashCatch attack detection
- NAS entropy analysis
- Paging volume anomaly and pre-harvest flood detection
- Tucker et al. NDSS 2025 53-message IMSI exposure taxonomy (formal IER calculation)
- Cell reselection parameter manipulation monitoring
- NAS timer anomaly detection (T3412/T3402/T3411)

### Timing & Hardware Fingerprinting

- Jitter DNA tracker — 2100ms non-3GPP timing fingerprint (srsRAN OS scheduler signature)
- Metronomic RRC release profiling (hardware temporal DNA)
- Beacon periodicity scorer — dual-stack SDR vs professional hardware interval classification
- CFO drift analyser
- Hardware lifecycle timeline — longitudinal jitter evolution across multi-session corpus
- Cross-session hardware persistence tracker

### Attribution Layer

- Dual-device temporal segregation analysis (audit evasion architecture detection)
- Operator rhythm profiler — human behavioral fingerprint extraction
- Hardware attribution engine — Harris/Septier vs srsRAN/BladeRF classification
- Platform Fusion Engine — cross-detector correlation with hypothesis defeater scoring
- Simultaneous CID co-presence / band incompatibility proof (physical-layer dual-device confirmation)
- CID rotation detector with eNB sector disambiguation
- CASTNET live API ingestion (auto-detects Pi on LAN or Tailscale)

### Regulatory & Behavioral

- Regulatory escalation scorer (ACMA/AFP/VicPol response pattern analysis)
- Regulatory event correlator (before/after behavioral comparison)
- Attack intensity timeline (daily threat scoring across corpus)
- Attack campaign segmenter (multi-campaign timeline with regulatory trigger correlation)
- Silent period / blackout detector
- Cross-source corroboration engine (triple-confirmation framework)

### Geographic & Export

- KML forensic map export (rogue CID locations + Timing Advance distance rings)
- Novel CID detector (OpenCelliD cross-reference)
- Rogue tower detector
- Fleet RF signature detector (AU fleet/vehicle/tracker profiles)

---

## Platform Fusion Engine

Synthesises findings from all detectors into a unified attacker profile:

```
+- PLATFORM_ALPHA -- Confidence: 80.0%
|  CID Cluster:    8409357, 137713165 ...
|  Jitter DNA:     124595.0ms mean cycle
|  Operator:       Business hours (Mon-Fri 08:00-18:00 AEST)
|  IMSI Harvests:  2 confirmed
|  Hypothesis Defeater:
|    Cel-Fi G51 repeater:         0.00%
|    Legitimate carrier edge case: 0.00%
|    Active rogue platform:        99.99%
```

---

## Provenance Map

Every finding is classified by what it's actually built on:

```
[MEASURED]   byte-backed from this capture set
[DISPUTED]   cites this capture but message not in decode
[HISTORICAL] from CASTNET / multi-session corpus
[INFERRED]   attribution built on assumptions
[PENDING]    detector active, no data yet
```

This prevents findings from different evidence tiers being weighted equally.

---

## Installation

```bash
git clone https://github.com/JulianBurns85/rayhunter-threat-analyzer
cd rayhunter-threat-analyzer
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, pyshark, scapy, pyyaml, requests, flask (optional, for web UI)

**Windows note:** pyshark requires Wireshark/tshark to be installed and on PATH.

---

## Usage

```bash
# Scan a directory of captures
python main.py --dir "C:\RH\captures"

# Include Android bug reports for Shannon IMS firmware analysis
python main.py --dir captures/ --bug-reports /path/to/BugReports/

# Point to a specific CASTNET API (auto-detects if not specified)
python main.py --dir captures/ --castnet-api http://192.168.1.100:5000

# Output formats
python main.py --dir captures/ --format both   # terminal + JSON
python main.py --dir captures/ --format json   # JSON only

# Parallel QMDL parsing — set to your CPU core count for best performance
python main.py --dir captures/ --workers 8

# Verbose with manifest
python main.py --dir captures/ --verbose --manifest
```

---

## Configuration

`config.yaml` controls all detection parameters:

```yaml
bug_report_dir: "C:/RH/BugReports"   # Android bug reports for Shannon IMS parser

detection:
  rogue_tower:
    known_rogue_cids: []              # Confirmed rogue CIDs (byte-level proof required)
    watchlist_cids:                   # Prior-session leads (INFO-only)
      - "137713165"

opencellid:
  enabled: true
  api_key: "YOUR_KEY_HERE"
```

> **Note on `known_rogue_cids`:** A CID earns a place here only through byte-level attack behaviour in a capture — EEA0 cipher selection, pre-security IMSI request, or Auth-Reject harvest. List membership alone is not confirmation.

---

## Input Formats

| Format | Source | Notes |
|--------|--------|-------|
| `.ndjson` | Rayhunter | Primary event log |
| `.pcapng` | Rayhunter / tshark | RRC/NAS packet capture |
| `.qmdl` | Rayhunter (QMDL mode) | Qualcomm diagnostic log |
| `bugreport-*.txt` | Android bug report | Shannon IMS firmware log extraction |

---

## Output

**Terminal report** — structured findings with evidence, technique citations, spec references, and recommended actions.

**JSON report** — machine-readable full output including all findings, provenance classification, corroboration data, and YAICD score. Suitable for downstream tooling and app integration.

**KML map** — rogue CID locations with Timing Advance distance rings. Compatible with Google Earth, QGIS, and all standard GIS applications.

---

## CASTNET Integration

CASTNET is a companion federated IMSI catcher detection network. When a CASTNET Pi API is reachable (LAN or Tailscale), the analyzer automatically pulls live detections and includes them in Phase 2d cross-source corroboration.

```
CASTNET Live API:  connected (31,189+ rogue detections, 2 node(s))
```

No manual export required — the live fetch runs automatically at startup and fails silently if the Pi is unreachable, so the analyzer always runs regardless of network state.

→ [github.com/JulianBurns85/CASTNET](https://github.com/JulianBurns85/CASTNET)

---

## Hardware Stack (reference deployment)

The tool is tested against captures from the following hardware:

- **Capture device:** Google Pixel 9 Pro Fold (GrapheneOS) running Rayhunter
- **SDR:** bladeRF 2.0 micro xA4 with Poynting XPOL-2-5G antenna
- **CASTNET node:** Raspberry Pi 5 (Flask API + SQLite), Ulefone Armor Pad 4 Ultra (field node)
- **Network gateway:** MikroTik Chateau 5G (independent Vodafone SIM for cellular monitoring)
- **Analysis workstation:** Windows 11 + D:\RAYHUNTER_MASTER corpus

---

## Releases

### v4.4.0 — Argus-DB Integration (2026-06-26)
- **Argus-DB cross-reference detector** — `detectors/argus_db_correlator.py`
  Cross-references hardware attribution findings against [kevwillow/argus-db](https://github.com/kevwillow/argus-db),
  a provenance-tracked database of 43,000+ surveillance equipment identifiers sourced from
  IEEE OUI allocations, FCC grantee records, court filings, and procurement data (ODbL-1.0).
- **Standalone lookup module** — `argus_db_lookup.py`
  Shared utility for SENTRY and the analyzer. Fetches and caches the argus-db CSV export,
  provides `lookup_vendor()`, `lookup_mac()`, and `sentry_alert_enrich()` for pipeline integration.
- **4th independent corroboration source** — L3Harris (conf=97%), Rohde & Schwarz (conf=95%),
  Septier (conf=90%) all confirmed in argus-db `network_surveillance` category (936 rows),
  independently of RF corpus, Shannon IMS logs, and CASTNET.
- **GUARD CLEAN** — argus-db finding correctly auto-tagged as `[HISTORICAL]` provenance.
- **Credit:** [kevwillow/argus-db](https://github.com/kevwillow/argus-db) — dataset licensed
  ODbL-1.0 (data) / CC-BY-SA-4.0 (docs) / AGPL-3.0 (pipeline). Argus-DB explicitly targets
  Rayhunter as a downstream consumer. Integration follows ODbL attribution requirements.

### v4.3.1 — Integrity corrections, false positive removal, performance
- Confirmed eNB 32849 as legitimate Vodafone macro — removed from all rogue lists
- Added eNB 33853 (OpenCelliD: Cell not found) as confirmed post-ACMA rogue cluster
- corpus_guard BLEED_THROUGH false positive suppressed (session counts legitimately exceed input file count)
- Added `--workers N` flag for parallel QMDL parsing — ~30% speedup on large capture sets
- Fixed 20,629-day duration overflow in attack campaign segmenter
- Persistence tracker anchored to investigation start date (153+ days confirmed)
- Hardware attribution corrected to MULTI-CHAIN HARDWARE PROFILE with ECI decomposition caveat
- All eNB 32849 false rogue attributions removed across 13 detector files

### v4.4 — Triple-confirmation cross-source corroboration
- Shannon IMS baseband log parser
- Cross-source corroboration engine (RF + firmware + CASTNET)
- Tucker et al. NDSS 2025 IER taxonomy

### v4.3 — Corpus guard, provenance map, new detectors
- Provenance classification system
- corpus_guard integrity checker
- KML forensic map export

---

## Research Citations

The detection framework builds on:

- Tucker et al. — [SnoopDog: Exposing IMSI-Catcher Attacks](https://www.ndss-symposium.org/ndss-paper/snoopdog-exposing-imsi-catcher-attacks/) (NDSS 2025)
- Dabrowski et al. — IMSI-Catch Me If You Can (ACSAC 2014)
- Ziayi et al. — YAICD: Yet Another IMSI Catcher Detector (2021)
- Zhuang et al. — FBSleuth: Fake Base Station Forensics (AsiaCCS 2018)
- SeaGlass — University of Washington IMSI Catcher Detection (2017)
- 3GPP TS 36.331 — LTE RRC Protocol Specification
- 3GPP TS 33.401 — LTE Security Architecture
- 3GPP TS 36.104 — LTE Operating Bands

---

## Forensic Methodology Notes

**Triple-confirmation rule:** No finding achieves CONFIRMED status without independent corroboration. The tool is designed to be honest about what each finding is built on — passive RF corpus data, firmware layer evidence, and federated network detections are treated as separate evidence classes and never conflated.

**Provenance integrity:** The [GUARD] system flags findings that cite external data without source tagging, cross-session corpus bleed-through, and location claims without in-capture measurement. These flags appear in every report so the investigator knows exactly what weight to give each finding.

**Appropriate hedging:** The tool uses consistent language — "consistent with," "probable," "suspected" — calibrated to the strength of the underlying evidence. This is intentional. Overclaiming is worse than underclaiming when output may be used in legal or regulatory contexts.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Repository

GitHub: [github.com/JulianBurns85/rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

Companion apps:
- [github.com/JulianBurns85/CASTNET](https://github.com/JulianBurns85/CASTNET) — federated IMSI catcher detection network
- [github.com/JulianBurns85/canary](https://github.com/JulianBurns85/canary) — on-device real-time IMSI catcher detection for GrapheneOS

---

*For Steve.*
