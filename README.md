# Rayhunter Threat Analyzer

> **Forensic-grade IMSI catcher detection and analysis for Rayhunter cellular captures.**  
> Built by Julian Burns — Cranbourne East, Victoria, Australia — 2026

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows/Linux/macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com)

---

## What Is This?

This is a **post-processing forensic analysis layer** for [Rayhunter](https://github.com/EFForg/rayhunter) — the EFF's open-source IMSI catcher detector.

Where Rayhunter detects and flags suspicious events in real time, the **Rayhunter Threat Analyzer** takes those raw captures (NDJSON, PCAP/PCAPNG, QMDL) and performs deep forensic analysis:

- Correlates events across multiple capture sessions and networks
- Identifies **hardware fingerprints** (srsRAN, Harris, PKI, Septier, Cobham)
- Detects behavioral attack patterns over time, not just single events
- Produces court-ready forensic reports with SHA-256 chain-of-custody manifests
- Maps findings to 3GPP specifications and Australian/international law

This tool was built during a **10-month real-world IMSI catcher investigation** in suburban Melbourne, Australia — processing over **40 million events** across dual Rayhunter units monitoring Telstra (505-01) and Vodafone (505-03) simultaneously.

---

## Key Discovery: The 210.2s srsRAN Fingerprint

During this investigation, a metronomic **210.2-second RRCConnectionRelease cycle** was identified as a unique hardware fingerprint of srsRAN/OpenAirInterface running on commodity SDR hardware (HackRF, LimeSDR, USRP).

This fingerprint was confirmed across **four independent evidence streams**:

| Stream | Finding |
|--------|---------|
| NDJSON analysis | 208.0s + 209.3s intervals on 2 independent Telstra Cell IDs |
| QMDL deep decode | 3× simultaneous PDN bearer re-establishment (forced de-attach confirmed) |
| Raw pcapng (tshark) | **210.217s** RRCConnectionRelease delta — direct packet timestamp measurement |
| Session analysis | 85× SecurityModeCommand + 85× UEInformationRequest-r9 + 84× Release `cause=other` |

Legitimate LTE infrastructure uses **dynamic, load-dependent** release timers. A fixed-precision 210.2s cycle is a programmatic timer baked into firmware — not a carrier tower behavior.

**This fingerprint is now implemented as a core detector in this tool.**

---

## Detectors

| Detector | What It Finds | 3GPP Reference |
|----------|--------------|----------------|
| `IdentityHarvestDetector` | IMSI Identity Request floods (>2 per attach) | TS 24.301 §5.4.4 |
| `CipherDowngradeDetector` | EEA0+EIA0 null-cipher Security Mode Commands | TS 33.401 §5.1.3.2 |
| `RogueTowerDetector` | Cross-network Cell ID overlap, rogue cell patterns | TS 36.331 |
| `RRCPeriodicityDetector` | Metronomic release cycles (210.2s srsRAN signature) | TS 36.331 §5.3.8 |
| `HandoverInjectDetector` | Suspicious handover command sequences | TS 36.331 §5.4 |
| `PagingAnomalyDetector` | Abnormal paging patterns and IMSI exposure | TS 24.301 §5.6.2 |
| `EARFCNAnomalyDetector` | Suspicious EARFCN/frequency band usage | TS 36.101 |
| `HardwareFingerprinter` | Device classification by behavioral profile | — |

---

## Hardware Fingerprints

The tool scores captures against known IMSI catcher behavioral profiles:

| Device | Key Indicators |
|--------|---------------|
| **srsRAN / OpenAirInterface** | 210.2s metronomic cycle, Deku Incomplete NAS errors, SDR timing jitter |
| **Harris HailStorm / StingRay II** | Auth Reject chains, catch-release pattern, `cause=other` floods |
| **PKI 1625 / 1650** | Null-cipher + identity harvest combination, Band 28 preference |
| **Septier IMSI Catcher** | Multi-IMSI burst, specific SMC timing |
| **Cobham Sentry** | UMTS/LTE dual-mode indicators |

---

## Supported Input Formats

| Format | Source | Notes |
|--------|--------|-------|
| `.ndjson` | Rayhunter alert files | Primary format — full event data |
| `.pcap` / `.pcapng` | Rayhunter + Wireshark | Requires `tshark` installed |
| `.qmdl` | Qualcomm DIAG (modem) | Raw physical layer data — richest signal |

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/julianburnz/rayhunter-threat-analyzer.git
cd rayhunter-threat-analyzer

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install tshark (for PCAP support)
# Ubuntu/Debian:
sudo apt install tshark
# macOS:
brew install wireshark
# Windows: install Wireshark from https://wireshark.org

# 4. Optional: install pySCAT for full QMDL dissection
pip install git+https://github.com/fgsect/scat.git

# 5. Run the synthetic test (no files needed)
python test_synthetic.py

# 6. Analyze your Rayhunter captures
python main.py --dir /path/to/rayhunter/output

# 7. Full forensic run with HTML report + manifest
python main.py --dir /path/to/captures --manifest --html --output report.json
```

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
  --watch                   Watch mode — re-analyze when new files appear.
  --watch-interval N        Watch polling interval in seconds (default: 30).
```

---

## Real-World Results

From the Cranbourne East investigation (Feb–May 2026):

```
Total events analyzed:    40,036,142
Capture files processed:  19,819
Analysis runtime:         3,672 seconds (61 minutes)

Findings:
  CRITICAL  102,810 EEA0+EIA0 null-cipher Security Mode Commands
  CRITICAL    750 IMSI Identity Requests in 120-second window (375× permitted max)
  HIGH          1 Auth Reject → Identity Request attack chain (5.364s gap)
  INFO         18 unique Cell IDs observed (5 anomalous, 1 unknown TAC)

Hardware profile: Harris HailStorm / PKI 1625 class (confidence: 0.85)
                  srsRAN / OpenAirInterface (confidence: 0.25)
```

---

## Architecture

```
rayhunter-threat-analyzer/
├── main.py                    # Entry point — orchestrates full pipeline
├── config.yaml                # Detection thresholds and network config
├── requirements.txt           # Python dependencies
│
├── Parsers
│   ├── ndjson_parser.py       # Rayhunter NDJSON alert files
│   ├── pcap_parser.py         # PCAP/PCAPNG via pyshark/tshark
│   └── qmdl_parser.py         # Qualcomm DIAG binary format
│
├── Detectors
│   ├── base.py                # BaseDetector interface
│   ├── identity_harvest.py    # IMSI Identity Request flood
│   ├── cipher_downgrade.py    # EEA0/EIA0 null-cipher detection
│   ├── rogue_tower.py         # Cell ID correlation + rogue patterns
│   ├── rrc_periodicity.py     # 210.2s metronomic cycle (srsRAN fingerprint)
│   ├── handover_inject.py     # Handover injection detection
│   ├── paging_anomaly.py      # Paging flood / IMSI exposure
│   ├── paging_cycle.py        # Automated paging cycle analysis
│   ├── earfcn_anomaly.py      # EARFCN / frequency anomalies
│   └── proximity_track.py     # ProSe/D2D proximity tracking
│
├── Analysis
│   ├── hardware_fingerprint.py  # Device classification engine
│   ├── timeline_correlator.py   # Cross-session event timeline
│   ├── cell_db.py               # Cell ID registry and lookup
│   ├── earfcn.py                # EARFCN / frequency utilities
│   └── known_patterns.py        # Reference behavioral signatures
│
├── Output
│   ├── reporter.py              # Terminal report (rich)
│   ├── html_reporter.py         # Interactive HTML report
│   ├── html_reporter_v2.py      # HTML report v2 with timeline
│   ├── manifest_generator.py    # SHA-256 forensic manifest
│   ├── pcap_exporter.py         # Flagged events → PCAPNG
│   ├── report_differ.py         # Report comparison / diff
│   └── watcher.py               # Watch mode file monitor
│
├── Intelligence (YAML database)
│   ├── attacker_profiles.yaml
│   ├── behavioral_signatures.yaml
│   ├── cipher_downgrade.yaml
│   ├── identity_request.yaml
│   ├── rogue_tower.yaml / opensource_sdr.yaml / commercial_le.yaml
│   └── ... (15 intelligence files total)
│
└── test_synthetic.py          # Synthetic data test — no captures needed
```

---

## Configuration

Edit `config.yaml` to tune detection thresholds:

```yaml
detection:
  identity_harvest:
    window_seconds: 120
    max_requests: 2          # 3GPP permits max 2 per attach
    
  cipher_downgrade:
    flag_eea0: true          # Flag null encryption
    flag_eia0: true          # Flag null integrity (prohibited by 3GPP)
    
  rrc_periodicity:
    cycle_seconds: 210.2     # srsRAN default timer
    tolerance_seconds: 15.0  # Jitter window
    min_observations: 3      # Minimum cycle count to flag

network:
  mcc: "505"                 # Australia
  mnc_telstra: "001"
  mnc_vodafone: "003"
```

---

## Legal Framework (Australia)

Findings are mapped to applicable Australian legislation:

| Finding | Applicable Law |
|---------|---------------|
| Null-cipher interception | Telecommunications (Interception and Access) Act 1979 (Cth) |
| IMSI harvesting | Privacy Act 1988 (Cth) — APP 3; Radiocommunications Act 1992 s.189 |
| Rogue base station | Radiocommunications Act 1992 (Cth) s.189 |
| Protocol manipulation | Criminal Code Act 1995 (Cth) Div 477 |

---

## Background

This tool was built during a personal investigation into suspected IMSI catcher activity near my home in Cranbourne East, Victoria, Australia. What started as a home network anomaly in late 2025 escalated into a full cellular surveillance investigation using:

- 2× TP-Link M7350 hotspots running Rayhunter firmware
- Raspberry Pi 5 as analysis and Tailscale gateway
- Dual-network monitoring (Telstra + Vodafone simultaneously)

Active regulatory complaints have been filed with ACMA, TIO, Victoria Police, and Telstra. Raw capture data has been shared with the Electronic Frontier Foundation.

The 210.2s srsRAN fingerprint discovered during this investigation is an original finding — confirmed across four independent evidence streams — and is submitted here as a contribution to the open-source cellular security community.

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
- [YAICD](https://github.com/AIMSICD/AIMSICD) — Yet Another IMSI Catcher Detector
- 3GPP TS 24.301, TS 33.401, TS 36.331 — the specifications that define what "normal" looks like

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built with a Raspberry Pi 5, two TP-Link hotspots, and a lot of late nights.*  
*Julian Burns — Cranbourne East, VIC, Australia — 2026*
