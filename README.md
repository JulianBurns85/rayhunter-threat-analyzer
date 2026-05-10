# Rayhunter Threat Analyzer

> **Forensic-grade IMSI catcher detection and analysis for Rayhunter cellular captures.**  
> Built by Julian Burns — Cranbourne East, Victoria, Australia — 2024–2026

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows/Linux/macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com)

---

## What Is This?

This is a **post-processing forensic analysis layer** for [Rayhunter](https://github.com/EFForg/rayhunter) — the EFF's open-source IMSI catcher detector.

Where Rayhunter detects and flags suspicious events in real time, the **Rayhunter Threat Analyzer** takes those raw captures (NDJSON, PCAP/PCAPNG, QMDL) and performs deep forensic analysis:

- Correlates events across multiple capture sessions and networks
- Identifies **hardware fingerprints** (Harris HailStorm/StingRay II, PKI, Septier, Cobham, srsRAN)
- Detects behavioral attack patterns over time, not just single events
- Produces forensic reports with SHA-256 chain-of-custody manifests
- Maps findings to 3GPP specifications and Australian/international law

This tool was built during a **16-month real-world IMSI catcher investigation** in suburban Melbourne, Australia — processing captures across dual Rayhunter units monitoring Telstra (505-01) and Vodafone AU (505-03) simultaneously.

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

### Confirmed Rogue Cell IDs (all on-air as of 9 May 2026)

**Telstra AU (MCC=505 MNC=001, TAC=12385):**
`137713155` · `137713165` · `137713175` · `137713195`

**Vodafone AU (MCC=505 MNC=003, TAC=30336):**
`8409357` · `8409367` · `8409387` · `8409397`

### Cross-Carrier Simultaneous Operation

Zero-second simultaneous RRCConnectionRelease across Telstra and Vodafone confirmed (April 8, 2026 15:38:08 UTC). This is architecturally impossible on srsRAN or any single-carrier platform. Harris StingRay II/HailStorm hardware with independent Harpoon power amplifiers per carrier is the only commercial platform consistent with this signature.

### T1 Hold Timer — Shared Harris Signature

T1 = 610.6s ±0.55s confirmed across five independent macro connection events on both carriers (PCAPNG burst analysis, 9 May 2026). Machine-precision shared parameter = both devices managed by a single Harris RayFish Controller.

### Three-Phase Operational Timeline

| Phase | Period | T3 Timer | Interpretation |
|-------|--------|----------|----------------|
| Phase 1 | Dec 2024 – Jan 22, 2026 | 3000.4s ±0.35s | Passive survey / baseline mode |
| Phase 2 | Jan 28 – May 7, 2026 | 210.2s (Telstra) / 40.5s (Vodafone) | Active harvest mode |
| Phase 3 | May 8, 2026 onwards | Chaotic — T1 unchanged at 610.6s | 

- Both devices remained operational — not decommiss

**Regulatory complaints on file:** ACMA ENQ-1851DVJH04 · TIO 2026-03-04898 · VicPol CIRS-20260331-141 · VicPol CIRS-20260413-6 · Telstra Ref 128653446 (confirmed unauthorised Cel-Fi G51)

---

## Detectors

| Detector | What It Finds | 3GPP Reference |
|----------|---------------|----------------|
| `IdentityHarvestDetector` | IMSI/IMEI/IMEISV Identity Request floods — correctly labels type | TS 24.301 §5.4.4 |
| `CipherDowngradeDetector` | EEA0+EIA0 null-cipher in SecurityModeCommand context | TS 33.401 §5.1.3.2 |
| `RogueTowerDetector` | Rogue Cell IDs with per-carrier MNC attribution | TS 36.331 |
| `RRCPeriodicityDetector` | Metronomic T3 and T1 timer analysis | TS 36.331 §5.3.8 |
| `HandoverInjectDetector` | Suspicious handover command sequences | TS 36.331 §5.4 |
| `PagingAnomalyDetector` | Abnormal paging patterns and IMSI exposure | TS 24.301 §5.6.2 |
| `EARFCNAnomalyDetector` | Suspicious EARFCN/frequency band usage | TS 36.101 |
| `HardwareFingerprinter` | Device classification by behavioral profile | — |

---

## Hardware Fingerprints

The tool scores captures against known IMSI catcher behavioral profiles:

| Device | Key Indicators | Score Modifiers |
|--------|---------------|-----------------|
| **Harris HailStorm / StingRay II** | Cross-carrier simultaneous release, T1=610.6s, UEInfo-r9, Auth Reject | +0.40 cross-carrier, +0.30 T1 |
| **Harris KingFish** | UEInfo-r9 harvesting, Auth Reject chains | +0.15 UEInfo |
| **PKI 1625** | Catch-and-release, Band 28, multi-carrier cycling | +0.30 cross-carrier |
| **Septier IMSI Catcher** | Multi-IMSI burst, specific SMC timing | — |
| **Cobham Sentry** | UMTS/LTE dual-mode indicators | — |
| **srsRAN / OpenAirInterface** | 210.2s cycle + Identity Request ONLY (no Attach Reject) | −0.40 cross-carrier (impossible) |

**Note on srsRAN discrimination:** Cross-carrier simultaneous release is architecturally impossible on srsRAN (single-carrier by design). If cross-carrier events are present, srsRAN receives a −0.40 confidence penalty. The 210.2s release cycle alone is ambiguous — it matches both the srsRAN default timer and the Cranbourne East Phase 2 Telstra T3 value. Additional discriminators (T1 hold timer, cross-carrier sync, UEInfo harvesting) are required for confident attribution.

---

## Supported Input Formats

| Format | Source | Notes |
|--------|--------|-------|
| `.ndjson` | Rayhunter alert files | Primary format — full event data with PLMN per cell |
| `.pcap` / `.pcapng` | Rayhunter + Wireshark | Requires `tshark` installed for full decode |
| `.qmdl` | Qualcomm DIAG (modem) | Raw physical layer — install pySCAT for full NAS dissection |

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

# 5. Analyze your Rayhunter captures
python main.py --dir /path/to/rayhunter/output

# 6. Full forensic run with HTML report + manifest
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

## Example Output

```
◆ HARDWARE CANDIDATES
  [0.7] Harris HailStorm / StingRay II
        PERSISTENCE: EXTREME (506 days confirmed — >1 year persistent operation)
  [0.6] Harris StingRay II
        T1_HOLD: T1=610.6s matches confirmed Harris signature (both carriers)
  [0.4] PKI 1625

◆ CELL SUMMARY
  CID=8409387  TAC=30336 MCC=505 MNC=03 (Vodafone AU) observations=9
  CID=8409357  TAC=30336 MCC=505 MNC=03 (Vodafone AU) observations=17
  CID=137713195 TAC=12385 MCC=505 MNC=01 (Telstra)    observations=9
  CID=137713155 TAC=12385 MCC=505 MNC=01 (Telstra)    observations=6
```

---

## Architecture

```
rayhunter-threat-analyzer/
├── main.py                      # Entry point — orchestrates full pipeline
├── config.yaml                  # Detection thresholds, known rogue cells, investigation context
├── requirements.txt             # Python dependencies
│
├── parsers/
│   ├── ndjson_parser.py         # Rayhunter NDJSON — per-cell MNC from SIB1 PLMN
│   ├── pcap_parser.py           # PCAP/PCAPNG via pyshark/tshark
│   └── qmdl_parser.py           # Qualcomm DIAG binary format
│
├── detectors/
│   ├── base.py                  # BaseDetector interface
│   ├── identity_harvest.py      # IMSI/IMEI/IMEISV Identity Request — correct type labelling
│   ├── cipher_downgrade.py      # EEA0/EIA0 — SecurityModeCommand context only
│   ├── rogue_tower.py           # Cell ID correlation with per-carrier MNC
│   ├── rrc_periodicity.py       # T3/T1 metronomic cycle analysis
│   ├── handover_inject.py       # Handover injection detection
│   ├── paging_anomaly.py        # Paging flood / IMSI exposure
│   ├── paging_cycle.py          # Automated paging cycle analysis
│   ├── earfcn_anomaly.py        # EARFCN / frequency anomalies
│   └── proximity_track.py       # ProSe/D2D proximity tracking
│
├── intelligence/
│   ├── hardware_fingerprint.py  # Device scoring: Harris primary, srsRAN discriminated
│   └── db_engine.py             # Intelligence YAML database engine
│
├── output/
│   ├── reporter.py              # Terminal report (rich colour)
│   ├── html_reporter.py         # Interactive HTML report
│   ├── html_reporter_v2.py      # HTML report v2 with timeline
│   ├── manifest_generator.py    # SHA-256 forensic manifest
│   ├── pcap_exporter.py         # Flagged events → PCAPNG exhibit file
│   ├── report_differ.py         # Report comparison / diff
│   └── watcher.py               # Watch mode file monitor
│
└── tests/
    └── test_synthetic.py        # Synthetic data test — no captures needed
```

---

## Configuration

Edit `config.yaml` to tune detection thresholds:

```yaml
network:
  mcc: "505"     # Australia
  mnc: "001"     # Telstra (use 003 for Vodafone AU scans)

thresholds_v2:
  # T1 hold timer — confirmed Harris signature (9 May 2026)
  t1_hold_timer_confirmed_seconds: 610.6
  t1_hold_timer_std_dev: 0.55

  # RRC Periodicity
  rrc_periodicity_target_telstra_seconds: 210.2
  rrc_periodicity_target_vodafone_seconds: 40.5

investigation:
  confirmed_operation_start: "2024-12-19"
  total_confirmed_days: 506

known_rogue_cells:
  "505-01-137713195":
    notes: "Primary Telstra rogue — ACMA ENQ-1851DVJH04"
  "505-03-8409357":
    notes: "Primary Vodafone rogue — cross-network confirmed"
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
- 2× TP-Link M7350 hotspots running Rayhunter v0.10.2 firmware (dual simultaneous monitoring)
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

## v2.1 Changes (9 May 2026)

- **identity_harvest.py** — Correctly labels IMEISV (type 3) vs IMSI (type 1). tshark-verified: 1778156124.pcapng frames 650/1098/1970/2639 are IMEISV device fingerprinting events, not IMSI flood.
- **cipher_downgrade.py** — EEA0 detector now requires `msg_type == SecurityModeCommand`. Prevents false positives from UE capability advertisement fields.
- **ndjson_parser.py** — Per-cell MNC read from SIB1 PLMN field. Vodafone cells (MNC=03) no longer misreported as Telstra (MNC=01).
- **rogue_tower.py** — Cell summary uses per-cell MNC with carrier name. Evidence lines now show `MNC=03 (Vodafone AU)` / `MNC=01 (Telstra)`.
- **hardware_fingerprint.py** — Harris HailStorm now primary candidate. Persistence reads `total_confirmed_days` from config (506 days) not batch timestamp span. srsRAN 210.2s default removed. Cross-carrier detection fixed. T1=610.6s Harris signature added.
- **config.yaml** — Vodafone CIDs corrected to MNC=003. T1 signature, investigation start date, and EARFCN 16384 added.

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

*Built with a Raspberry Pi 5, two TP-Link hotspots, an RTL-SDR, 3 LLM's lot of late nights, and possibly a couple of beers*
*"For Steve..." - Hunt the Hunters*
*-Julian Burns — Cranbourne East, VIC, Australia — 2026*
