# Rayhunter Threat Analyzer
> **Forensic-grade IMSI catcher detection and analysis for Rayhunter cellular captures.**
> Built by Julian Burns — Cranbourne East, Victoria, Australia — 2026

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows/Linux/macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com)
[![KanyRay West](https://img.shields.io/badge/version-KanyRay%20West%20Edition-gold)](https://github.com/JulianBurns85/rayhunter-threat-analyzer)
[![AFP Referred](https://img.shields.io/badge/status-AFP%20REFERRED-red)](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

---

## What Is This?

A **post-processing forensic analysis layer** for [Rayhunter](https://github.com/EFForg/rayhunter) — the EFF's open-source IMSI catcher detector.

Where Rayhunter detects and flags suspicious events in real time, the **Rayhunter Threat Analyzer** takes those raw captures (NDJSON, PCAP/PCAPNG, QMDL) and performs deep forensic analysis:

- Correlates events across multiple capture sessions and networks
- Identifies **hardware fingerprints** (Harris HailStorm/StingRay II, PKI, Septier, Cobham, srsRAN/OAI)
- Detects behavioral attack patterns over time, not just single events
- Produces **court-ready forensic reports** with SHA-256 chain-of-custody manifests
- Maps findings to 3GPP specifications and Australian/international law
- Cross-references Cell IDs against ACMA licensed spectrum and OpenCelliD database

Built during a **real-world IMSI catcher investigation** in suburban Melbourne, Australia — processing over **40 million events** across dual Rayhunter units monitoring Telstra (505-01) and Vodafone AU (505-03) simultaneously.

---

## Quick Start

```bash
git clone https://github.com/JulianBurns85/rayhunter-threat-analyzer.git
cd rayhunter-threat-analyzer
pip install -r requirements.txt

# Optional: tshark for PCAP support
# Windows: install Wireshark from https://wireshark.org
# Linux: sudo apt install tshark
# macOS: brew install wireshark

# Run synthetic test -- no captures needed
python tests/test_synthetic.py

# Analyze your Rayhunter captures
python main.py --dir /path/to/rayhunter/output

# Full forensic run with all outputs
python main.py --dir /path/to/captures --manifest --html --output report.json
```

---

## Detectors

| Detector | What It Finds | 3GPP Reference |
|----------|---------------|----------------|
| `IdentityHarvestDetector` | IMSI/IMEI/IMEISV Identity Request floods | TS 24.301 §5.4.4 |
| `CipherDowngradeDetector` | EEA0+EIA0 null-cipher SecurityModeCommand | TS 33.401 §5.1.3.2 |
| `RogueTowerDetector` | Rogue Cell IDs, EARFCN anomalies, OpenCelliD cross-reference | TS 36.331 |
| `RRCPeriodicityDetector` | Metronomic release cycles (210.2s srsRAN / 40.5s Vodafone signature) | TS 36.331 §5.3.8 |
| `HandoverInjectDetector` | mobilityControlInfo without MeasurementReport | TS 36.331 §5.4 |
| `PagingAnomalyDetector` | IMSI-targeted paging, paging floods | TS 24.301 §5.6.2 |
| `EARFCNAnomalyDetector` | Out-of-band EARFCN, multi-EARFCN per Cell ID | TS 36.101 |
| `HardwareFingerprinter` | Device classification by behavioral profile | -- |

---

## Hardware Fingerprints

| Device | Key Indicators |
|--------|----------------|
| **Harris HailStorm / StingRay II** | Cross-carrier simultaneous release, T1=610.6s, UEInfo-r9 harvesting |
| **Harris KingFish** | UEInfo-r9 harvesting, Auth Reject chains |
| **PKI 1625 / 1650** | Catch-and-release, Band 28 preference, null-cipher + identity harvest |
| **Septier IMSI Catcher / GUARDIAN** | Multi-IMSI area sweep, EEA0 negotiation, mass collection pattern |
| **Cobham Sentry** | UMTS/LTE dual-mode indicators |
| **srsRAN / OpenAirInterface** | 210.2s metronomic cycle, EEA0+EIA0 default, SDR timing jitter |

**srsRAN vs Harris discrimination:** Cross-carrier simultaneous release is architecturally impossible on srsRAN. The 210.2s cycle alone is ambiguous -- T1 hold timer, cross-carrier sync, and UEInfo harvesting are required for confident Harris attribution.

---

## Intelligence Database

```
intelligence/db/
├── 01_au_spectrum_acma.yaml           # ACMA licensed bands -- Telstra, Vodafone, Optus
├── attacker_profiles.yaml             # Named attacker behavioral profiles
├── attacks/
│   ├── 02_null_cipher_attack.yaml     # EEA0/EIA0 attack patterns and variants
│   ├── 03_geran_redirect_attack.yaml  # 2G forced downgrade (critical in AU -- 2G shutdown 2018)
│   ├── 05_eff_imsi_catcher_guide.yaml
│   └── 10_heuristic_framework.yaml
└── devices/
    ├── 01_srsran_profile.yaml
    ├── 02_cheap_commercial.yaml
    ├── 03_harris_drt_state.yaml
    ├── 04_amateur_experimenter.yaml
    ├── 05_catch_release_hard_landing.yaml
    ├── 06_septier_profile.yaml        # Septier IMSI Catcher / GUARDIAN
    └── 07_pki_electronic_profile.yaml # PKI 1625 / 1650
```

**Australian context:** Australia's 2G networks shut down in 2018. Any GERAN redirect in Australian LTE captures is forensically anomalous -- there is no legitimate 2G infrastructure to redirect to.

---

## Key Confirmed Findings -- Cranbourne East Investigation

### Primary Hardware Profile: Harris Commercial IMSI Catcher

Two Harris commercial IMSI catcher devices confirmed operational at a neighbouring Cranbourne East property. All findings tshark-verified from raw PCAPNG binary unless noted.

| Parameter | Telstra Device (505-01) | Vodafone Device (505-03) |
|-----------|------------------------|--------------------------|
| T3 release cycle | 210.212s +/-0.139s | 40.553s +/-0.327s |
| T3 sample count | 333+ events, 13 sessions | 27 intervals |
| T1 hold timer | 610.6s +/-0.55s (shared) | 610.6s +/-0.55s (shared) |
| UEInfo harvesting | Zero | 100% correlation, 46x baseline |
| EEA0 null cipher | Zero | Zero |
| Rayhunter alerts | Zero | Zero |

**Zero null cipher events and zero Rayhunter alerts are expected** -- Harris Transparent Proxy mode maintains legitimate-appearing encryption while intercepting traffic. Standard detection tools produce no alerts against this operational mode. Timing analysis and Cell ID anomaly detection are the primary reliable detection vectors.

### Confirmed Rogue Cell IDs (active as of May 2026)

**Telstra AU (MCC=505 MNC=001, TAC=12385):**
`137713155` `137713165` `137713175` `137713195` `135836171` `135836191`

**Vodafone AU (MCC=505 MNC=003, TAC=30336):**
`8409357` `8409367` `8409387` `8409397` `8435480` `8666381` `8666391` `8666411`

CIDs 8666381, 8666391, 8666411 appeared immediately after the ACMA field inspection on 8 May 2026 -- consistent with post-visit device reconfiguration.

### OpenCelliD Geographic Corroboration

| CID | Location | Distance from Home | Updated |
|-----|----------|-------------------|---------|
| 137713175 | **Prendergast Avenue, CE** | **331m** | Apr 24 2026 |
| 135836191 | Collison Road, CE | 912m | Oct 2025 |
| 135836171 | Casey Fields area | 2,424m | Aug 2025 |

Movement corridor: Casey Fields (Aug 2025) -> Collison Road (Oct 2025) -> Prendergast Avenue (Apr 2026). Consistent with a mobile unit progressively closing on subject premises over 8 months.

### Cross-Carrier Simultaneous Operation

Zero-second simultaneous RRCConnectionRelease across Telstra and Vodafone confirmed (April 8, 2026 15:38:08 UTC). Architecturally impossible on srsRAN or any single-carrier platform. Harris StingRay II/HailStorm with independent Harpoon power amplifiers per carrier is the only commercial platform consistent with this signature.

### T1 Hold Timer -- Shared Harris Signature

T1 = 610.6s +/-0.55s confirmed across five independent macro connection events on both carriers. Machine-precision shared parameter = both devices managed by a single Harris RayFish Controller.

### Three-Phase Operational Timeline

| Phase | Period | T3 Timer | Interpretation |
|-------|--------|----------|----------------|
| Phase 1 | Dec 2024 - Jan 22, 2026 | 3000.4s +/-0.35s | Passive survey / baseline |
| Phase 2 | Jan 28 - May 7, 2026 | 210.2s / 40.5s | Active harvest mode |
| Phase 3 | May 8, 2026 onwards | Chaotic -- T1 unchanged at 610.6s | Post-ACMA reconfiguration |

---

## CLI Reference

```
python main.py [options]

Input:
  --file FILE, -f FILE      Input file (NDJSON, PCAP, QMDL). Repeatable.
  --dir DIR,  -d DIR        Scan directory for all supported files.

Output:
  --output FILE, -o FILE    Write JSON report to file.
  --html                    Generate interactive HTML forensic report.
  --manifest                Generate SHA-256 forensic file manifest.
  --timeline                Generate cross-session event timeline.
  --export-pcap             Export flagged events as PCAPNG.

Analysis:
  --mcc MCC                 Override MCC (505 for Australia).
  --mnc MNC                 Override MNC (001=Telstra, 003=Vodafone AU).
  --config FILE, -c FILE    Config file (default: config.yaml).
  --verbose, -v             Verbose output.

Advanced:
  --compare A.json B.json   Diff two reports to track changes over time.
  --watch                   Watch mode -- re-analyze on new files.
  --watch-interval N        Watch polling interval seconds (default: 30).
```

---

## Architecture

```
rayhunter-threat-analyzer/
├── main.py                    # Entry point
├── config.yaml                # Detection thresholds, known rogue cells
├── requirements.txt
│
├── parsers/
│   ├── ndjson_parser.py
│   ├── pcap_parser.py
│   ├── pcap_exporter.py
│   └── qmdl_parser.py
│
├── detectors/
│   ├── base.py
│   ├── identity_harvest.py
│   ├── cipher_downgrade.py
│   ├── rogue_tower.py
│   ├── rrc_periodicity.py
│   ├── handover_inject.py
│   ├── paging_anomaly.py
│   ├── paging_cycle.py
│   ├── earfcn_anomaly.py
│   ├── proximity_track.py
│   └── heuristic_scorer.py
│
├── intelligence/
│   ├── hardware_fingerprint.py
│   ├── db_engine.py
│   └── db/
│       ├── 01_au_spectrum_acma.yaml
│       ├── attacker_profiles.yaml
│       ├── attacks/
│       └── devices/
│
├── tests/
│   └── test_synthetic.py
│
└── archive/
    └── rayhunter_deep_analysis.py  # v2.4 Hello Mofo Edition -- archived
```

---

## Legal Framework (Australia)

| Finding | Applicable Law |
|---------|----------------|
| IMSI/IMEISV harvesting | Privacy Act 1988 (Cth) APP 3; Radiocommunications Act 1992 s.189 |
| Rogue base station operation | Radiocommunications Act 1992 (Cth) s.189 |
| Unauthorised interception | Telecommunications (Interception and Access) Act 1979 (Cth) |
| Unauthorised network access | Criminal Code Act 1995 (Cth) Div 477 |

---

## Background

Investigation into confirmed IMSI catcher activity at a neighbouring property in Cranbourne East, Victoria, Australia. Began late 2024, ongoing as of May 2026.

**Equipment:** 2x TP-Link M7350 running Rayhunter v0.10.2 (dual simultaneous monitoring) · Raspberry Pi 5 · bladeRF 2.0 micro xA4 · XPOL-2 5G MIMO antenna · MikroTik Chateau 5G · RTL-SDR V3 · WiFi Pineapple MK7 · Flipper Zero

**Regulatory actions on file:**
- ACMA ENQ-1851DVJH04 -- field inspection conducted 8 May 2026
- TIO 2026-03-04898
- VicPol CIRS-20260331-141 and CIRS-20260413-6
- Telstra Ref 128653446 -- confirmed unauthorised Cel-Fi G51 on network
- AFP referral -- May 2026
- Raw capture data shared with Hayley Pedersen at the Electronic Frontier Foundation
- Invited to join EFF Atlas of Surveillance project

---

## Changelog

### v3.0 -- KanyRay West Edition (22 May 2026)
- Clean rebuild from canonical GitHub base
- RogueTower dead code bug fixed -- main detection loop now executes on real data
- Intelligence database enriched: AU spectrum (ACMA), Septier, PKI device profiles added
- Null-cipher and GERAN redirect attack YAML profiles added
- 9/9 synthetic tests passing -- evidence-grade baseline established
- rayhunter_deep_analysis.py v2.4 archived

### v2.4 -- Hello Mofo Edition (16 May 2026)
- Named attacker profile for Cranbourne East persistent operator (score 11.0)
- Transmitter movement corridor analysis
- Cross-batch comparison mode
- ACMA evidence draft generation

### v2.2 (9 May 2026)
- Heuristic scorer, RRC periodicity detector, intelligence DB structure

### v2.1 (9 May 2026)
- Identity harvest, cipher downgrade, per-cell MNC attribution fixes

---

## Acknowledgements

- [EFF Rayhunter](https://github.com/EFForg/rayhunter) -- the foundation this tool is built on
- [SeaGlass](https://seaglass.cs.washington.edu/) -- University of Washington IMSI catcher detection research
- [YAICD / AIMSICD](https://github.com/AIMSICD/AIMSICD) -- Android IMSI catcher detector
- 3GPP TS 24.301, TS 33.401, TS 36.331 -- the specifications that define what normal looks like
- Tucker et al. (NDSS 2025) -- 53-message IMSI exposure taxonomy
- Dabrowski et al. (RAID 2016) -- operator-side IMSI catcher detection

---

## Contributing

Pull requests welcome. Priority areas:
- pySCAT/signalcat integration for full QMDL NAS dissection
- OpenCelliD automatic cell verification
- 5G NR (NR-RRC) support
- Additional hardware fingerprint profiles
- Multi-language support (EU regulatory frameworks)

---

## License

MIT -- see [LICENSE](LICENSE)

---

*Built with a Raspberry Pi 5, two TP-Link hotspots, a bladeRF 2.0, 3 LLMs, and a lot of late nights.*

*"I'm not saying it was IMSI catchers... but it was IMSI catchers."*

*-- Julian Burns -- Cranbourne East, VIC, Australia -- 2026*
