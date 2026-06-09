# rayhunter-threat-analyzer

**Cellular surveillance detection and forensic analysis framework.**

Analyses Rayhunter output files (NDJSON, QMDL, PCAP) and CASTNET distributed detection data for IMSI catcher activity, rogue base stations, and active man-in-the-middle attacks on LTE networks.

---

## Current Version: 4.1 — Hidden Blade: Assassins Creep

### 4.1 Changes — Hardware Discrimination Suite

Four new detectors added for dual-device identification and hardware attribution:

**`CFODriftAnalyser`** — Oscillator class fingerprinting via carrier frequency offset variance. Distinguishes OCXO-disciplined professional hardware (Harris/Septier) from VCTCXO consumer SDR platforms (BladeRF 2.0, LimeSDR) using RSRP stability as a proxy for oscillator quality. References: Ali & Fischer 2019, Zhuang et al. 2018 FBSleuth.

**`BeaconPeriodicityScorerV2`** — Software stack identification via inter-beacon interval analysis. Identifies srsRAN by its canonical 2.10s measurement reporting signature (`measurement_report_period=2000ms` default + OS scheduler jitter ~100ms). This interval is physically impossible from Harris, Septier, or Rohde & Schwarz hardware, which use dedicated FPGA timing (80ms/160ms SIB1 intervals). Stack signature database covers Harris/Septier/R&S, srsRAN, OpenLTE, OsmocomBB, YateBTS.

**`SimultaneousCIDDiscriminator`** — Band co-presence analysis proving single-chain SDR operation impossible. Identifies 60-second windows where physically incompatible frequency bands are simultaneously present (Band 28 + Band 7 = 3.71× frequency ratio; Band 28 + Band 1 = 3.0×; Band 28 + Band 3 = 2.43×). Per 3GPP TS 36.104: a single RF chain cannot simultaneously transmit on these band combinations. Co-presence requires either multi-chain professional hardware or two separate devices.

**`HardwareAttributionEngineV2`** — AFP-ready hardware attribution synthesis. Combines oscillator class, beacon periodicity, band co-presence, and behavioral analysis to produce court-ready Device A / Device B identification. Outputs specific configuration fingerprint for forensic match: `enb_id`, `tac`, `mcc`, `mnc` combination unique to each deployment.

**New intelligence:**
- `intelligence/db/hardware_id_library.yaml` — Complete manufacturer database covering Harris, Septier, Rohde & Schwarz, PKI, Phantom, Comstrac, Datong, Revector, plus consumer SDR platforms (srsRAN/BladeRF, OpenLTE, OsmocomBB, HackRF, LimeSDR, USRP).

---

## Key Findings — MAY_2026_CAPTURES (853,810 events)

```
YAICD Score:        5.00 / threshold 2.6  *** FORMAL POSITIVE DETECTION ***
Heuristics:         9/10 confirmed, 0 partial
Platform confidence: 95.0%
Hypothesis defeater: Active rogue platform 99.99%

Device A: L3Harris Technologies HailStorm II [PROBABLE]
  - 80ms/160ms SIB1 intervals (FPGA timing — impossible from consumer SDR)
  - OCXO oscillator class (RSRP std < 3 dBm during business hours)
  - Multi-band simultaneous (Bands 1+3+7+28) — requires multi-chain hardware
  - Fixed TA=7 (~547m) maintained >10 days — stationary professional installation

Device B: srsRAN eNB on general-purpose OS [CONFIRMED]
  - 2.10s inter-event intervals — exact srsRAN measurement_report_period fingerprint
  - After-hours operation profile
  - Single-band per session — consistent with single-chain SDR limitation
  - Post-gap escalation 44.5× confirming personal device resumption

Simultaneous operation: CONFIRMED
  - 166 band co-presence windows (Band 28 + Band 7/1/3)
  - Physically impossible from single RF chain
  - Two transmitters required

Corporate audit effect: ZERO
  - Device B not on any corporate asset register
  - Personal search warrant required for Device B seizure
  - Configuration fingerprint: enb_id=537942, tac=12385, mcc=505, mnc=1
```

---

## Forensic Corpus Summary

| Corpus | Events | Campaigns | IMSI Harvests | YAICD |
|---|---|---|---|---|
| Forensic Dossier (Dec 2024–Mar 2026) | 10,668,887 | 9 | 365 confirmed | 5.00 |
| MAY_2026_CAPTURES (Mar–May 2026) | 853,810 | 4 | 41 confirmed | 5.00 |
| CASTNET live (ongoing) | 4,863+ | — | — | — |

**Total confirmed attacks across full corpus:**
- Injected handovers: 1,048 (mobilityControlInfo without MeasurementReport)
- IMSI harvests: 365+ confirmed
- ProSe proximity tracking: 522 events (real-time location tracking)
- FlashCatch: confirmed (sub-second IMSI capture, Paci et al. WiSec 2025)
- Wallet Inspector: confirmed (pre-encryption IMSI extraction, Tucker et al. NDSS 2025 msg #47)
- Auth Reject → Identity Request chains: confirmed

**Peak intensity:** 2026-03-03 — 768,052 threat score (single day)
**De-escalation post-regulatory:** 435.9× reduction

---

## Detection Capabilities

### 10-Heuristic YAICD Framework
Based on Dabrowski et al. 2014 / Ziayi et al. 2021:
- 4.1.1 Off-band EARFCN
- 4.1.2 Unusual Cell ID
- 4.1.3 Unusual base station parameters
- 4.1.4 No forced 2G downgrade
- 4.1.6 EEA0 null-cipher (active MitM)
- 4.1.7 Empty/invalid neighbour list
- 4.1.8 Traffic forwarding
- 4.1.10 Changing/inconsistent LAC

### Hardware Discrimination (4.1)
- Oscillator class fingerprinting (OCXO vs VCTCXO vs XO)
- srsRAN 2.10s beacon periodicity identification
- Band co-presence physical impossibility analysis
- Dual-device attribution and configuration fingerprinting

### Behavioral Analysis
- Operator rhythm profiling (human vs automated)
- Regulatory event correlation (before/after behavioral comparison)
- Campaign segmentation with independent scoring
- Cross-session hardware persistence (jitter DNA)
- Hardware lifecycle timeline (longitudinal tracking)

### Attack Technique Detection
- IMSI harvest via Identity Request flood
- Auth Reject → Identity Request chain (Tucker et al. NDSS 2025 msg #8)
- Wallet Inspector / pre-SecurityModeCommand extraction (msg #47)
- FlashCatch sub-second capture (Paci et al. WiSec 2025)
- LTE ProSe proximity tracking (3GPP TS 36.331 §6.3.6)
- Forced handover injection
- CID rotation cluster detection
- NAS entropy scoring (Shannon 1948 / SeaGlass UW 2017)
- Tucker Taxonomy IER scoring (53-message exposure taxonomy)
- C-RNTI repeat targeting and harvest chain detection

---

## CASTNET Integration

CASTNET (Cellular Anomaly Surveillance Tracking Network) is the distributed detection component. Flask API on port 5000, communal aggregation on port 5001, live Leaflet.js map dashboard. Rayhunter nodes report detections to the aggregation server; CASTNET data feeds into the analyzer via `--castnet-obs`.

Repository: `JulianBurns85/CASTNET`

---

## Usage

```powershell
# Full corpus analysis
python main.py --dir D:\captures --gps-lat -38.1089 --gps-lon 145.3098 --output output\report.json

# With CASTNET observations
python main.py --dir D:\captures --castnet-obs C:\castnet\obs.json --output output\report.json

# Split analysis (dual device discriminators on CASTNET DB)
python split_analysis.py --castnet castnet.db --output split_report.txt

# Temporal device timeline reconstruction
python temporal_device_timeline.py --dir D:\captures --castnet castnet.db --output timeline.txt
```

---

## Legal References

AFP LEX 4864 | ACMA ENQ-1851DVJH04 | VicPol CIRS-20260331-141 | TIO 2026-03-04898

Applicable legislation: Radiocommunications Act 1992 (Cth) s.189 · Telecommunications (Interception and Access) Act 1979 (Cth) · Privacy Act 1988 (Cth) · Criminal Code Act 1995 (Cth) Div 477

---

## References

- Dabrowski et al. (2014) — IMSI-Catch Me If You Can
- Ziayi et al. (2021) — YAICD: Yet Another IMSI Catcher Detector
- Tucker et al. (2025) — SnoopDog: Exposing IMSI-Catcher Attacks (NDSS 2025)
- Paci et al. (2025) — FlashCatch (WiSec 2025)
- Zhuang et al. (2018) — FBSleuth (AsiaCCS 2018)
- Shannon (1948) — A Mathematical Theory of Communication
- SeaGlass (UW 2017) — Passive Measurement of IMSI-Catchers
