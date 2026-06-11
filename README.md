# rayhunter-threat-analyzer

**Cellular surveillance detection and forensic analysis framework.**

Analyses Rayhunter output files (NDJSON, QMDL, PCAP) and CASTNET distributed detection data for IMSI catcher activity, rogue base stations, and active man-in-the-middle attacks on LTE networks.

Current version: **4.4**

---

## Usage

```powershell
# Directory scan
python main.py --dir D:\captures

# With Android bug reports for Shannon IMS baseband analysis
python main.py --dir D:\captures --bug-reports D:\BugReports

# With CASTNET observations
python main.py --dir D:\captures --castnet-obs C:\castnet\obs.json

# Full options
python main.py --dir D:\captures --html --manifest --verbose
```

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

### Hardware Discrimination
- Oscillator class fingerprinting (OCXO vs VCTCXO vs XO)
- srsRAN 2.10s beacon periodicity identification
- Band co-presence physical impossibility analysis
- Dual-device attribution and configuration fingerprinting
- Hardware lifecycle timeline via jitter DNA tracking

### Behavioral Analysis
- Operator rhythm profiling (human vs automated)
- Regulatory event correlation (before/after behavioral comparison)
- Campaign segmentation with independent scoring
- Cross-session hardware persistence tracking

### Attack Technique Detection
- IMSI harvest via Identity Request flood
- Auth Reject → Identity Request chain (Tucker et al. NDSS 2025 msg #8)
- Wallet Inspector / pre-SecurityModeCommand extraction (msg #47)
- FlashCatch sub-second capture (Paci et al. WiSec 2025)
- LTE ProSe proximity tracking (3GPP TS 36.331 §6.3.6)
- Forced handover injection (mobilityControlInfo without MeasurementReport)
- CID rotation cluster detection
- NAS entropy scoring (Shannon 1948 / SeaGlass UW 2017)
- Tucker Taxonomy IER scoring (53-message exposure taxonomy)
- C-RNTI repeat targeting and harvest chain detection

---

## Shannon IMS Baseband Log Parser

New in v4.4. Parses Android bug reports for Samsung Shannon baseband modem IMS log entries (`RILC_UNSOL_IMS_SUPPORT_SERVICE`) and cross-references them against a known rogue CID list.

**Why this matters:** This provides firmware-layer evidence completely independent of passive RF capture methodology. The modem logs which cell it registered to at the hardware layer — independently of Rayhunter, CASTNET, or any user-space tool. If passive RF capture detects a rogue cell, and separately the device's own modem firmware logged connecting to the same CID, those are two different evidence classes from two different methodologies.

**Compatible devices:** Any Android device using a Samsung Shannon-based modem. This includes the entire Google Pixel series from Pixel 6 onwards (Tensor / Exynos Modem 5300/5400) and Samsung Galaxy devices.

**What it requires:** An Android bug report (`bugreport-*.txt`) generated while the device was in range of the rogue cell. Bug reports can be generated via Android developer options or `adb bugreport`.

**What it is not:** A real-time detector. This is retrospective forensic corroboration.

```powershell
# Standalone test
python detectors\shannon_ims_parser.py path\to\bugreport.txt

# Integrated — add to config.yaml
bug_report_dir: "D:/BugReports"
```

---

## CASTNET Integration

CASTNET (Cellular Anomaly Surveillance Tracking Network) is the distributed detection component. Flask API on port 5000, communal aggregation on port 5001, live Leaflet.js map dashboard. Rayhunter nodes report detections to the aggregation server; CASTNET data feeds into the analyzer via `--castnet-obs`.

Repository: `JulianBurns85/CASTNET`

---

## Output

- Terminal report with findings ranked by severity
- JSON report (`rayhunter_report_<timestamp>.json`)
- KML forensic map (`rayhunter_forensic_map_<timestamp>.kml`) — Google Earth compatible
- Optional HTML report (`--html`)
- Optional SHA-256 forensic manifest (`--manifest`)

---

## Configuration

Edit `config.yaml` to set known rogue CIDs, OpenCelliD API key, detection thresholds, and bug report directory.

---

## Changelog

### v4.4
- `ShannonImsParser` — Samsung Shannon baseband IMS log parser for Android bug reports
- `--bug-reports` CLI flag and `bug_report_dir` config for automatic bug report scanning
- Operational profile synthesiser moved to post-detector pass — fixes zero-count bug
- Intent language audit throughout — behavioral correlations stated as "consistent with"
- Version label corrected

### v4.3
- `TargetEntropyScorer`, `RSRPDirectionalWedge`, `RealtimeAlertEngine`
- Cross-carrier timer correlation with co-presence window analysis
- Regulatory escalation scorer with behavioral response classification
- Platform Fusion Engine with hypothesis defeater scoring

### v4.1
- `CFODriftAnalyser` — oscillator class fingerprinting
- `BeaconPeriodicityScorerV2` — srsRAN 2.10s stack identification
- `SimultaneousCIDDiscriminator` — band co-presence physical impossibility analysis
- `HardwareAttributionEngineV2` — dual-device AFP-ready attribution
- `FleetDetectorModule` — AU RF signature library
- BladeRF bridge for SDR capture ingestion
- CASTNET observation JSON ingestion

---

## Applicable Legislation (AU)

- Radiocommunications Act 1992 (Cth) s.189
- Telecommunications (Interception and Access) Act 1979 (Cth)
- Criminal Code Act 1995 (Cth) Div 477
- Privacy Act 1988 (Cth)

---

## References

- Dabrowski et al. (2014) — IMSI-Catch Me If You Can
- Ziayi et al. (2021) — YAICD: Yet Another IMSI Catcher Detector
- Tucker et al. (2025) — SnoopDog: Exposing IMSI-Catcher Attacks (NDSS 2025)
- Paci et al. (2025) — FlashCatch (WiSec 2025)
- Zhuang et al. (2018) — FBSleuth (AsiaCCS 2018)
- Shannon (1948) — A Mathematical Theory of Communication
- SeaGlass (UW 2017) — Passive Measurement of IMSI-Catchers
