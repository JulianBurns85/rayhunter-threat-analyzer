# Rayhunter Threat Analyzer — Changelog

## v2.1 — Session 7 (2026-05-03)

### Intelligence Database — Major Expansion
- **9 new YAML files** added to `intelligence/db/references/`
- `04_tucker_marlin_2025.yaml` — Full Tucker et al. NDSS 2025 methodology
  - All 53 IMSI-exposing messages across 2G/3G/4G/5G-NSA (Table III)
  - Empirically validated thresholds: <3% LTE, <6% GSM from 400+ capture hours
  - Open-source tool protocol signatures (YateBTS/OpenBTS/srsRAN)
  - Commercial device court-event signature (Attach Reject dominant)
- `05_eff_imsi_catcher_guide.yaml` — EFF 2019 attack taxonomy
- `06_yaicd_gsm_detection_parameters.yaml` — YAICD 15-parameter GSM framework
  - Rayhunter coverage assessment: 73% of parameters covered
  - Enhancement roadmap for 4 uncovered parameters
- `07_seaglass_signatures.yaml` — SeaGlass signature classes + SeaTac anomalies
- `08_nr_scope_5g_telemetry.yaml` — 5G SA future detection roadmap
- `09_ransacked_core_fuzzing.yaml` — RAN-core vulnerability context (93 CVEs)
- `10_imsi_catcher_impact_4g_5g.yaml` — Impact taxonomy
- `11_detection_thresholds_master.yaml` — Master empirically-validated thresholds
- `12_julian_burns_field_captures.yaml` — Field evidence canonical reference

### Intelligence Database — Updates
- `03_harris_drt_state.yaml` — Major expansion from newly processed ITAR documents:
  - Arrowhead 1.0.1: explicit Band 28 uplink DF (703–748 MHz) confirmed
  - HailStorm Slice auto-recovery 15-min gap signature
  - UMTS Survey Uplink Measurements per-platform defaults
  - iDEN 2.4: 700/800 Harpoon support — Band 28 Australian LTE PA confirmed
  - HailStorm external GPS requirement — physical field indicator
  - Verbatim Harris iDEN Manual §1-11 LAI attack description (primary source)
  - Verbatim forced-power transmission (MS DF mode) confirmation
  - Cell ID operator-configurable 0–65535 — cross-carrier overlap explanation
  - TMSI captured but NOT matched (QSG §1-9) — mass logging confirmed
  - LTE Redirect MS DF status machine (Searching→Connected→Lost-Repaging)
  - IMEI 'rarely broadcast' in LTE — manufacturer's own admission

### Package Structure
- Reorganised into proper Python package layout:
  `parsers/`, `detectors/`, `intelligence/`, `intelligence/db/{attacks,devices,profiles,references}/`
- All `__init__.py` files added for proper module resolution

---

## v2.0 — Session 6

### New Features
- Full IntelligenceDB engine (`db_engine.py`)
- Hardware fingerprinting with device attribution scoring
- IMSI Exposure Ratio calculation (Tucker et al. methodology)
- HTML timeline reports (`html_reporter_v2.py`)
- Operator assessment panel with danger score 0–10
- Attacker profile matching
- Manifest generator with SHA-256 chain of custody
- Report differ (`report_differ.py`)
- Watch mode (`watcher.py`)
- Timeline correlator (`timeline_correlator.py`)

### Intelligence Database
- Initial 19 YAML files across attacks, devices, profiles
- 13 device entries: srsRAN, YateBTS, OsmocomBB, PKI 1625/1650/1540,
  Harris StingRay/HailStorm/KingFish, DRT Dirtbox, Septier, Revector UAV
- 5 attacker profiles

---

## v1.0 — Initial Release

- Core detectors: identity_harvest, cipher_downgrade, rogue_tower,
  handover_inject, proximity_track, paging_anomaly, earfcn_anomaly
- NDJSON, PCAP, QMDL parsers
- Basic terminal and JSON reporting
- RRC periodicity detector (210.2s signature)
