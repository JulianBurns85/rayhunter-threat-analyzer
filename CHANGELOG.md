# Changelog

## [3.4.0] - 2026-06-01

### Added
- `OperatorRhythmProfiler` — Human behavioral attribution via temporal analysis. Extracts operator work schedule, sleep window, lunch patterns, day-of-week bias, timezone inference, and post-ACMA behavioral shift from event corpus. First open-source IMSI catcher detector to perform chronological human attribution.
- `WalletInspectorDetector` — Detects pre-SecurityModeCommand IMSI extraction (Tucker et al. NDSS 2025 msg #47). Invisible to standard null-cipher detectors. Catches IMSI theft before any encryption is negotiated.
- `RRCJitterProfiler` — Microsecond timing jitter analysis. Extracts hardware temporal DNA from RRC release interval variance. Signature survives CID rotation, frequency changes, and firmware reconfiguration. Duplicate suppression via signature key deduplication.
- `NeighbourListAuditor` — Audits SIB3/SIB4/SIB5 neighbour cell lists. Promotes YAICD 4.1.7 from PARTIAL to CONFIRMED. Detects empty neighbour lists on handover-issuing cells (3GPP violation) and rogue CIDs in advertised neighbour entries.

### Changed
- YAICD 4.1.7 now reliably CONFIRMED (was PARTIAL) — 8/10 heuristics confirmed on MAY_2026_CAPTURES
- Version banner updated to v3.4.0


## [3.3.2] - 2026-06-01

### Added
- `manifest_generator.py` — SHA-256 + MD5 forensic evidence manifest generator. Run with `--manifest` flag. Produces JSON and human-readable text chain-of-custody manifest for all input files. Required for AFP/court submission.
- SHA-256 deduplication in `collect_files()` — files with identical content are deduplicated by hash before processing. Reports count of dropped duplicates via `[DEDUP]` header line. Eliminates event count inflation from duplicate files across subdirectories.

### Fixed
- OpenCelliD integration fully operational. `config.yaml` `enabled` key now correctly parsed. API key `pk.edc03d962e6813e3a05fc21f1030fddd` active. All runs now show `OpenCelliD: enabled` in header.
- SCAT pipeline timeout handling — graceful fallback to raw DIAG frame scan on large QMDLs confirmed working.
- HandoverInject target cell extraction — `targetPCI`, `target_earfcn`, `t304`, `new_rnti` fields extracted from tshark output. All injected handovers now show full target cell profile.
- Reporter rendering — all 7 finding types render complete Technique/Spec/Hardware/Evidence/Action blocks.
- EEA0 false positive correction in `ndjson_parser.py` and `pcap_parser.py`.
- Attacker profile discriminator correctly identifies Law Enforcement Full Traffic Intercept (MitM Mode).
- Cross-carrier simultaneous release moved to incompatible in srsRAN profile.

### Changed
- Parallel QMDL processor reduced to 2 workers (from 4) to prevent OOM on large corpora (93GB+).
- README updated to How You Like Me Now Edition with v3.3.2 changelog badge.


## [2.1.4] - 2026-05-03

### Fixed
- `HardwareFingerprinter.analyze()` bridge method added — resolves `AttributeError` crash in main pipeline
- Hardware candidate output keys unified (`hardware`, `confidence`, `severity`, `notes`) to match reporter expectations
- `_metadata_from_findings()` correctly extracts PLMN, Cell IDs, and cycle intervals from detector findings

### Added
- Full QMDL HDLC frame decode with proper byte-unstuffing
- NAS ESM bearer context extraction (APN, DNS, IPv6 prefix recovery)
- pySCAT/signalcat integration (requires: `pip install git+https://github.com/fgsect/scat.git`)
- Boot-relative PCAP timestamp correction (anchors epoch-zero timestamps to file mtime)

## [2.1.0] - 2026-05-01

### Added
- Full C:\ recursive scan support via `--dir`
- pyshark async event loop compatibility (graceful fallback to raw frame scan)
- Duplicate file detection by SHA-256 hash
- 750 IMSI/120s threshold confirmed against full dataset (40M+ events)
- 18-cell registry with anomalous TAC 53360 flagging

## [1.1.0] - 2026-04-17

### Added
- RRC Periodicity Detector — metronomic 210.2s cycle (srsRAN hardware fingerprint)
- Cross-file timeline correlation
- Interactive HTML report generation
- SHA-256 forensic file manifest (JSON + CSV)
- Flagged events PCAP exporter
- Report diff tool
- Hardware fingerprinting engine (5 device profiles)

### Detectors
- IdentityHarvestDetector
- CipherDowngradeDetector
- RogueTowerDetector
- HandoverInjectDetector
- ProximityTrackDetector
- PagingAnomalyDetector
- EARFCNAnomalyDetector
- RRCPeriodicityDetector

## [1.0.0] - 2026-04-12

Initial release — core detection engine.
## [3.3.1] - 2026-05-29

### Fixed
- Replaced pyshark with tshark subprocess parser (pyshark incompatible with Python 3.14 asyncio)
- Fixed tshark field names: lte-rrc.* fields require hyphens not underscores
- Fixed invalid field names: reportProximityConfig_r9_element, geran_element
- Reporter: added label/message fallback for findings missing title/description fields

### Added
- Dual parser: tshark primary + _parse_basic NAS byte-scan supplement
- HandoverInjectDetector: forced handover injection via mobilityControlInfo without MeasurementReport
- ProSe proximity tracking detection via reportProximityConfig-r9
- P_handover_inject scoring parameter added to YAICD framework

### Changed
- PCAP events: 13,831 -> 27,280 on May 27 dataset (+13,449)
- Mar19 dossier: 10,825,118 total events confirmed
- YAICD 3.00 FORMAL POSITIVE DETECTION confirmed on both datasets

### Cross-Dataset Confirmation
- CID=135836191 confirmed in Mar19 (2026-03-03) AND May27 (2026-05-23)
- 89 injected handovers across 358h window in Mar19 dossier
- 88 ProSe proximity tracking events in Mar19 dossier
