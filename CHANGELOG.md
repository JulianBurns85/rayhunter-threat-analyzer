# Changelog

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
