# Changelog

## [1.1.0] - 2026-04-17

### Added
- RRC Periodicity Detector for metronomic 210s cycle detection (srsRAN signature)
- Cross-file timeline correlation analysis
- Interactive HTML report generation
- SHA-256 forensic file manifest generator
- Flagged events PCAP exporter
- Report diff tool for tracking changes over time
- Comprehensive hardware fingerprinting (5 device types)

### Detectors
- Identity Harvest (IMSI flood detection)
- Cipher Downgrade (EEA0/EIA0 violations)
- Rogue Tower (Cell ID correlation)
- Handover Injection
- Proximity Tracking (ProSe/D2D)
- Paging Anomaly
- EARFCN Anomaly
- RRC Periodicity (metronomic cycle detection)

### Forensic Features
- Multi-format support: NDJSON, PCAP/PCAPNG, QMDL
- Cross-network correlation (Telstra + Vodafone AU confirmed)
- Legal chain-of-custody manifest generation
- 3GPP specification references in all findings
- Australian legal framework integration (ACMA, Radiocommunications Act 1992)

## [1.0.0] - 2026-04-12

Initial release - core detection engine.