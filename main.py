#!/usr/bin/env python3
"""
Rayhunter Threat Analyzer
=========================
Analyzes Rayhunter output files (NDJSON, PCAP, QMDL) for cellular surveillance
threats, IMSI catchers, rogue towers, null-cipher attacks, and related anomalies.

Usage:
    python main.py --file capture.ndjson
    python main.py --dir /path/to/rayhunter/output
    python main.py --file capture.pcap --file capture2.ndjson
    python main.py --dir ./captures --output report.json --format json
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from typing import List

from parsers.ndjson_parser import NdjsonParser
from parsers.pcap_parser import PcapParser
from parsers.qmdl_parser import QmdlParser
from detectors.identity_harvest import IdentityHarvestDetector
from detectors.cipher_downgrade import CipherDowngradeDetector
from detectors.rogue_tower import RogueTowerDetector
from detectors.handover_inject import HandoverInjectDetector
from detectors.proximity_track import ProximityTrackDetector
from detectors.paging_anomaly import PagingAnomalyDetector
from detectors.earfcn_anomaly import EarfcnAnomalyDetector
from intelligence.hardware_fingerprint import HardwareFingerprinter
from reporter import ThreatReporter
import config_loader


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          RAYHUNTER THREAT ANALYZER  v1.0                     ║
║   Cellular Surveillance Detection & Forensic Analysis        ║
║   Targets: NDJSON · PCAP · QMDL                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# Directories to skip during C:\ recursive scan
SKIP_DIRS = {
    "windows", "system32", "syswow64", "winsxs", "winside",
    "program files", "program files (x86)", "programdata",
    "appdata", "packages", "windowsapps", "$recycle.bin",
    "system volume information", "recovery", "boot",
    "perflogs", "msocache", "intel", "amd", "nvidia",
}


def collect_files(paths: List[str], directory: str) -> dict:
    """Collect and categorise input files by type."""
    files = {"ndjson": [], "pcap": [], "qmdl": []}

    all_paths = list(paths or [])
    if directory:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"[ERROR] Directory not found: {directory}")
            sys.exit(1)

        print(f"  Scanning {directory} (skipping system directories)...")
        for ext in ("*.ndjson", "*.pcap", "*.pcapng", "*.qmdl", "*.bin"):
            for p in dir_path.rglob(ext):
                try:
                    # Skip system/application directories
                    parts_lower = {part.lower() for part in p.parts}
                    if parts_lower & SKIP_DIRS:
                        continue
                    all_paths.append(str(p))
                except (PermissionError, OSError):
                    continue

    for path in all_paths:
        p = Path(path)
        if not p.exists():
            print(f"[WARN] File not found, skipping: {path}")
            continue
        ext = p.suffix.lower()
        if ext == ".ndjson":
            files["ndjson"].append(str(p))
        elif ext in (".pcap", ".pcapng"):
            files["pcap"].append(str(p))
        elif ext in (".qmdl", ".bin"):
            files["qmdl"].append(str(p))
        else:
            # Try to detect by content
            print(f"[WARN] Unknown extension for {p.name}, skipping.")

    return files


def run_analysis(files: dict, cfg: dict, verbose: bool) -> dict:
    """Run all parsers and detectors, return aggregated events + findings."""
    all_events = []

    # ── Parse NDJSON ──────────────────────────────────────────────────
    if files["ndjson"]:
        parser = NdjsonParser(cfg)
        for f in files["ndjson"]:
            if verbose:
                print(f"  [NDJSON] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    # ── Parse PCAP ────────────────────────────────────────────────────
    if files["pcap"]:
        parser = PcapParser(cfg)
        for f in files["pcap"]:
            if verbose:
                print(f"  [PCAP] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    # ── Parse QMDL ────────────────────────────────────────────────────
    if files["qmdl"]:
        parser = QmdlParser(cfg)
        for f in files["qmdl"]:
            if verbose:
                print(f"  [QMDL] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    if not all_events:
        print("\n[WARN] No events extracted. Check file formats and paths.")
        return {"events": [], "findings": []}

    print(f"\n  Total events: {len(all_events)}")

    # ── Run Detectors ─────────────────────────────────────────────────
    detectors = [
        IdentityHarvestDetector(cfg),
        CipherDowngradeDetector(cfg),
        RogueTowerDetector(cfg),
        HandoverInjectDetector(cfg),
        ProximityTrackDetector(cfg),
        PagingAnomalyDetector(cfg),
        EarfcnAnomalyDetector(cfg),
    ]

    all_findings = []
    for detector in detectors:
        if verbose:
            print(f"  [DETECT] Running {detector.name}...")
        findings = detector.analyze(all_events)
        if findings:
            print(f"    → {len(findings)} finding(s): {detector.name}")
        all_findings.extend(findings)

    # ── Hardware Fingerprinting ───────────────────────────────────────
    fingerprinter = HardwareFingerprinter(cfg.get("intelligence", {}).get("db_path", "intelligence/db"))
    fingerprints = fingerprinter.analyze(all_events, all_findings)
    if fingerprints:
        print(f"  [HWFP] {len(fingerprints)} hardware candidate(s) identified")

    return {
        "events": all_events,
        "findings": all_findings,
        "hardware": fingerprints,
    }


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Rayhunter Threat Analyzer — cellular surveillance detection"
    )
    parser.add_argument(
        "--file", "-f",
        action="append",
        metavar="FILE",
        help="Input file (NDJSON, PCAP, or QMDL). Repeatable.",
    )
    parser.add_argument(
        "--dir", "-d",
        metavar="DIR",
        help="Directory to scan recursively for all supported files.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON report to file (default: print to terminal).",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "both"],
        default="both",
        help="Output format (default: both).",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        default="config.yaml",
        help="Config file path (default: config.yaml).",
    )
    parser.add_argument(
        "--mcc", type=str, help="Override MCC (e.g. 505)"
    )
    parser.add_argument(
        "--mnc", type=str, help="Override MNC (e.g. 001 for Telstra, 003 for Vodafone AU)"
    )
    parser.add_argument(
        "--no-opencellid",
        action="store_true",
        help="Disable OpenCelliD lookups (offline mode).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output.",
    )

    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────
    cfg = config_loader.load(args.config)
    if args.mcc:
        cfg["network"]["mcc"] = args.mcc
    if args.mnc:
        cfg["network"]["mnc"] = args.mnc
    if args.no_opencellid:
        cfg["opencellid"]["enabled"] = False

    print(f"  Network: MCC={cfg['network']['mcc']} MNC={cfg['network']['mnc']}")
    print(f"  OpenCelliD: {'enabled' if cfg['opencellid']['enabled'] else 'OFFLINE'}")
    print()

    # ── Collect files ─────────────────────────────────────────────────
    files = collect_files(args.file, args.dir)
    total = sum(len(v) for v in files.values())
    if total == 0:
        print("[ERROR] No valid files found.")
        sys.exit(1)

    print(f"Files queued: {files['ndjson']} NDJSON | "
          f"{len(files['pcap'])} PCAP | {len(files['qmdl'])} QMDL\n")
    print("─" * 62)
    print("PHASE 1 — PARSING")
    print("─" * 62)

    start = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    print()
    print("─" * 62)
    print("PHASE 2 — REPORTING")
    print("─" * 62)

    reporter = ThreatReporter(cfg)
    report = reporter.build_report(results, elapsed)

    if args.format in ("terminal", "both"):
        reporter.print_terminal(report)

    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_out)
            print(f"\n[✓] JSON report saved to: {args.output}")
        else:
            out_path = f"rayhunter_report_{int(time.time())}.json"
            Path(out_path).write_text(json_out)
            print(f"\n[✓] JSON report saved to: {out_path}")


if __name__ == "__main__":
    main()#!/usr/bin/env python3
"""
Rayhunter Threat Analyzer
=========================
Analyzes Rayhunter output files (NDJSON, PCAP, QMDL) for cellular surveillance
threats, IMSI catchers, rogue towers, null-cipher attacks, and related anomalies.

Usage:
    python main.py --file capture.ndjson
    python main.py --dir /path/to/rayhunter/output
    python main.py --file capture.pcap --file capture2.ndjson
    python main.py --dir ./captures --output report.json --format json
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from typing import List

from parsers.ndjson_parser import NdjsonParser
from parsers.pcap_parser import PcapParser
from parsers.qmdl_parser import QmdlParser
from detectors.identity_harvest import IdentityHarvestDetector
from detectors.cipher_downgrade import CipherDowngradeDetector
from detectors.rogue_tower import RogueTowerDetector
from detectors.handover_inject import HandoverInjectDetector
from detectors.proximity_track import ProximityTrackDetector
from detectors.paging_anomaly import PagingAnomalyDetector
from detectors.earfcn_anomaly import EarfcnAnomalyDetector
from intelligence.hardware_fingerprint import HardwareFingerprinter
from reporter import ThreatReporter
import config_loader


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          RAYHUNTER THREAT ANALYZER  v1.0                     ║
║   Cellular Surveillance Detection & Forensic Analysis        ║
║   Targets: NDJSON · PCAP · QMDL                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# Directories to skip during C:\ recursive scan
SKIP_DIRS = {
    "windows", "system32", "syswow64", "winsxs", "winside",
    "program files", "program files (x86)", "programdata",
    "appdata", "packages", "windowsapps", "$recycle.bin",
    "system volume information", "recovery", "boot",
    "perflogs", "msocache", "intel", "amd", "nvidia",
}


def collect_files(paths: List[str], directory: str) -> dict:
    """Collect and categorise input files by type."""
    files = {"ndjson": [], "pcap": [], "qmdl": []}

    all_paths = list(paths or [])
    if directory:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"[ERROR] Directory not found: {directory}")
            sys.exit(1)

        print(f"  Scanning {directory} (skipping system directories)...")
        for ext in ("*.ndjson", "*.pcap", "*.pcapng", "*.qmdl", "*.bin"):
            for p in dir_path.rglob(ext):
                try:
                    # Skip system/application directories
                    parts_lower = {part.lower() for part in p.parts}
                    if parts_lower & SKIP_DIRS:
                        continue
                    all_paths.append(str(p))
                except (PermissionError, OSError):
                    continue

    for path in all_paths:
        p = Path(path)
        if not p.exists():
            print(f"[WARN] File not found, skipping: {path}")
            continue
        ext = p.suffix.lower()
        if ext == ".ndjson":
            files["ndjson"].append(str(p))
        elif ext in (".pcap", ".pcapng"):
            files["pcap"].append(str(p))
        elif ext in (".qmdl", ".bin"):
            files["qmdl"].append(str(p))
        else:
            # Try to detect by content
            print(f"[WARN] Unknown extension for {p.name}, skipping.")

    return files


def run_analysis(files: dict, cfg: dict, verbose: bool) -> dict:
    """Run all parsers and detectors, return aggregated events + findings."""
    all_events = []

    # ── Parse NDJSON ──────────────────────────────────────────────────
    if files["ndjson"]:
        parser = NdjsonParser(cfg)
        for f in files["ndjson"]:
            if verbose:
                print(f"  [NDJSON] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    # ── Parse PCAP ────────────────────────────────────────────────────
    if files["pcap"]:
        parser = PcapParser(cfg)
        for f in files["pcap"]:
            if verbose:
                print(f"  [PCAP] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    # ── Parse QMDL ────────────────────────────────────────────────────
    if files["qmdl"]:
        parser = QmdlParser(cfg)
        for f in files["qmdl"]:
            if verbose:
                print(f"  [QMDL] Parsing {f}")
            events = parser.parse(f)
            print(f"    → {len(events)} events extracted from {Path(f).name}")
            all_events.extend(events)

    if not all_events:
        print("\n[WARN] No events extracted. Check file formats and paths.")
        return {"events": [], "findings": []}

    print(f"\n  Total events: {len(all_events)}")

    # ── Run Detectors ─────────────────────────────────────────────────
    detectors = [
        IdentityHarvestDetector(cfg),
        CipherDowngradeDetector(cfg),
        RogueTowerDetector(cfg),
        HandoverInjectDetector(cfg),
        ProximityTrackDetector(cfg),
        PagingAnomalyDetector(cfg),
        EarfcnAnomalyDetector(cfg),
    ]

    all_findings = []
    for detector in detectors:
        if verbose:
            print(f"  [DETECT] Running {detector.name}...")
        findings = detector.analyze(all_events)
        if findings:
            print(f"    → {len(findings)} finding(s): {detector.name}")
        all_findings.extend(findings)

    # ── Hardware Fingerprinting ───────────────────────────────────────
    fingerprinter = HardwareFingerprinter(cfg.get("intelligence", {}).get("db_path", "intelligence/db"))
    fingerprints = fingerprinter.analyze(all_events, all_findings)
    if fingerprints:
        print(f"  [HWFP] {len(fingerprints)} hardware candidate(s) identified")

    return {
        "events": all_events,
        "findings": all_findings,
        "hardware": fingerprints,
    }


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Rayhunter Threat Analyzer — cellular surveillance detection"
    )
    parser.add_argument(
        "--file", "-f",
        action="append",
        metavar="FILE",
        help="Input file (NDJSON, PCAP, or QMDL). Repeatable.",
    )
    parser.add_argument(
        "--dir", "-d",
        metavar="DIR",
        help="Directory to scan recursively for all supported files.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON report to file (default: print to terminal).",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "both"],
        default="both",
        help="Output format (default: both).",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        default="config.yaml",
        help="Config file path (default: config.yaml).",
    )
    parser.add_argument(
        "--mcc", type=str, help="Override MCC (e.g. 505)"
    )
    parser.add_argument(
        "--mnc", type=str, help="Override MNC (e.g. 001 for Telstra, 003 for Vodafone AU)"
    )
    parser.add_argument(
        "--no-opencellid",
        action="store_true",
        help="Disable OpenCelliD lookups (offline mode).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output.",
    )

    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────
    cfg = config_loader.load(args.config)
    if args.mcc:
        cfg["network"]["mcc"] = args.mcc
    if args.mnc:
        cfg["network"]["mnc"] = args.mnc
    if args.no_opencellid:
        cfg["opencellid"]["enabled"] = False

    print(f"  Network: MCC={cfg['network']['mcc']} MNC={cfg['network']['mnc']}")
    print(f"  OpenCelliD: {'enabled' if cfg['opencellid']['enabled'] else 'OFFLINE'}")
    print()

    # ── Collect files ─────────────────────────────────────────────────
    files = collect_files(args.file, args.dir)
    total = sum(len(v) for v in files.values())
    if total == 0:
        print("[ERROR] No valid files found.")
        sys.exit(1)

    print(f"Files queued: {files['ndjson']} NDJSON | "
          f"{len(files['pcap'])} PCAP | {len(files['qmdl'])} QMDL\n")
    print("─" * 62)
    print("PHASE 1 — PARSING")
    print("─" * 62)

    start = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    print()
    print("─" * 62)
    print("PHASE 2 — REPORTING")
    print("─" * 62)

    reporter = ThreatReporter(cfg)
    report = reporter.build_report(results, elapsed)

    if args.format in ("terminal", "both"):
        reporter.print_terminal(report)

    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_out)
            print(f"\n[✓] JSON report saved to: {args.output}")
        else:
            out_path = f"rayhunter_report_{int(time.time())}.json"
            Path(out_path).write_text(json_out)
            print(f"\n[✓] JSON report saved to: {out_path}")


if __name__ == "__main__":
    main()