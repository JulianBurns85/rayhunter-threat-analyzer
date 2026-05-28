# --- Python 3.14 asyncio fix for pyshark ---
import asyncio
try:
    import nest_asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    nest_asyncio.apply(loop)
except ImportError:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
# --- End asyncio fix ---

# #!/usr/bin/env python3
"""
Rayhunter Threat Analyzer v3.2
Analyses Rayhunter output files (NDJSON, PCAP, QMDL) for cellular
surveillance threats: IMSI catchers, rogue towers, null-cipher attacks,
metronomic timing signatures, cross-carrier anomalies, targeted paging,
and CID rotation evasion.

Produces terminal output, JSON report, and optional HTML report.

Usage:
    python main.py --file capture.ndjson
    python main.py --dir C:\\RH\\captures --output report.json
    python main.py --dir C:\\RH\\captures --html --manifest --verbose
    python main.py --dir C:\\RH\\captures --mnc 003  # Vodafone AU

v3.2 changes:
    - PagingTargetDetector: flags devices paged at machine-precision intervals
      (~10.880s quantum confirmed from 402-event Cranbourne East dataset).
      Detects base/double/triple quantum pattern and gap analysis.
      Severity CRITICAL (>150 pages) or HIGH; confidence CONFIRMED when
      base_count >= 40 and SD < 2.0s.
    - CIDRotationDetector: flags numerically adjacent Cell IDs within the
      same TAC that rotate sequentially — confirmed rogue evasion technique
      (Harris documented operational mode).
    - config.yaml: corrected base_quantum_seconds to 10.880 (was 10.94),
      full rogue CID list including post-ACMA trio.

v2.3 changes:
    - NovelCidDetector: flags first-seen Cell IDs with <=3 observations
      and sub-10s appearance windows (transient rogue CID sweep signature)
    - EncryptedTrafficRatioDetector: surfaces sessions with anomalously
      high NAS encryption rates (>70% = Warn, >85% = High)
    - SessionOverlapCorrelator: identifies dual-carrier parallel capture
      sessions and outputs overlap windows + cross-carrier timestamp pairs
    - CrossCarrierEvidencePatcher: injects pinned timestamp pairs into
      existing cross-carrier findings for USB evidence package
    - sessions dict passed to reporter for session-level correlation
    - session_correlation block added to JSON report output

v2.2 changes:
    - HeuristicScorerDetector wired in (runs after all primary detectors)
    - RRCPeriodicityDetector added (detects 210.2s / 610.6s cycles)
    - YAICD formal score block printed to terminal
    - heuristic_analysis injected into JSON report output
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

# -- Parsers ------------------------------------------------------------------
from parsers.ndjson_parser import NdjsonParser
from parsers.pcap_parser    import PcapParser
from parsers.qmdl_parser    import QmdlParser

# -- Primary detectors --------------------------------------------------------
from detectors.identity_harvest  import IdentityHarvestDetector
from detectors.cipher_downgrade  import CipherDowngradeDetector
from detectors.rogue_tower       import RogueTowerDetector
from detectors.handover_inject   import HandoverInjectDetector
from detectors.proximity_track   import ProximityTrackDetector
from detectors.paging_anomaly    import PagingAnomalyDetector
from detectors.earfcn_anomaly    import EarfcnAnomalyDetector

# -- RRC periodicity (210.2s / 610.6s fingerprint) ---------------------------
try:
    from detectors.rrc_periodicity import RRCPeriodicityDetector
    _HAS_RRC = True
except ImportError:
    _HAS_RRC = False
    print(
        "[WARN] detectors/rrc_periodicity.py not found — "
        "RRC periodicity detection disabled."
    )

# -- v2.3 detectors -----------------------------------------------------------
try:
    from detectors.novel_cid_detector import NovelCidDetector
    _HAS_NOVEL_CID = True
except ImportError:
    _HAS_NOVEL_CID = False
    print(
        "[WARN] detectors/novel_cid_detector.py not found — "
        "Novel CID detection disabled."
    )

try:
    from detectors.encrypted_traffic_ratio_detector import (
        EncryptedTrafficRatioDetector,
    )
    _HAS_ENCRYPTED_RATIO = True
except ImportError:
    _HAS_ENCRYPTED_RATIO = False
    print(
        "[WARN] detectors/encrypted_traffic_ratio_detector.py not found — "
        "Encrypted traffic ratio detection disabled."
    )

# -- v3.2 detectors -----------------------------------------------------------
try:
    from detectors.paging_target import PagingTargetDetector
    _HAS_PAGING_TARGET = True
except ImportError:
    _HAS_PAGING_TARGET = False
    print(
        "[WARN] detectors/paging_target.py not found — "
        "Targeted paging detection disabled."
    )

try:
    from detectors.cid_rotation import CIDRotationDetector
    _HAS_CID_ROTATION = True
except ImportError:
    _HAS_CID_ROTATION = False
    print(
        "[WARN] detectors/cid_rotation.py not found — "
        "CID rotation detection disabled."
    )

# -- Post-processing ----------------------------------------------------------
from detectors.heuristic_scorer import HeuristicScorerDetector

# -- Intelligence / reporting -------------------------------------------------
from intelligence.hardware_fingerprint import HardwareFingerprinter
from reporter import ThreatReporter
import config_loader

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║  RAYHUNTER THREAT ANALYZER v3.2                              ║
║  Cellular Surveillance Detection & Forensic Analysis         ║
║  Targets: NDJSON · PCAP · QMDL                               ║
║  10-Heuristic Framework + YAICD Scoring (Ziayi et al. 2021) ║
╚══════════════════════════════════════════════════════════════╝
"""

SKIP_DIRS = {
    "windows", "system32", "syswow64", "winsxs",
    "program files", "program files (x86)", "programdata",
    "appdata", "packages", "windowsapps", "$recycle.bin",
    "system volume information", "recovery", "boot",
    "perflogs", "msocache", "intel", "amd", "nvidia",
}

# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------
def collect_files(paths: List[str], directory: str) -> Dict[str, List[str]]:
    files: Dict[str, List[str]] = {"ndjson": [], "pcap": [], "qmdl": []}
    all_paths = list(paths or [])
    if directory:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"[ERROR] Directory not found: {directory}")
            sys.exit(1)
        print(f"  Scanning: {directory}")
        for ext in ("*.ndjson", "*.pcap", "*.pcapng", "*.qmdl", "*.bin"):
            for p in dir_path.rglob(ext):
                try:
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
            print(f"[WARN] Unknown extension for {p.name}, skipping.")
    return files

# ---------------------------------------------------------------------------
# Session grouping (v2.3)
# ---------------------------------------------------------------------------
def group_events_by_session(all_events: list) -> dict:
    """
    Group flat event list into a dict of session_id -> list[event_dict].
    Uses the 'source' or 'session_id' field of each event.
    Falls back to 'unknown' if neither is present.
    """
    sessions: dict = defaultdict(list)
    for evt in all_events:
        sid = (
            evt.get("session_id")
            or evt.get("source", "unknown")
        )
        if "/" in str(sid) or "\\" in str(sid):
            sid = Path(sid).stem
        if "." in str(sid):
            sid = str(sid).rsplit(".", 1)[0]
        sessions[sid].append(evt)
    return dict(sessions)

# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------
def run_analysis(files: Dict[str, List[str]],
                 cfg: dict,
                 verbose: bool) -> dict:
    all_events: list = []

    # -- Parse ----------------------------------------------------------------
    parsers = [
        ("NDJSON", NdjsonParser(cfg), files["ndjson"]),
        ("PCAP",   PcapParser(cfg),   files["pcap"]),
        ("QMDL",   QmdlParser(cfg),   files["qmdl"]),
    ]
    for label, parser, flist in parsers:
        for f in flist:
            if verbose:
                print(f"  [{label}] Parsing {f}")
            try:
                events = parser.parse(f)
                print(f"  -> {len(events):,} events from {Path(f).name}")
                all_events.extend(events)
            except Exception as exc:
                print(f"  [WARN] Parse error in {Path(f).name}: {exc}")

    if not all_events:
        print("\n[WARN] No events extracted. Check file formats and paths.")
        return {
            "events": [], "findings": [],
            "hardware": [], "heuristics": None,
            "sessions": {},
        }

    print(f"\n  Total events: {len(all_events):,}")

    # -- v2.3: Build sessions dict --------------------------------------------
    sessions = group_events_by_session(all_events)
    if verbose:
        print(f"  [SESSION] {len(sessions)} session(s) identified: "
              f"{', '.join(sorted(sessions.keys()))}")

    # -- Primary detectors ----------------------------------------------------
    primary_detectors = [
        IdentityHarvestDetector(cfg),
        CipherDowngradeDetector(cfg),
        RogueTowerDetector(cfg),
        HandoverInjectDetector(cfg),
        ProximityTrackDetector(cfg),
        PagingAnomalyDetector(cfg),
        EarfcnAnomalyDetector(cfg),
    ]

    if _HAS_RRC:
        primary_detectors.append(RRCPeriodicityDetector(cfg))

    # v2.3 detectors
    if _HAS_NOVEL_CID:
        primary_detectors.append(NovelCidDetector(cfg))
    if _HAS_ENCRYPTED_RATIO:
        primary_detectors.append(EncryptedTrafficRatioDetector(cfg))

    # v3.2 detectors
    if _HAS_PAGING_TARGET:
        primary_detectors.append(PagingTargetDetector(cfg))
    if _HAS_CID_ROTATION:
        primary_detectors.append(CIDRotationDetector(cfg))

    all_findings: list = []
    for detector in primary_detectors:
        if verbose:
            print(f"  [DETECT] Running {detector.name}...")
        try:
            findings = detector.analyze(all_events)
            if findings:
                print(f"  -> {len(findings)} finding(s): {detector.name}")
            all_findings.extend(findings)
        except Exception as exc:
            print(f"  [WARN] {detector.name} error: {exc}")

    # -- Hardware fingerprinting ----------------------------------------------
    try:
        fp = HardwareFingerprinter(
            cfg.get("intelligence", {}).get("db_path", "intelligence/db"),
            cfg=cfg,
        )
        fingerprints = fp.analyze(all_events, all_findings)
        if fingerprints:
            print(f"  [HWFP] {len(fingerprints)} hardware candidate(s) identified")
    except Exception as exc:
        print(f"  [WARN] HardwareFingerprinter error: {exc}")
        fingerprints = []

    # -- Heuristic scorer (post-processing) -----------------------------------
    print()
    print("  Running 10-Heuristic IMSI Catcher Detection Framework...")
    try:
        hscorer = HeuristicScorerDetector(cfg)
        heuristic_result = hscorer.analyze(all_events, all_findings)
        print(f"  [HEURISTIC] {heuristic_result.summary}")
        if verbose:
            for h in heuristic_result.heuristics:
                icon = {
                    "CONFIRMED":      "[+]",
                    "PARTIAL":        "[~]",
                    "NOT_DETECTED":   "[ ]",
                    "NOT_APPLICABLE": "[N/A]",
                }.get(h.status, "[?]")
                print(f"    {icon} {h.heuristic_id} {h.label}: {h.status}")
    except Exception as exc:
        print(f"  [WARN] HeuristicScorerDetector error: {exc}")
        heuristic_result = None

    return {
        "events":    all_events,
        "findings":  all_findings,
        "hardware":  fingerprints,
        "heuristics": heuristic_result,
        "sessions":  sessions,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="Rayhunter Threat Analyzer v3.2"
    )
    ap.add_argument("--file", "-f", action="append", metavar="FILE",
                    help="Input file. Repeatable.")
    ap.add_argument("--dir", "-d", metavar="DIR",
                    help="Directory to scan recursively.")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="Write JSON report to FILE.")
    ap.add_argument("--format",
                    choices=["terminal", "json", "both"], default="both",
                    help="Output format (default: both).")
    ap.add_argument("--config", "-c", metavar="FILE", default="config.yaml",
                    help="Config file (default: config.yaml).")
    ap.add_argument("--mcc", type=str, help="Override MCC (e.g. 505).")
    ap.add_argument("--mnc", type=str,
                    help="Override MNC (001=Telstra AU, 003=Vodafone AU).")
    ap.add_argument("--no-opencellid", action="store_true",
                    help="Disable OpenCelliD lookups (offline mode).")
    ap.add_argument("--manifest", action="store_true",
                    help="Generate SHA-256 forensic file manifest.")
    ap.add_argument("--html", action="store_true",
                    help="Generate interactive HTML report.")
    ap.add_argument("--timeline", action="store_true",
                    help="Generate cross-session event timeline.")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose — show per-heuristic status.")
    args = ap.parse_args()

    if not args.file and not args.dir:
        ap.print_help()
        sys.exit(1)

    # Load config
    cfg = config_loader.load(args.config)
    if args.mcc:
        cfg["network"]["mcc"] = args.mcc
    if args.mnc:
        cfg["network"]["mnc"] = args.mnc
    if args.no_opencellid:
        cfg["opencellid"]["enabled"] = False

    # Status block
    print(f"  Network:    MCC={cfg['network']['mcc']} "
          f"MNC={cfg['network']['mnc']}")
    print(f"  OpenCelliD: "
          f"{'enabled' if cfg['opencellid']['enabled'] else 'OFFLINE'}")
    print(f"  RRC Detector:           {'enabled (210.2s + 610.6s)' if _HAS_RRC else 'MISSING'}")
    print(f"  Novel CID Detector:     {'enabled' if _HAS_NOVEL_CID else 'MISSING'}")
    print(f"  Encrypted Ratio Detector: {'enabled' if _HAS_ENCRYPTED_RATIO else 'MISSING'}")
    print(f"  Paging Target Detector: {'enabled' if _HAS_PAGING_TARGET else 'MISSING'}")
    print(f"  CID Rotation Detector:  {'enabled' if _HAS_CID_ROTATION else 'MISSING'}")
    print()

    # Collect files
    files = collect_files(args.file or [], args.dir or "")
    total = sum(len(v) for v in files.values())
    if total == 0:
        print("[ERROR] No valid files found.")
        sys.exit(1)

    print(f"  Files queued: "
          f"{len(files['ndjson'])} NDJSON | "
          f"{len(files['pcap'])} PCAP | "
          f"{len(files['qmdl'])} QMDL\n")

    print("##" + "-" * 62)
    print("## PHASE 1 -- PARSING & DETECTION")
    print("##" + "-" * 62)

    start = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    print()
    print("-" * 64)
    print("PHASE 2 -- REPORTING")
    print("-" * 64)

    reporter = ThreatReporter(cfg)
    report   = reporter.build_report(results, elapsed)

    # Inject heuristic result into JSON report
    hr = results.get("heuristics")
    if hr:
        report["heuristic_analysis"] = hr.to_dict()

    # Terminal output
    if args.format in ("terminal", "both"):
        reporter.print_terminal(report)

        # YAICD summary block
        if hr:
            confirmed = [h for h in hr.heuristics if h.status == "CONFIRMED"]
            partial   = [h for h in hr.heuristics if h.status == "PARTIAL"]
            print()
            print("=" * 64)
            print("# YAICD FORMAL DETECTION SCORE (Ziayi et al. 2021)")
            print("#" + "=" * 63)
            print(f"#   Confirmed heuristics : {hr.confirmed_count}")
            print(f"  Partial heuristics   : {hr.partial_count}")
            print(f"  YAICD score          : {hr.yaicd_formal_score:.2f} "
                  f"(threshold: 2.6)")
            print(f"  Triggered params     : "
                  f"{', '.join(hr.triggered_params) or 'none'}")
            verdict = (
                "*** FORMAL POSITIVE DETECTION ***"
                if hr.yaicd_detected else "Below threshold"
            )
            print(f"  Verdict              : {verdict}")
            print(f"  Severity             : {hr.severity}")
            if confirmed:
                print()
                print("  Confirmed indicators:")
                for h in confirmed:
                    print(f"    [+] {h.heuristic_id} {h.label}")
            if partial:
                print("  Partial indicators:")
                for h in partial:
                    print(f"    [~] {h.heuristic_id} {h.label}")
            print("=" * 64)

    # JSON output
    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {args.output}")
        else:
            out_path = f"rayhunter_report_{int(time.time())}.json"
            Path(out_path).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {out_path}")

    # Optional HTML report
    if args.html:
        try:
            from html_reporter_v2 import HTMLReporterV2
            html_path = (
                Path(args.output).with_suffix(".html")
                if args.output
                else Path(f"rayhunter_report_{int(time.time())}.html")
            )
            HTMLReporterV2(cfg).generate(report, str(html_path))
            print(f"[OK] HTML report saved to: {html_path}")
        except ImportError:
            print("[WARN] html_reporter_v2.py not found — HTML skipped.")

    # Optional forensic manifest
    if args.manifest:
        try:
            from manifest_generator import ManifestGenerator
            manifest_files = (
                files["ndjson"] + files["pcap"] + files["qmdl"]
            )
            ManifestGenerator(cfg).generate(manifest_files)
            print("[OK] SHA-256 forensic manifest generated.")
        except ImportError:
            print("[WARN] manifest_generator.py not found — manifest skipped.")

if __name__ == "__main__":
    main()
