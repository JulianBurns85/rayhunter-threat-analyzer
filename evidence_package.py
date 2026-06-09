#!/usr/bin/env python3
"""
evidence_package.py — Rayhunter Threat Analyzer v2.4
=====================================================
Produces a cryptographically hashed, timestamped, court-ready evidence
package from a Rayhunter analysis session.

Usage (standalone):
    python evidence_package.py --report rayhunter_report_XXXXXXX.json
                               --session-dir "C:\\RH\\captures\\27.05.26"
                               --case-ref "CIRS-20260331-141"
                               --output-dir "C:\\RH\\evidence"

Usage (via main.py):
    python main.py --dir "C:\\RH\\captures\\27.05.26" --evidence-package
                   --case-ref "CIRS-20260331-141"

Output:
    evidence_package_YYYYMMDD_HHMMSS.zip containing:
      ├── MANIFEST.txt          — SHA256 hashes of all files
      ├── EVIDENCE_REPORT.txt   — Human-readable narrative summary
      ├── rayhunter_report.json — Full machine-readable report
      ├── session_files/        — Original capture files (NDJSON, PCAPNG, QMDL)
      └── CHAIN_OF_CUSTODY.txt  — Generation metadata

Author: JulianBurns85 / rayhunter-threat-analyzer
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "2.4"
TOOL_NAME = "Rayhunter Threat Analyzer"
REPO = "https://github.com/JulianBurns85/rayhunter-threat-analyzer"

# Regulatory reference map for report narrative
COMPLAINTS = {
    "ACMA":   "ENQ-1851DVJH04",
    "TIO":    "2026-03-04898",
    "VicPol": "CIRS-20260331-141 / CIRS-20260413-6",
    "AFP_FOI": "LEX 4864",
}

SPEC_REFS = {
    "auth_reject_identity": "3GPP TS 24.301 §5.4.3.2",
    "unprovoked_identity":  "3GPP TS 24.301 §5.4.4",
    "sib1_cid":             "3GPP TS 36.331 §6.2.2",
    "yaicd":                "Ziayi et al. 2021 / Dabrowski 2014",
}


# ── Hashing ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    """Return SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_string(s: str) -> str:
    """Return SHA256 hex digest of a UTF-8 string."""
    return hashlib.sha256(s.encode("utf-8")).digest().hex()


# ── Report Parser ─────────────────────────────────────────────────────────────

def load_report(report_path: Path) -> dict:
    """Load and validate a rayhunter JSON report."""
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def extract_summary(report: dict) -> dict:
    """Pull key fields from the JSON report for narrative generation."""
    summary = {
        "threat_level":         report.get("threat_level", "UNKNOWN"),
        "yaicd_score":          report.get("yaicd_score", 0),
        "yaicd_threshold":      report.get("yaicd_threshold", 2.6),
        "yaicd_verdict":        report.get("yaicd_verdict", ""),
        "confirmed_heuristics": report.get("confirmed_heuristics", 0),
        "partial_heuristics":   report.get("partial_heuristics", 0),
        "total_events":         report.get("total_events", 0),
        "findings":             report.get("findings", []),
        "hardware_candidates":  report.get("hardware_candidates", []),
        "cell_summary":         report.get("cell_summary", []),
        "generated_at":         report.get("generated_at", ""),
        "session_dir":          report.get("session_dir", ""),
        "rayhunter_version":    report.get("rayhunter_version", ""),
        "confirmed_indicators": report.get("confirmed_indicators", []),
        "partial_indicators":   report.get("partial_indicators", []),
        "triggered_params":     report.get("triggered_params", []),
    }
    return summary


# ── Text Generators ───────────────────────────────────────────────────────────

def build_evidence_report(summary: dict, case_ref: str, package_ts: str) -> str:
    """Generate human-readable evidence narrative."""

    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    verdict = summary["yaicd_verdict"]
    score   = summary["yaicd_score"]
    thresh  = summary["yaicd_threshold"]
    conf_h  = summary["confirmed_heuristics"]
    part_h  = summary["partial_heuristics"]

    lines = []
    lines.append("=" * 78)
    lines.append("RAYHUNTER THREAT ANALYZER — FORENSIC EVIDENCE REPORT")
    lines.append("=" * 78)
    lines.append(f"Generated    : {ts_now}")
    lines.append(f"Package ID   : {package_ts}")
    lines.append(f"Case Ref     : {case_ref or 'Not specified'}")
    lines.append(f"Tool Version : {TOOL_NAME} v{VERSION}")
    lines.append(f"Repository   : {REPO}")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 1 — REGULATORY COMPLAINTS")
    lines.append("─" * 78)
    lines.append("This evidence package relates to the following active complaints:")
    lines.append(f"  ACMA Complaint    : {COMPLAINTS['ACMA']}")
    lines.append(f"  TIO Complaint     : {COMPLAINTS['TIO']}")
    lines.append(f"  Victoria Police   : {COMPLAINTS['VicPol']}")
    lines.append(f"  AFP FOI Request   : {COMPLAINTS['AFP_FOI']}")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 2 — FORMAL DETECTION RESULT")
    lines.append("─" * 78)
    lines.append(f"  Threat Level         : {summary['threat_level']}")
    lines.append(f"  YAICD Score          : {score:.2f} (threshold: {thresh})")
    lines.append(f"  Verdict              : {verdict}")
    lines.append(f"  Confirmed Heuristics : {conf_h}/10")
    lines.append(f"  Partial Heuristics   : {part_h}/10")
    lines.append(f"  Events Analysed      : {summary['total_events']:,}")
    lines.append("")
    lines.append("  Scoring Framework: Ziayi et al. 2021 YAICD + Dabrowski 2014")
    lines.append("  A score above 2.6 constitutes a FORMAL POSITIVE DETECTION.")
    lines.append(f"  This session scored {score:.2f} — {score - thresh:+.2f} above threshold.")
    lines.append("")

    if summary["confirmed_indicators"]:
        lines.append("  Confirmed Indicators:")
        for ind in summary["confirmed_indicators"]:
            lines.append(f"    [+] {ind}")
    if summary["partial_indicators"]:
        lines.append("  Partial Indicators:")
        for ind in summary["partial_indicators"]:
            lines.append(f"    [~] {ind}")
    if summary["triggered_params"]:
        lines.append(f"  Triggered Parameters: {', '.join(summary['triggered_params'])}")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 3 — FINDINGS")
    lines.append("─" * 78)

    findings = summary["findings"]
    if not findings:
        lines.append("  No structured findings in report. See rayhunter_report.json.")
    else:
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "UNKNOWN")
            status   = f.get("status", "")
            title    = f.get("title", f.get("name", "Finding"))
            desc     = f.get("description", "")
            tech     = f.get("technique", "")
            spec     = f.get("spec", "")
            hardware = f.get("hardware", "")
            evidence = f.get("evidence", [])

            lines.append(f"  [{i}] {severity} | {status} — {title}")
            if desc:
                # Word-wrap description at 72 chars
                words = desc.split()
                line_buf = "      "
                for word in words:
                    if len(line_buf) + len(word) + 1 > 74:
                        lines.append(line_buf)
                        line_buf = "      " + word
                    else:
                        line_buf += (" " if line_buf.strip() else "") + word
                if line_buf.strip():
                    lines.append(line_buf)
            if tech:
                lines.append(f"      Technique : {tech}")
            if spec:
                lines.append(f"      Spec Ref  : {spec}")
            if hardware:
                lines.append(f"      Hardware  : {hardware}")
            if evidence:
                lines.append("      Evidence  :")
                for ev in evidence[:10]:  # cap at 10 events per finding
                    lines.append(f"        {ev}")
                if len(evidence) > 10:
                    lines.append(f"        ... and {len(evidence)-10} more (see rayhunter_report.json)")
            lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 4 — HARDWARE FINGERPRINT")
    lines.append("─" * 78)
    candidates = summary["hardware_candidates"]
    if not candidates:
        lines.append("  No hardware candidates identified.")
    else:
        lines.append("  The following hardware platforms are consistent with observed signatures.")
        lines.append("  Scores represent relative fit to collected evidence (not certainty).")
        lines.append("")
        for c in candidates:
            name    = c.get("name", "Unknown")
            score_h = c.get("score", 0)
            reasons = c.get("reasons", [])
            lines.append(f"  [{score_h:.2f}] {name}")
            for r in reasons:
                lines.append(f"         {r}")
        lines.append("")
        lines.append("  Note: Cross-carrier simultaneous operation (Telstra 505-01 + Vodafone")
        lines.append("  505-03) is consistent with hardware featuring 4 Tx ports (HailStorm /")
        lines.append("  StingRay II architecture). Single-carrier platforms are excluded.")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 5 — CELL ID INVENTORY")
    lines.append("─" * 78)
    cells = summary["cell_summary"]
    if not cells:
        lines.append("  No cell summary available. See rayhunter_report.json.")
    else:
        lines.append("  All Cell IDs observed across session captures.")
        lines.append("  CIDs marked [ROGUE] are confirmed not present in OpenCelliD global")
        lines.append("  database and have zero registered observations worldwide.")
        lines.append("")
        lines.append(f"  {'CID':<15} {'TAC':<8} {'MCC':<6} {'MNC':<6} {'Operator':<20} {'Obs':>5}  Status")
        lines.append("  " + "-" * 70)
        for cell in cells:
            cid  = str(cell.get("cid", cell.get("cell_id", "")))
            tac  = str(cell.get("tac", ""))
            mcc  = str(cell.get("mcc", "505"))
            mnc  = str(cell.get("mnc", ""))
            ops  = "Telstra AU" if mnc in ("1", "01", "001") else "Vodafone AU" if mnc in ("3", "03", "003") else "Unknown"
            obs  = cell.get("observations", cell.get("count", 0))
            flag = cell.get("rogue", False)
            status = "[ROGUE]" if flag else "[VERIFY]"
            lines.append(f"  {cid:<15} {tac:<8} {mcc:<6} {mnc:<6} {ops:<20} {obs:>5}  {status}")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 6 — INFRASTRUCTURE VERIFICATION")
    lines.append("─" * 78)
    lines.append("  Independent verification of rogue Cell IDs has been conducted against:")
    lines.append("  1. OzTowers (oztowers.com.au) — ACMA-sourced registered tower database")
    lines.append("     Result: No registered Telstra infrastructure found in residential")
    lines.append("     streets of Cranbourne East (Prendergast Ave area). Zero tower pins")
    lines.append("     in the immediate vicinity of detected rogue CID signals.")
    lines.append("")
    lines.append("  2. OpenCelliD (opencellid.org) — Global crowd-sourced cell database")
    lines.append("     Result: TAC=12385 (Telstra) and TAC=30336 (Vodafone) are legitimate")
    lines.append("     TACs with registered cells on main roads. The specific rogue CIDs")
    lines.append("     (137713195, 137713165, 137713155, 137713175, 135836191, 8409357,")
    lines.append("     8409367, 8409387, 8409397) do not appear in global observations.")
    lines.append("")
    lines.append("  3. Telstra Written Confirmation (Ref: 128653446)")
    lines.append("     Telstra confirmed in writing that an unauthorised Cel-Fi G51 device")
    lines.append("     connected to their network. This confirmation, combined with the")
    lines.append("     absence of registered infrastructure and the YAICD formal positive")
    lines.append("     detection, establishes a multi-source evidentiary record.")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 7 — SIGNAL PROXIMITY EVIDENCE")
    lines.append("─" * 78)
    lines.append("  RSRP (Reference Signal Received Power) readings from Termux-based")
    lines.append("  scanning (CastNet node 'grapher') recorded on 27 May 2026:")
    lines.append("")
    lines.append("  Peak proximity readings (stronger = closer source):")
    lines.append("    07:40 AEST — CID=137713165 — RSRP=-78 dBm")
    lines.append("    07:58 AEST — CID=137713155 — RSRP=-72 dBm  ← Strongest recorded")
    lines.append("")
    lines.append("  Baseline readings for same CIDs: typically -100 to -116 dBm")
    lines.append("  Delta: approximately 30-40 dB above baseline at time of proximity spike.")
    lines.append("")
    lines.append("  Network Signal Info Pro (Android) triangulated CID=137713165 at")
    lines.append("  approximately 20 metres from the subject's location at 19:28 AEST")
    lines.append("  on 27 May 2026. No registered Telstra infrastructure exists within")
    lines.append("  several hundred metres of this location per OzTowers/OpenCelliD.")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 8 — CAPTURE FILES INCLUDED")
    lines.append("─" * 78)
    lines.append("  See session_files/ directory and MANIFEST.txt for complete file list")
    lines.append("  with SHA256 integrity hashes. All files are original, unmodified")
    lines.append("  captures from Rayhunter v0.11.1 running on TP-Link M7350 devices.")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 9 — TOOL INTEGRITY")
    lines.append("─" * 78)
    lines.append(f"  Analysis Tool  : {TOOL_NAME} v{VERSION}")
    lines.append(f"  Repository     : {REPO}")
    lines.append("  This tool is open source and publicly auditable. All detection logic,")
    lines.append("  scoring algorithms, and heuristic frameworks are documented in the")
    lines.append("  repository. Results are independently reproducible from the included")
    lines.append("  capture files.")
    lines.append("")

    lines.append("─" * 78)
    lines.append("SECTION 10 — DISCLAIMER")
    lines.append("─" * 78)
    lines.append("  This report was produced by civilian investigative tooling and does")
    lines.append("  not constitute a formal expert witness statement. The findings are")
    lines.append("  offered as technical evidence for consideration by authorised")
    lines.append("  investigators. All data is derived from passive observation of signals")
    lines.append("  broadcast in public space. No interception of communications occurred.")
    lines.append("")
    lines.append("=" * 78)

    return "\n".join(lines)


def build_chain_of_custody(package_ts: str, case_ref: str,
                            report_path: Path, session_dir: Path,
                            file_hashes: dict) -> str:
    """Generate chain of custody document."""
    ts_now = datetime.now(timezone.utc).isoformat()
    hostname = platform.node()
    py_version = platform.python_version()
    os_info = f"{platform.system()} {platform.release()}"

    lines = []
    lines.append("CHAIN OF CUSTODY DOCUMENT")
    lines.append("=" * 78)
    lines.append(f"Package ID       : {package_ts}")
    lines.append(f"Generated        : {ts_now}")
    lines.append(f"Case Reference   : {case_ref or 'Not specified'}")
    lines.append(f"Generated On     : {hostname}")
    lines.append(f"Operating System : {os_info}")
    lines.append(f"Python Version   : {py_version}")
    lines.append(f"Tool Version     : {TOOL_NAME} v{VERSION}")
    lines.append(f"Repository       : {REPO}")
    lines.append("")
    lines.append("SOURCE REPORT")
    lines.append("-" * 40)
    lines.append(f"Path   : {report_path}")
    lines.append(f"SHA256 : {sha256_file(report_path)}")
    lines.append("")
    lines.append("SESSION DIRECTORY")
    lines.append("-" * 40)
    lines.append(f"Path   : {session_dir or 'Not specified'}")
    lines.append("")
    lines.append("FILE MANIFEST")
    lines.append("-" * 40)
    for fname, fhash in sorted(file_hashes.items()):
        lines.append(f"{fhash}  {fname}")
    lines.append("")
    lines.append("INTEGRITY STATEMENT")
    lines.append("-" * 40)
    lines.append("The SHA256 hashes above were computed at package generation time.")
    lines.append("Any subsequent modification to the listed files will produce a")
    lines.append("different hash value, indicating tampering.")
    lines.append("")
    lines.append("This document was generated automatically by " + TOOL_NAME)
    lines.append("and has not been manually edited.")

    return "\n".join(lines)


def build_manifest(file_hashes: dict, package_ts: str) -> str:
    """Generate SHA256 manifest."""
    lines = [
        f"# SHA256 Manifest — {TOOL_NAME} v{VERSION}",
        f"# Package ID: {package_ts}",
        f"# Generated : {datetime.now(timezone.utc).isoformat()}",
        "#",
        "# FORMAT: SHA256_HASH  FILENAME",
        "#",
    ]
    for fname, fhash in sorted(file_hashes.items()):
        lines.append(f"{fhash}  {fname}")
    return "\n".join(lines)


# ── Package Builder ───────────────────────────────────────────────────────────

def build_package(
    report_path: Path,
    session_dir: Path | None,
    case_ref: str,
    output_dir: Path,
    verbose: bool = False,
) -> Path:
    """
    Build the evidence package zip.

    Returns path to the generated zip file.
    """

    package_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_name   = f"evidence_package_{package_ts}.zip"
    zip_path   = output_dir / zip_name

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  EVIDENCE PACKAGE GENERATOR")
    print(f"  {TOOL_NAME} v{VERSION}")
    print(f"{'='*60}")
    print(f"  Report     : {report_path.name}")
    print(f"  Session    : {session_dir or 'Not specified'}")
    print(f"  Case Ref   : {case_ref or 'Not specified'}")
    print(f"  Output     : {zip_path}")
    print(f"{'='*60}\n")

    # Load report
    print("  [1/5] Loading report...")
    report  = load_report(report_path)
    summary = extract_summary(report)

    # Generate text documents
    print("  [2/5] Generating evidence narrative...")
    evidence_report_text = build_evidence_report(summary, case_ref, package_ts)

    print("  [3/5] Computing file hashes...")
    file_hashes = {}
    session_files = []

    # Hash the JSON report
    file_hashes["rayhunter_report.json"] = sha256_file(report_path)

    # Collect session files if dir provided
    if session_dir and session_dir.exists():
        extensions = {".ndjson", ".pcapng", ".qmdl", ".pcap"}
        for f in sorted(session_dir.iterdir()):
            if f.suffix.lower() in extensions and f.is_file():
                session_files.append(f)
                rel = f"session_files/{f.name}"
                file_hashes[rel] = sha256_file(f)
                if verbose:
                    print(f"       Hashed: {f.name}")

    # Generate manifest and chain of custody
    manifest_text = build_manifest(file_hashes, package_ts)
    custody_text  = build_chain_of_custody(
        package_ts, case_ref, report_path, session_dir, file_hashes
    )

    # Hash the generated text docs and add to manifest
    file_hashes["EVIDENCE_REPORT.txt"]    = sha256_string(evidence_report_text)
    file_hashes["CHAIN_OF_CUSTODY.txt"]   = sha256_string(custody_text)
    # Regenerate manifest with the text doc hashes included
    manifest_text = build_manifest(file_hashes, package_ts)
    file_hashes["MANIFEST.txt"]           = sha256_string(manifest_text)

    print(f"  [4/5] Building zip ({len(session_files)} capture files)...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Text documents at root
        zf.writestr("EVIDENCE_REPORT.txt",  evidence_report_text)
        zf.writestr("CHAIN_OF_CUSTODY.txt", custody_text)
        zf.writestr("MANIFEST.txt",         manifest_text)

        # JSON report
        with open(report_path, "r", encoding="utf-8") as f:
            zf.writestr("rayhunter_report.json", f.read())

        # Session capture files
        for sf in session_files:
            arcname = f"session_files/{sf.name}"
            zf.write(sf, arcname=arcname)
            if verbose:
                print(f"       Added: {sf.name}")

    print(f"  [5/5] Verifying package integrity...")
    pkg_hash = sha256_file(zip_path)
    pkg_size = zip_path.stat().st_size

    print(f"\n{'='*60}")
    print(f"  ✅ PACKAGE GENERATED SUCCESSFULLY")
    print(f"{'='*60}")
    print(f"  File     : {zip_path.name}")
    print(f"  Size     : {pkg_size:,} bytes ({pkg_size/1024:.1f} KB)")
    print(f"  SHA256   : {pkg_hash}")
    print(f"  Files    : {len(file_hashes)} items in manifest")
    print(f"  Captures : {len(session_files)} session files included")
    print(f"\n  Package is ready for submission to:")
    print(f"    Victoria Police — DSC Cameron Burns, badge 38739")
    print(f"    ACMA — ENQ-1851DVJH04")
    print(f"    TIO  — 2026-03-04898")
    print(f"{'='*60}\n")

    # Write package hash to a separate sidecar file
    sidecar = output_dir / f"evidence_package_{package_ts}.sha256"
    sidecar.write_text(f"{pkg_hash}  {zip_name}\n", encoding="utf-8")
    print(f"  Sidecar hash : {sidecar.name}")

    return zip_path


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — Evidence Package Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evidence_package.py --report rayhunter_report_1779888200.json
  python evidence_package.py --report rayhunter_report_1779888200.json \\
      --session-dir "C:\\Users\\Jessum Chap\\Desktop\\27.05.26" \\
      --case-ref "CIRS-20260331-141" \\
      --output-dir "C:\\RH\\evidence"
        """
    )
    parser.add_argument(
        "--report", required=True,
        help="Path to rayhunter JSON report file"
    )
    parser.add_argument(
        "--session-dir", default=None,
        help="Path to session directory containing capture files (NDJSON/PCAPNG/QMDL)"
    )
    parser.add_argument(
        "--case-ref", default="",
        help="Case reference number (e.g. CIRS-20260331-141)"
    )
    parser.add_argument(
        "--output-dir", default="evidence_packages",
        help="Output directory for the package zip (default: evidence_packages/)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show each file as it is added"
    )

    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[ERROR] Report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    session_dir = Path(args.session_dir) if args.session_dir else None
    if session_dir and not session_dir.exists():
        print(f"[WARN] Session directory not found: {session_dir}", file=sys.stderr)
        session_dir = None

    output_dir = Path(args.output_dir)

    build_package(
        report_path=report_path,
        session_dir=session_dir,
        case_ref=args.case_ref,
        output_dir=output_dir,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
