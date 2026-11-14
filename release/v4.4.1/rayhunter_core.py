#!/usr/bin/env python3
"""
rayhunter_core.py — NDJSON parser-gap and identity-request summary (v4.4.1)

Standalone pre-pass over Rayhunter NDJSON captures. Complements main.py by
quantifying parser skips (encrypted NAS, ServingCellTiming, MAC framed, etc.)
before full detector analysis.

Usage:
    python rayhunter_core.py --dir "C:\\RH\\captures"
    python rayhunter_core.py --dir captures --output-dir "C:/RH/reports and maps"
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from collections import Counter
from pathlib import Path
from typing import Optional


def _classify_skip(reason_str: str) -> str:
    if "ServingCellTiming.num_records" in reason_str:
        return "ServingCellTiming Zero-Record Assertion"
    if "Incomplete" in reason_str:
        return "Incomplete NAS Message (NeedSize)"
    if "LteMacFramed" in reason_str:
        return "Unsupported LTE MAC Framed"
    if "Encrypted" in reason_str:
        return "Encrypted NAS Message (Skipped)"
    return "Other Parser Gap"


def analyze_capture_set(base_dir: str, output_dir: Optional[Path] = None) -> dict:
    """Scan NDJSON tree; return counts and write CSV + Markdown reports."""
    print("=" * 60)
    print(" RAYHUNTER NDJSON PARSER-GAP SUMMARY v4.4.1")
    print("=" * 60)

    if not os.path.exists(base_dir):
        print(f"[!] Target directory not found: {base_dir}")
        return {}

    out_dir = output_dir or Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    total_files = 0
    total_records = 0
    skipped_reasons: Counter = Counter()
    message_types: Counter = Counter()
    identity_requests: Counter = Counter()

    for root, _, files in os.walk(base_dir):
        for file in files:
            if not file.endswith(".ndjson") or file.endswith("-gps.ndjson"):
                continue
            file_path = os.path.join(root, file)
            total_files += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        total_records += 1

                        if "skipped_message_reason" in data:
                            skipped_reasons[_classify_skip(str(data["skipped_message_reason"]))] += 1

                        events = data.get("events", [])
                        if not isinstance(events, list):
                            continue
                        for ev in events:
                            if not isinstance(ev, dict):
                                continue
                            msg = str(ev.get("message", ev)).lower()
                            if "attach" in msg:
                                message_types["Attach / Re-registration"] += 1
                            if "detach" in msg:
                                message_types["Detach Event"] += 1
                            if "identity" in msg or "imeisv" in msg or "imsi" in msg:
                                if "imeisv" in msg:
                                    identity_requests["IMEISV Request (Type 3)"] += 1
                                elif "imsi" in msg:
                                    identity_requests["IMSI Request (Type 1/2)"] += 1
                                else:
                                    identity_requests["Generic Identity Request"] += 1
            except OSError as e:
                print(f"[!] Error reading {file_path}: {e}")

    print(f"\n[+] Scanned {total_files} NDJSON files ({total_records} records).")
    print("-" * 60)
    print(f"  Message activity:      {dict(message_types)}")
    print(f"  Identity requests:     {dict(identity_requests)}")
    print(f"  Parser gaps/glitches:  {dict(skipped_reasons)}")
    print("-" * 60)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"rayhunter_report_{timestamp}.csv"
    md_path = out_dir / f"rayhunter_report_{timestamp}.md"

    with open(csv_path, "w", encoding="utf-8") as csv_file:
        csv_file.write("Category,Metric,Count\n")
        for k, v in message_types.items():
            csv_file.write(f"Message Activity,{k},{v}\n")
        for k, v in identity_requests.items():
            csv_file.write(f"Identity Request,{k},{v}\n")
        for k, v in skipped_reasons.items():
            csv_file.write(f"Parser Gap,{k},{v}\n")

    with open(md_path, "w", encoding="utf-8") as md_file:
        md_file.write("# Rayhunter Forensic Analysis Summary\n\n")
        md_file.write(f"- **Target Directory:** `{base_dir}`\n")
        md_file.write(f"- **Files Scanned:** {total_files}\n")
        md_file.write(f"- **Total Records Processed:** {total_records}\n\n")
        md_file.write("## Parser Gaps & Glitches\n| Category | Count |\n|---|---|\n")
        for k, v in skipped_reasons.items():
            md_file.write(f"| {k} | {v} |\n")
        md_file.write("\n## Identity Requests\n| Request Type | Count |\n|---|---|\n")
        if identity_requests:
            for k, v in identity_requests.items():
                md_file.write(f"| {k} | {v} |\n")
        else:
            md_file.write("| *None detected* | 0 |\n")

    print(f"[OK] CSV:  {csv_path}")
    print(f"[OK] Markdown: {md_path}")

    return {
        "files": total_files,
        "records": total_records,
        "message_types": dict(message_types),
        "identity_requests": dict(identity_requests),
        "parser_gaps": dict(skipped_reasons),
        "csv": str(csv_path),
        "markdown": str(md_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Rayhunter NDJSON parser-gap summary (v4.4.1)")
    parser.add_argument("--dir", required=True, help="Path to capture directory")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory (default: current directory)",
    )
    args = parser.parse_args()
    out = Path(args.output_dir).expanduser() if args.output_dir else None
    analyze_capture_set(args.dir, output_dir=out)


if __name__ == "__main__":
    main()
