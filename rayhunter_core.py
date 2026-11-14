#!/usr/bin/env python3
"""Standalone NDJSON parser-gap summary.

Same count the main analyzer reports as NdjsonParserGapDetector.
Does not treat the word IMSI in an analyzer title as an Identity Request.

Usage:
    python rayhunter_core.py --dir "C:\\Users\\Jessum Fellow\\Desktop\\raymum4"
"""
from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from detectors.ndjson_parser_gap import NdjsonParserGapDetector
from main import collect_files
from parsers.ndjson_parser import NdjsonParser


def analyze_capture_set(base_dir: str, output_dir: Path | None = None) -> dict:
    files = collect_files([], base_dir)
    parser = NdjsonParser({})
    events = []
    for path in files["ndjson"]:
        batch = parser.parse(path)
        print(f"  -> {len(batch):,} events from {Path(path).name}")
        events.extend(batch)
    findings = NdjsonParserGapDetector({}).analyze(events)
    print("=" * 60)
    if not findings:
        print("No NDJSON files found.")
        return {}
    finding = findings[0]
    print(finding["title"])
    print("-" * 60)
    for line in finding["evidence"]:
        print(f"  {line}" if line else "")
    print("-" * 60)
    print(finding["recommended_action"])

    out_dir = output_dir or Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = out_dir / f"ndjson_parser_gap_{stamp}.md"
    md_path.write_text(
        "# NDJSON parser gaps\n\n"
        + finding["description"]
        + "\n\n"
        + "\n".join(f"- {line}" for line in finding["evidence"] if line)
        + "\n",
        encoding="utf-8",
    )
    print(f"[OK] {md_path}")
    return {"markdown": str(md_path), "title": finding["title"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Rayhunter NDJSON parser-gap summary")
    parser.add_argument("--dir", required=True, help="Path to capture directory")
    parser.add_argument("--output-dir", default=None, help="Report directory")
    args = parser.parse_args()
    out = Path(args.output_dir).expanduser() if args.output_dir else None
    analyze_capture_set(args.dir, output_dir=out)


if __name__ == "__main__":
    main()
