#!/usr/bin/env python3
"""
diagnose.py — NDJSON Structure Inspector
=========================================
Prints raw JSON lines and parsed event fields from your actual Rayhunter
NDJSON files so we can see exactly what fields exist and fix the parser.

Usage:
    python diagnose.py --file capture.ndjson
    python diagnose.py --dir C:\ray --lines 5
    python diagnose.py --file capture.ndjson --search eea0
"""

import json
import sys
import argparse
from pathlib import Path


def inspect_ndjson(filepath, max_lines=10, search=None):
    print(f"\n{'='*70}")
    print(f"FILE: {filepath}")
    print(f"{'='*70}")

    path = Path(filepath)
    if not path.exists():
        print(f"  [ERROR] File not found")
        return

    lines_shown = 0
    total_lines = 0
    all_keys = set()

    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total_lines += 1

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Collect all keys recursively
            collect_keys(obj, all_keys)

            # Search filter
            if search:
                if search.lower() not in line.lower():
                    continue

            if lines_shown < max_lines:
                print(f"\n--- Line {lineno} ---")
                # Pretty print with truncation
                pretty = json.dumps(obj, indent=2, default=str)
                if len(pretty) > 2000:
                    pretty = pretty[:2000] + "\n  ... [truncated]"
                print(pretty)
                lines_shown += 1

    print(f"\n--- Summary ---")
    print(f"  Total non-empty lines: {total_lines}")
    print(f"  Lines shown: {lines_shown}")
    print(f"\n  All keys found (any depth):")
    for k in sorted(all_keys):
        print(f"    {k}")


def collect_keys(obj, keys, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.add(full_key)
            collect_keys(v, keys, full_key)
    elif isinstance(obj, list):
        for item in obj:
            collect_keys(item, keys, prefix)


def inspect_events(filepath, cfg):
    """Show what the NDJSON parser actually extracts."""
    sys.path.insert(0, str(Path(__file__).parent))
    import config_loader
    cfg = config_loader.load("config.yaml")
    from parsers.ndjson_parser import NdjsonParser

    parser = NdjsonParser(cfg)
    events = parser.parse(filepath)

    print(f"\n{'='*70}")
    print(f"PARSED EVENTS FROM: {Path(filepath).name}")
    print(f"{'='*70}")
    print(f"Total events extracted: {len(events)}")

    # Show events that have any interesting fields set
    interesting = [
        e for e in events
        if any([
            e.get("msg_type"),
            e.get("cipher_alg"),
            e.get("integrity_alg"),
            e.get("identity_type"),
            e.get("has_mobility_control"),
            e.get("has_geran_redirect"),
            e.get("has_prose"),
            e.get("paging_type"),
            e.get("harness_alerts"),
        ])
    ]

    print(f"Events with useful fields: {len(interesting)}")

    print(f"\nField population across all {len(events)} events:")
    fields = ["msg_type", "cipher_alg", "integrity_alg", "identity_type",
              "cell_id", "earfcn", "tac", "pci", "rsrp", "layer",
              "has_mobility_control", "has_geran_redirect", "has_prose",
              "paging_type", "harness_alerts"]
    for field in fields:
        non_null = [e for e in events if e.get(field)]
        if non_null:
            # Show unique values
            unique_vals = list(set(str(e.get(field))[:80] for e in non_null))[:5]
            print(f"  {field}: {len(non_null)} events | values: {unique_vals}")
        else:
            print(f"  {field}: (none)")

    print(f"\nSample interesting events (up to 5):")
    for e in interesting[:5]:
        print(f"\n  [{e.get('timestamp','?')}]")
        for f in fields:
            v = e.get(f)
            if v:
                print(f"    {f}: {str(v)[:100]}")


def main():
    parser = argparse.ArgumentParser(description="Rayhunter NDJSON diagnostic tool")
    parser.add_argument("--file", "-f", help="Single NDJSON file to inspect")
    parser.add_argument("--dir", "-d", help="Directory to scan for NDJSON files")
    parser.add_argument("--lines", "-n", type=int, default=5,
                        help="Number of raw JSON lines to show per file (default: 5)")
    parser.add_argument("--search", "-s",
                        help="Only show lines containing this string (e.g. 'eea0', 'identity')")
    parser.add_argument("--parsed", "-p", action="store_true",
                        help="Show parsed event fields (what the detector sees)")
    args = parser.parse_args()

    files = []
    if args.file:
        files.append(args.file)
    if args.dir:
        d = Path(args.dir)
        files.extend(str(p) for p in d.rglob("*.ndjson"))

    if not files:
        print("Usage: python diagnose.py --file capture.ndjson")
        print("       python diagnose.py --dir C:\\ray --lines 3")
        print("       python diagnose.py --file capture.ndjson --search eea0")
        print("       python diagnose.py --file capture.ndjson --parsed")
        sys.exit(1)

    for f in files[:10]:  # Limit to 10 files
        if args.parsed:
            inspect_events(f, {})
        else:
            inspect_ndjson(f, max_lines=args.lines, search=args.search)


if __name__ == "__main__":
    main()
