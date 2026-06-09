#!/usr/bin/env python3
"""
debug_findings.py -- Dump exact finding structure from all detectors.

Run BEFORE fixing heuristic_scorer.py to see what key names the
detectors actually produce.

Usage:
    cd C:\RH
    python debug_findings.py --dir C:\ray_staged_full

Save to: C:\RH\debug_findings.py
"""

import argparse
import json
import sys
from pathlib import Path

import config_loader
from parsers.ndjson_parser import NdjsonParser
from parsers.pcap_parser import PcapParser

from detectors.identity_harvest import IdentityHarvestDetector
from detectors.cipher_downgrade import CipherDowngradeDetector
from detectors.rogue_tower import RogueTowerDetector
from detectors.earfcn_anomaly import EarfcnAnomalyDetector

SKIP_DIRS = {
    "windows", "system32", "syswow64", "program files",
    "program files (x86)", "programdata", "appdata",
    "$recycle.bin", "system volume information",
}


def collect(directory):
    files = {"ndjson": [], "pcap": []}
    for ext, key in [("*.ndjson", "ndjson"), ("*.pcap", "pcap"),
                     ("*.pcapng", "pcap")]:
        for p in Path(directory).rglob(ext):
            parts = {x.lower() for x in p.parts}
            if parts & SKIP_DIRS:
                continue
            files[key].append(str(p))
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", "-d", required=True)
    ap.add_argument("--config", "-c", default="config.yaml")
    ap.add_argument("--limit", type=int, default=5,
                    help="Max files to parse (default 5, keeps it fast)")
    args = ap.parse_args()

    cfg = config_loader.load(args.config)
    files = collect(args.dir)

    # Limit file count to keep it fast
    files["ndjson"] = files["ndjson"][: args.limit]
    files["pcap"]   = files["pcap"][: args.limit]

    print(f"Parsing {len(files['ndjson'])} NDJSON + {len(files['pcap'])} PCAP files...")

    all_events = []
    if files["ndjson"]:
        p = NdjsonParser(cfg)
        for f in files["ndjson"]:
            all_events.extend(p.parse(f))
    if files["pcap"]:
        p = PcapParser(cfg)
        for f in files["pcap"]:
            all_events.extend(p.parse(f))

    print(f"Total events: {len(all_events):,}\n")

    # Show first event structure
    if all_events:
        print("=" * 60)
        print("FIRST EVENT KEYS:")
        print("=" * 60)
        e0 = all_events[0]
        for k, v in e0.items():
            print(f"  {k!r}: {v!r}")
        print()

    detectors = [
        ("IdentityHarvestDetector", IdentityHarvestDetector(cfg)),
        ("CipherDowngradeDetector", CipherDowngradeDetector(cfg)),
        ("RogueTowerDetector",      RogueTowerDetector(cfg)),
        ("EarfcnAnomalyDetector",   EarfcnAnomalyDetector(cfg)),
    ]

    all_findings = []
    for name, det in detectors:
        findings = det.analyze(all_events)
        all_findings.extend(findings)
        print("=" * 60)
        print(f"DETECTOR: {name}  ->  {len(findings)} finding(s)")
        print("=" * 60)
        for i, f in enumerate(findings[:3]):   # Show first 3 findings max
            print(f"\n  Finding [{i}] -- ALL KEYS:")
            if isinstance(f, dict):
                for k, v in f.items():
                    # Truncate long values
                    vstr = repr(v)
                    if len(vstr) > 120:
                        vstr = vstr[:120] + "..."
                    print(f"    {k!r}: {vstr}")
            else:
                # It might be a dataclass or object
                print(f"  Type: {type(f)}")
                if hasattr(f, "__dict__"):
                    for k, v in f.__dict__.items():
                        vstr = repr(v)
                        if len(vstr) > 120:
                            vstr = vstr[:120] + "..."
                        print(f"    {k!r}: {vstr}")
                else:
                    print(f"  repr: {repr(f)[:300]}")
        print()

    # Also show unique 'type' and 'finding_type' values across all findings
    print("=" * 60)
    print("ALL UNIQUE TYPE / FINDING_TYPE VALUES IN FINDINGS:")
    print("=" * 60)
    type_vals = set()
    for f in all_findings:
        if isinstance(f, dict):
            for key in ("type", "finding_type", "detector", "category",
                        "name", "attack_type", "severity"):
                v = f.get(key)
                if v:
                    type_vals.add(f"{key}={v!r}")
        elif hasattr(f, "__dict__"):
            for key in ("type", "finding_type", "detector", "category",
                        "name", "attack_type", "severity"):
                v = getattr(f, key, None)
                if v:
                    type_vals.add(f"{key}={v!r}")
    for tv in sorted(type_vals):
        print(f"  {tv}")

    print()
    print("=" * 60)
    print("SAMPLE EVENT -- CHECKING EEA0-RELATED FIELDS:")
    print("=" * 60)
    eea0_keys_seen = {}
    for e in all_events[:5000]:
        for k, v in (e.items() if isinstance(e, dict) else {}):
            vs = str(v).lower()
            if any(x in vs for x in ("eea0", "null", "cipher", "security")):
                eea0_keys_seen.setdefault(k, set()).add(str(v)[:40])
    for k, vals in list(eea0_keys_seen.items())[:15]:
        print(f"  {k!r}: {sorted(vals)[:5]}")

    print("\nDone. Paste this output to diagnose heuristic_scorer field mismatches.")


if __name__ == "__main__":
    main()
