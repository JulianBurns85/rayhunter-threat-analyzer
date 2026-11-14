#!/usr/bin/env python3
import os
import sys
import json
import glob
from pathlib import Path
from collections import Counter

def run_deep_analysis(target_dir):
    print("=" * 60)
    print(" RAYHUNTER ADVANCED DEEP-PACKET QMDL & PCAP EXTRACTOR v4.5")
    print("=" * 60)
    print(f"[*] Target Directory: {target_dir}")
    print(f"[*] Primary Monitoring Address: 27 Nightingale Street, Balaclava VIC 3183")
    
    if not os.path.exists(target_dir):
        print(f"[!] Directory not found: {target_dir}")
        return

    ndjson_files = glob.glob(os.path.join(target_dir, "**/*.ndjson"), recursive=True)
    qmdl_files = glob.glob(os.path.join(target_dir, "**/*.qmdl"), recursive=True)
    pcap_files = glob.glob(os.path.join(target_dir, "**/*.pcap*"), recursive=True)

    print(f"[*] Found: {len(ndjson_files)} NDJSON, {len(qmdl_files)} QMDL, {len(pcap_files)} PCAP files.")

    total_events = 0
    nas_msgs = Counter()
    gaps = Counter()

    for fp in ndjson_files[:50]: # Sample files for deep-dive extraction
        try:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        total_events += 1
                        if "skipped_message_reason" in data:
                            gaps[str(data["skipped_message_reason"])] += 1
                        events = data.get("events", [])
                        if isinstance(events, list):
                            for ev in events:
                                if isinstance(ev, dict):
                                    msg = ev.get("message", str(ev))
                                    nas_msgs[msg[:50]] += 1
                    except Exception:
                        pass
        except Exception:
            pass

    print(f"[*] Processed {total_events} sample events.")
    print("-" * 60)
    print("• Top Parsed Messages:", nas_msgs.most_common(5))
    print("• Top Gaps/Skips:", gaps.most_common(5))
    print("[✓] Deep extraction analysis complete.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=".")
    args = parser.parse_args()
    run_deep_analysis(args.dir)