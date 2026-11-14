#!/usr/bin/env python3
"""
baseline_rrc.py — Control capture file inventory (v4.4.1)

Counts QMDL/PCAP binaries and total size for a control or investigation folder.

Usage:
    python baseline_rrc.py --dir "C:\\RH\\captures\\control"
"""

from __future__ import annotations

import argparse
from pathlib import Path


def analyze_capture_baseline(directory_path: str | Path) -> dict:
    target_dir = Path(directory_path)

    qmdl_files = list(target_dir.rglob("*.qmdl"))
    pcap_files = list(target_dir.rglob("*.pcapng")) + list(target_dir.rglob("*.pcap"))

    print(f"[*] Scanning directory tree: {target_dir}")
    print(f"[*] Found {len(qmdl_files)} QMDL diagnostic file(s).")
    print(f"[*] Found {len(pcap_files)} PCAP/PCAPNG packet file(s).")

    all_bin = qmdl_files + pcap_files
    total_size_mb = sum(f.stat().st_size for f in all_bin) / (1024 * 1024)

    print("\n--- CONTROL BASELINE SUMMARY ---")
    print(f"Total Binary Capture Files : {len(all_bin)}")
    print(f"Combined Size on Disk      : {total_size_mb:.2f} MB")
    print("--------------------------------\n")

    return {
        "qmdl_count": len(qmdl_files),
        "pcap_count": len(pcap_files),
        "total_files": len(all_bin),
        "total_size_mb": round(total_size_mb, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Control capture baseline inventory (v4.4.1)")
    parser.add_argument("--dir", required=True, help="Path to the control/capture directory")
    args = parser.parse_args()
    analyze_capture_baseline(args.dir)


if __name__ == "__main__":
    main()
