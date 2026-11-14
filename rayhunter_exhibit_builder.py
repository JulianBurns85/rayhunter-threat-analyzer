#!/usr/bin/env python3
import os
import re
import glob
import argparse
from collections import Counter

def generate_exhibits(target_dir):
    print("=" * 60)
    print(" RAYHUNTER AUTOMATED EVENT-TO-EXHIBIT CORRELATOR v1.1")
    print("=" * 60)
    print(f"[*] Target Location: 27 Nightingale Street, Balaclava VIC 3183")
    print(f"[*] Scanning Directory: {target_dir}")
    
    txt_files = glob.glob(os.path.join(target_dir, "**/*.txt"), recursive=True) + ["1.txt", "2.txt", "3.txt"]
    exhibit_records = []
    
    for tf in txt_files:
        if not os.path.exists(tf):
            continue
        try:
            with open(tf, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if any(kw in line for kw in ["Identity request", "SecurityModeCommand", "Paging", "Attach request", "Authentication request", "SIB1"]):
                        exhibit_records.append(line.strip())
        except Exception:
            pass

    print(f"[*] Extracted {len(exhibit_records)} notable signaling events for legal/regulatory exhibits.")
    
    output_filename = "rayhunter_legal_exhibit_table.txt"
    with open(output_filename, "w", encoding="utf-8") as out:
        out.write("============================================================\n")
        out.write(" FORMAL FORENSIC EXHIBIT TABLE — BALACLAVA INVESTIGATION\n")
        out.write(" Subject Location: 27 Nightingale Street, Balaclava VIC 3183\n")
        out.write("============================================================\n\n")
        out.write("No.  Timestamp(s)       Protocol / Event Description\n")
        out.write("-" * 60 + "\n")
        for idx, rec in enumerate(exhibit_records[:200], 1):
            out.write(f"{idx:3d}  {rec}\n")
            
    print(f"[✓] Saved formal exhibit table to: {output_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=".")
    args = parser.parse_args()
    generate_exhibits(args.dir)