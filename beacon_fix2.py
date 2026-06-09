#!/usr/bin/env python3
"""
Patch 2 for BeaconPeriodicityScorerV2
Fixes: ROGUE_CIDS only contains TAC=12385 Telstra CIDs.
The 2.10s srsRAN fingerprint lives on TAC=30336 Vodafone CIDs.
Both sets need to be included.
"""

OLD = "ROGUE_CIDS = {137713155, 137713165, 137713175, 137713195}"

NEW = """# TAC=12385 Telstra CIDs (Device A — Harris professional hardware)
ROGUE_CIDS_DEVICE_A = {137713155, 137713165, 137713175, 137713195, 135836161, 135836171, 135836191}
# TAC=30336 Vodafone CIDs (Device B — srsRAN personal SDR — 2.10s fingerprint lives here)
ROGUE_CIDS_DEVICE_B = {8409357, 8409367, 8409387, 8409397, 8666381, 8666391, 8666411}
# Combined set for interval analysis
ROGUE_CIDS = ROGUE_CIDS_DEVICE_A | ROGUE_CIDS_DEVICE_B"""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\beacon_periodicity_scorer_v2.py"
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

if OLD not in content:
    print("ERROR: Could not find ROGUE_CIDS line — may already be patched or different format")
    idx = content.find("ROGUE_CIDS")
    print("Found ROGUE_CIDS at:", idx)
    print(content[idx:idx+200])
else:
    new_content = content.replace(OLD, NEW)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("PATCHED OK — ROGUE_CIDS now includes all 14 rogue CIDs across both TACs")
