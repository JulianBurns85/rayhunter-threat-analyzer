#!/usr/bin/env python3
"""
Patch script for BeaconPeriodicityScorerV2
Fixes: primary interval classifier biased toward high-frequency sub-second
intervals, burying the forensically significant 210s srsRAN cluster.
"""

FIX = '''
    def _classify_intervals(self, cid: int, intervals: List[float]) -> Dict:
        if not intervals:
            return {"stack_match": "UNKNOWN", "hardware_class": "UNKNOWN"}

        # Weighted signature matching:
        # Raw count alone is misleading — OsmocomBB at 0.48s produces many
        # sub-second intervals that bury the forensically significant 2.10s
        # srsRAN cluster. Apply forensic priority weights so that:
        #   - Professional hardware (Harris/Septier) always wins if present
        #   - srsRAN (2.10s) wins over sub-second SDR stacks
        #   - Sub-second SDR stacks (OsmocomBB, YateBTS) only win by default
        FORENSIC_WEIGHTS = {
            "PROFESSIONAL": 10.0,   # Harris/Septier — highest priority
            "CONSUMER_SDR": 1.0,    # Base weight for consumer SDR
        }
        # Additional weight bonus for the specific srsRAN range we've confirmed
        SRSLTE_BONUS = 5.0

        best_match = None
        best_score = 0

        for sig_min, sig_max, period, name, hw_class in STACK_SIGNATURES:
            count = sum(1 for iv in intervals if sig_min <= iv <= sig_max)
            if count == 0:
                continue
            # Base score = count * forensic weight
            base_weight = FORENSIC_WEIGHTS.get(hw_class, 1.0)
            score = count * base_weight
            # Bonus for the confirmed srsRAN 2.10s signature
            if 1.99 <= period <= 2.15:
                score *= SRSLTE_BONUS
            if score > best_score:
                best_score = score
                best_match = (period, name, hw_class, count)

        if best_match is None:
            best_match = (statistics.median(intervals), "UNRECOGNISED", "UNKNOWN", 0)

        return {
            "cid": cid,
            "total": len(intervals),
            "primary_interval": best_match[0],
            "stack_match": best_match[1],
            "hardware_class": best_match[2],
            "primary_count": best_match[3],
            "primary_fraction": best_match[3] / len(intervals) if intervals else 0,
        }
'''

OLD = '''    def _classify_intervals(self, cid: int, intervals: List[float]) -> Dict:
        if not intervals:
            return {"stack_match": "UNKNOWN", "hardware_class": "UNKNOWN"}

        # Find the most common interval range
        best_match = None
        best_count = 0

        for sig_min, sig_max, period, name, hw_class in STACK_SIGNATURES:
            count = sum(1 for iv in intervals if sig_min <= iv <= sig_max)
            if count > best_count:
                best_count = count
                best_match = (period, name, hw_class, count)

        if best_match is None:
            best_match = (statistics.median(intervals), "UNRECOGNISED", "UNKNOWN", 0)

        return {
            "cid": cid,
            "total": len(intervals),
            "primary_interval": best_match[0],
            "stack_match": best_match[1],
            "hardware_class": best_match[2],
            "primary_count": best_match[3],
            "primary_fraction": best_match[3] / len(intervals) if intervals else 0,
        }'''

path = r"C:\RH\rayhunter-threat-analyzer\detectors\beacon_periodicity_scorer_v2.py"
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

if OLD.strip() not in content:
    print("ERROR: Could not find target block — check whitespace")
    # Show what's actually there around _classify_intervals
    idx = content.find("def _classify_intervals")
    print("Found at char:", idx)
    print(content[idx:idx+600])
else:
    new_content = content.replace(OLD, FIX)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("PATCHED OK")
