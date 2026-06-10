#!/usr/bin/env python3
"""Fix JitterDNATracker - add None guard in analyze() before calling _build_evidence."""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\jitter_dna_tracker.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# The bug: when CASTNET has Device B data but intervals are too short,
# dna comes back None but _build_evidence still gets called.
# Fix: fall back to _build_from_confirmed_values() if dna is None

OLD = '''        evidence = self._build_evidence(
            intervals_ms, srsran_intervals, dna, daily_jitter, swap_events
        )

        severity = "CRITICAL" if dna and dna.get("count", 0) >= 10 else "HIGH"
        confidence = "CONFIRMED" if dna and dna.get("count", 0) >= 5 else "PROBABLE"'''

NEW = '''        # If dna is None (not enough srsRAN intervals), fall back to confirmed values
        if dna is None:
            return self._build_from_confirmed_values()

        evidence = self._build_evidence(
            intervals_ms, srsran_intervals, dna, daily_jitter, swap_events
        )

        severity = "CRITICAL" if dna.get("count", 0) >= 10 else "HIGH"
        confidence = "CONFIRMED" if dna.get("count", 0) >= 5 else "PROBABLE"'''

if OLD not in content:
    print("ERROR: Could not find target block")
    # Show context
    idx = content.find("evidence = self._build_evidence(")
    print("Context:", content[idx-100:idx+300])
else:
    content = content.replace(OLD, NEW)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — JitterDNA falls back to confirmed values when dna is None")
