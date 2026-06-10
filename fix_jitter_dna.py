#!/usr/bin/env python3
"""Fix JitterDNATracker NoneType error in _build_from_confirmed_values."""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\jitter_dna_tracker.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# The bug: evidence list contains a conditional expression that can be None
# Fix the oscillator class line that calls dna.get() when dna is None
OLD = '''        evidence.append(
            f"OSCILLATOR CLASS INFERENCE:\\n"
            f"  CV={dna.get('cv', 0.1):.2f}% → oscillator class: "
            f"{'TCXO (temperature-compensated)' if dna and dna.get('cv', 1) < 0.5 else 'VCTCXO or better'}\\n"
            f"  bladeRF 2.0 xA4 uses: VCTCXO (voltage-controlled TCXO)\\n"
            f"  Confirmed match: bladeRF 2.0 xA4 hardware fingerprint."
        )'''

NEW = '''        cv_val = dna.get('cv', 0.1) if dna else 0.1
        osc_class = 'TCXO (temperature-compensated)' if cv_val < 0.5 else 'VCTCXO or better'
        evidence.append(
            f"OSCILLATOR CLASS INFERENCE:\\n"
            f"  CV={cv_val:.2f}% -> oscillator class: {osc_class}\\n"
            f"  bladeRF 2.0 xA4 uses: VCTCXO (voltage-controlled TCXO)\\n"
            f"  Confirmed match: bladeRF 2.0 xA4 hardware fingerprint."
        )'''

if OLD not in content:
    # Try alternative fix — patch _build_from_confirmed_values to not call dna.get
    # The real issue is the format string with conditional inside f-string
    print("Primary fix not found - applying defensive patch")
    # Add None guard at top of _build_evidence
    OLD2 = "    def _build_evidence(self, intervals_ms, srsran_intervals,\n                        dna, daily_jitter, swap_events) -> List[str]:\n        evidence = []"
    NEW2 = "    def _build_evidence(self, intervals_ms, srsran_intervals,\n                        dna, daily_jitter, swap_events) -> List[str]:\n        evidence = []\n        if dna is None:\n            dna = {}"
    if OLD2 in content:
        content = content.replace(OLD2, NEW2)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print("PATCHED OK — defensive None guard added to _build_evidence")
    else:
        print("ERROR: Could not find patch point")
else:
    content = content.replace(OLD, NEW)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — oscillator class f-string fixed")
