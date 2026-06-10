#!/usr/bin/env python3
"""Patches main.py to register JitterDNATracker."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_IMPORT = "from detectors.behavioral_rhythm_fingerprinter import BehavioralRhythmFingerprinter"
NEW_IMPORT = (
    "from detectors.behavioral_rhythm_fingerprinter import BehavioralRhythmFingerprinter\n"
    "from detectors.jitter_dna_tracker import JitterDNATracker"
)

OLD_INST = "        BehavioralRhythmFingerprinter(cfg),"
NEW_INST = (
    "        BehavioralRhythmFingerprinter(cfg),\n"
    "        JitterDNATracker(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find BehavioralRhythmFingerprinter import")
elif OLD_INST not in content:
    print("ERROR: Could not find BehavioralRhythmFingerprinter instantiation")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — JitterDNATracker registered")
