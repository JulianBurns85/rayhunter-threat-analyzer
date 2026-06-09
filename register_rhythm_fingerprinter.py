#!/usr/bin/env python3
"""Patches main.py to register BehavioralRhythmFingerprinter."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_IMPORT = "from detectors.regulatory_escalation_scorer import RegulatoryEscalationScorer"
NEW_IMPORT = (
    "from detectors.regulatory_escalation_scorer import RegulatoryEscalationScorer\n"
    "from detectors.behavioral_rhythm_fingerprinter import BehavioralRhythmFingerprinter"
)

OLD_INST = "        RegulatoryEscalationScorer(cfg),"
NEW_INST = (
    "        RegulatoryEscalationScorer(cfg),\n"
    "        BehavioralRhythmFingerprinter(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find RegulatoryEscalationScorer import")
elif OLD_INST not in content:
    print("ERROR: Could not find RegulatoryEscalationScorer instantiation")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — BehavioralRhythmFingerprinter registered")
