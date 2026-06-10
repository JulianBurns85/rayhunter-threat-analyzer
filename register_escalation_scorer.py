#!/usr/bin/env python3
"""Patches main.py to register RegulatoryEscalationScorer."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_IMPORT = "from detectors.cross_carrier_timer_correlator import CrossCarrierTimerCorrelator"
NEW_IMPORT = (
    "from detectors.cross_carrier_timer_correlator import CrossCarrierTimerCorrelator\n"
    "from detectors.regulatory_escalation_scorer import RegulatoryEscalationScorer"
)

OLD_INST = "        CrossCarrierTimerCorrelator(cfg),"
NEW_INST = (
    "        CrossCarrierTimerCorrelator(cfg),\n"
    "        RegulatoryEscalationScorer(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find CrossCarrierTimerCorrelator import")
elif OLD_INST not in content:
    print("ERROR: Could not find CrossCarrierTimerCorrelator instantiation")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — RegulatoryEscalationScorer registered")
