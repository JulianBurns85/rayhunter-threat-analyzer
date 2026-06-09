#!/usr/bin/env python3
"""Patches main.py to register CrossCarrierTimerCorrelator."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_IMPORT = "from detectors.dual_device_temporal_segregator import DualDeviceTemporalSegregator"
NEW_IMPORT = (
    "from detectors.dual_device_temporal_segregator import DualDeviceTemporalSegregator\n"
    "from detectors.cross_carrier_timer_correlator import CrossCarrierTimerCorrelator"
)

OLD_INST = "        DualDeviceTemporalSegregator(cfg),"
NEW_INST = (
    "        DualDeviceTemporalSegregator(cfg),\n"
    "        CrossCarrierTimerCorrelator(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find DualDeviceTemporalSegregator import")
elif OLD_INST not in content:
    print("ERROR: Could not find DualDeviceTemporalSegregator instantiation")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — CrossCarrierTimerCorrelator registered")
