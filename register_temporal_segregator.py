#!/usr/bin/env python3
"""Patches main.py to register DualDeviceTemporalSegregator."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_IMPORT = "from detectors.imsi_harvest_chain_sequencer import IMSIHarvestChainSequencer"
NEW_IMPORT = (
    "from detectors.imsi_harvest_chain_sequencer import IMSIHarvestChainSequencer\n"
    "from detectors.dual_device_temporal_segregator import DualDeviceTemporalSegregator"
)

OLD_INST = "        IMSIHarvestChainSequencer(cfg),"
NEW_INST = (
    "        IMSIHarvestChainSequencer(cfg),\n"
    "        DualDeviceTemporalSegregator(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find chain sequencer import")
elif OLD_INST not in content:
    print("ERROR: Could not find chain sequencer instantiation")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — DualDeviceTemporalSegregator registered")
