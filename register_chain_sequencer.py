#!/usr/bin/env python3
"""Patches main.py to register IMSIHarvestChainSequencer."""

path = r"C:\RH\rayhunter-threat-analyzer\main.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add import after IdentityHarvestDetector import
OLD_IMPORT = "from detectors.identity_harvest  import IdentityHarvestDetector"
NEW_IMPORT = (
    "from detectors.identity_harvest  import IdentityHarvestDetector\n"
    "from detectors.imsi_harvest_chain_sequencer import IMSIHarvestChainSequencer"
)

# Add instantiation after IdentityHarvestDetector instantiation
OLD_INST = "        IdentityHarvestDetector(cfg),"
NEW_INST = (
    "        IdentityHarvestDetector(cfg),\n"
    "        IMSIHarvestChainSequencer(cfg),"
)

if OLD_IMPORT not in content:
    print("ERROR: Could not find import line")
elif OLD_INST not in content:
    print("ERROR: Could not find instantiation line")
else:
    content = content.replace(OLD_IMPORT, NEW_IMPORT)
    content = content.replace(OLD_INST, NEW_INST)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — IMSIHarvestChainSequencer registered")
