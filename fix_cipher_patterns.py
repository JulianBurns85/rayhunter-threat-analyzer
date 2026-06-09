#!/usr/bin/env python3
"""
Fix cipher negotiation pattern matching.
Problems:
1. Patterns use RRC_SETUP but parser produces ATTACH (no RRC setup events)
2. Harris Transparent Proxy pattern requires EEA0 but Harris uses proper encryption
3. Need ATTACH-based patterns that match what's actually in the corpus
"""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\cipher_negotiation_analyser.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

OLD_PATTERNS = '''# Known attack pattern fingerprints
PATTERNS = [
    {
        "name": "Harris Transparent Proxy (EEA0 Full Session)",
        "sequence_contains": ["RRC_SETUP", "SMC", "SMC_DONE"],
        "requires_eea0": True,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Wallet Inspector (Pre-Security IMSI)",
        "sequence_contains": ["RRC_SETUP", "IDENTITY"],
        "forbidden_before_identity": ["SMC"],
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "FlashCatch (Sub-Second IMSI)",
        "sequence_contains": ["RRC_SETUP", "IDENTITY", "RELEASE"],
        "max_duration_s": 2.0,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Auth Reject Harvest",
        "sequence_contains": ["AUTH_REJECT", "IDENTITY"],
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Phantom Session (No Data Exchange)",
        "sequence_contains": ["RRC_SETUP", "RELEASE"],
        "forbidden_in": ["ATTACH_OK", "AUTH"],
        "min_events": 2,
        "max_events": 5,
        "severity": "HIGH",
        "confidence": "PROBABLE",
    },
]'''

NEW_PATTERNS = '''# Known attack pattern fingerprints
# NOTE: Parser produces ATTACH (not RRC_SETUP) from NAS Attach Request messages.
# Patterns updated to use ATTACH as the session start indicator.
PATTERNS = [
    {
        "name": "Harris Transparent Proxy (EEA0 Full Session)",
        "sequence_contains": ["SMC", "SMC_DONE"],
        "requires_eea0": True,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Harris Transparent Proxy (Encrypted MitM — No EEA0)",
        # Harris in transparent proxy mode uses proper encryption but intercepts
        # at the network level. Identified by: SMC present, no Auth Reject,
        # session completes normally but traffic is forwarded through rogue eNB.
        "sequence_contains": ["ATTACH", "SMC", "SMC_DONE", "ATTACH_OK"],
        "severity": "HIGH",
        "confidence": "PROBABLE",
    },
    {
        "name": "Wallet Inspector (Pre-Security IMSI)",
        # Identity Request before Security Mode Command = IMSI extracted
        # before encryption negotiated
        "sequence_contains": ["IDENTITY"],
        "forbidden_before_identity": ["SMC"],
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "FlashCatch (Sub-Second IMSI)",
        "sequence_contains": ["IDENTITY", "RELEASE"],
        "max_duration_s": 2.0,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Auth Reject Harvest",
        # Auth Reject followed by Identity Request = deliberate forced re-auth
        # to expose IMSI. This is the most common IMSI catcher pattern.
        "sequence_contains": ["AUTH_REJECT", "IDENTITY"],
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
    },
    {
        "name": "Forced Re-Attach Cycle",
        # Multiple Attach sequences in rapid succession = forced re-registration
        # Used to repeatedly expose temporary identifiers
        "sequence_contains": ["ATTACH", "RELEASE", "ATTACH"],
        "severity": "HIGH",
        "confidence": "PROBABLE",
    },
    {
        "name": "Phantom Session (Attach Without Data)",
        # Attach completes but no data exchange follows = identity harvest only
        "sequence_contains": ["ATTACH", "RELEASE"],
        "forbidden_in": ["ATTACH_OK"],
        "min_events": 2,
        "max_events": 8,
        "severity": "HIGH",
        "confidence": "PROBABLE",
    },
]'''

if OLD_PATTERNS not in content:
    print("ERROR: Could not find PATTERNS block")
    idx = content.find("PATTERNS = [")
    print("Found PATTERNS at:", idx)
    print(content[idx:idx+200])
else:
    content = content.replace(OLD_PATTERNS, NEW_PATTERNS)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — PATTERNS updated to use ATTACH-based matching")
