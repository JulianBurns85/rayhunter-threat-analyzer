#!/usr/bin/env python3
"""
Fixes CipherNegotiationSequenceAnalyser:
1. MSG_MAP keys missing spaces (authenticationreject vs authentication reject)
2. SESSION_GAP_S too tight (60s → 300s)
3. Auth Reject pattern needs space-variant key
"""

path = r"C:\RH\rayhunter-threat-analyzer\detectors\cipher_negotiation_analyser.py"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix 1: SESSION_GAP_S too tight
OLD_GAP = "SESSION_GAP_S = 60.0"
NEW_GAP = "SESSION_GAP_S = 300.0  # expanded from 60s — Auth Reject sequences can be minutes apart"

# Fix 2: Add space-variant MSG_MAP keys for all compound message types
OLD_MAP = '''MSG_MAP = {
    "rrcconnectionsetup":          "RRC_SETUP",
    "rrcconnectionsetupcomplete":  "RRC_SETUP",
    "securitymodecommand":         "SMC",
    "security mode command":       "SMC",
    "securitymodecomplete":        "SMC_DONE",
    "securitymodereject":          "SMC_REJECT",
    "identityrequest":             "IDENTITY",
    "identity request":            "IDENTITY",
    "attachrequest":               "ATTACH",
    "attachaccept":                "ATTACH_OK",
    "attachreject":                "ATTACH_REJECT",
    "rrcconnectionrelease":        "RELEASE",
    "rrc connection release":      "RELEASE",
    "authenticationrequest":       "AUTH",
    "authenticationreject":        "AUTH_REJECT",
}'''

NEW_MAP = '''MSG_MAP = {
    # No-space variants (concatenated field names)
    "rrcconnectionsetup":          "RRC_SETUP",
    "rrcconnectionsetupcomplete":  "RRC_SETUP",
    "securitymodecommand":         "SMC",
    "securitymodecomplete":        "SMC_DONE",
    "securitymodereject":          "SMC_REJECT",
    "identityrequest":             "IDENTITY",
    "attachrequest":               "ATTACH",
    "attachaccept":                "ATTACH_OK",
    "attachreject":                "ATTACH_REJECT",
    "rrcconnectionrelease":        "RELEASE",
    "authenticationrequest":       "AUTH",
    "authenticationreject":        "AUTH_REJECT",
    "authenticationfailure":       "AUTH_REJECT",
    # Space variants (human-readable message_type field values)
    "security mode command":       "SMC",
    "security mode complete":      "SMC_DONE",
    "security mode reject":        "SMC_REJECT",
    "identity request":            "IDENTITY",
    "attach request":              "ATTACH",
    "attach accept":               "ATTACH_OK",
    "attach reject":               "ATTACH_REJECT",
    "rrc connection release":      "RELEASE",
    "rrc connection setup":        "RRC_SETUP",
    "authentication request":      "AUTH",
    "authentication reject":       "AUTH_REJECT",
    "authentication failure":      "AUTH_REJECT",
    "auth reject":                 "AUTH_REJECT",
    # Threat/alert string variants
    "imsi_harvest":                "IDENTITY",
    "imsi_exposure":               "IDENTITY",
    "auth_reject":                 "AUTH_REJECT",
    "identity_request":            "IDENTITY",
}'''

errors = []
if OLD_GAP not in content:
    errors.append("ERROR: SESSION_GAP_S line not found")
if OLD_MAP not in content:
    errors.append("ERROR: MSG_MAP block not found")
    # Show what IS there
    idx = content.find("MSG_MAP")
    print("Found MSG_MAP at:", idx)
    print(content[idx:idx+300])

if errors:
    for e in errors:
        print(e)
else:
    content = content.replace(OLD_GAP, NEW_GAP)
    content = content.replace(OLD_MAP, NEW_MAP)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK — MSG_MAP space variants added, SESSION_GAP_S expanded to 300s")
