#!/usr/bin/env python3
"""
Cipher Downgrade Detector
=========================
Detects null-cipher attacks (EEA0/EIA0) and 2G forced downgrades.

Rules:
  CRITICAL: SecurityModeCommand with EEA0 + EIA0 (full null cipher)
  CRITICAL: RRC Connection Release with GERAN redirect (forced 2G downgrade)
  HIGH:     SecurityModeCommand with EEA0 only (no encryption, has integrity)
  HIGH:     SecurityModeCommand with EIA0 only (no integrity, has encryption)
  MEDIUM:   GSM Cipher Mode Command with A5/0 (plaintext 2G)
  HIGH:     SecurityModeCommand with no prior Authentication

Fix history:
  v2.1 (9 May 2026): Corrected false-positive EEA0 detection. Previous versions
  fired on any event containing an EEA0 field, including UE capability
  advertisements and NAS fields that coincidentally contained zero values.
  tshark verification (April 11, 2026) confirmed ZERO actual EEA0
  SecurityModeCommands across all M7350 dual-unit captures. All confirmed
  SecurityModeCommands use EEA2/EIA2 (AES-128) — Harris Transparent Proxy mode.

  The detector now ONLY fires on events where:
  (a) msg_type is explicitly "Security Mode Command", AND
  (b) cipher_alg field is explicitly "EEA0"
  UE capability advertisements are excluded by checking for
  "UECapability" in msg_type before matching cipher fields.
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


# Messages that legitimately contain EEA0 in capability fields
# These are NOT cipher downgrade events — they are capability advertisements
_CAPABILITY_MSG_TYPES = {
    "UECapabilityInformation",
    "UECapabilityEnquiry",
    "UECapabilityInfo",
    "RRCConnectionSetupComplete",  # may include UE capability
    "AttachRequest",               # includes UE network capability
}


def _is_genuine_smc(event: dict) -> bool:
    """
    Return True only if this event is a genuine SecurityModeCommand
    with an explicitly negotiated cipher algorithm.
    Excludes UE capability advertisements that contain cipher capability fields.
    """
    msg_type = (event.get("msg_type") or "").strip()

    # Must be explicitly a SecurityModeCommand
    if "Security Mode Command" not in msg_type and msg_type not in ("Security Mode Command",):
        return False

    # Must not be a UE capability message
    if any(cap in msg_type for cap in _CAPABILITY_MSG_TYPES):
        return False

    return True


class CipherDowngradeDetector(BaseDetector):
    name = "CipherDowngradeDetector"
    description = "Detects null-cipher (EEA0/EIA0) and 2G forced-downgrade attacks"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # ── Pre-process: promote threat signals to field values ────────
        # Only promote to cipher fields when the source is a genuine SMC context
        for e in events:
            threats    = e.get("threats", [])
            alerts_str = " ".join(str(a).lower() for a in e.get("harness_alerts", []))
            raw_str    = str(e.get("raw", {})).lower()
            combined   = alerts_str + " " + raw_str

            if "NULL_CIPHER" in threats and not e.get("cipher_alg"):
                # Only promote if msg_type is already SMC — don't assume
                if "Security Mode Command" in str(e.get("msg_type", "")):
                    e["cipher_alg"]    = "EEA0"
                    e["integrity_alg"] = "EIA0"

            if "GERAN_REDIRECT" in threats or "SIB_DOWNGRADE" in threats:
                e["has_geran_redirect"] = True

            if "PROSE_TRACKING" in threats:
                e["has_prose"] = True

            if "HANDOVER_INJECT" in threats:
                e["has_mobility_control"] = True

            # Only promote eea0/eia0 from raw strings when msg_type already
            # indicates a SecurityModeCommand — prevents false positives from
            # UE capability advertisements
            if "Security Mode Command" in str(e.get("msg_type", "")):
                if "eea0" in combined and not e.get("cipher_alg"):
                    e["cipher_alg"] = "EEA0"
                if "eia0" in combined and not e.get("integrity_alg"):
                    e["integrity_alg"] = "EIA0"

            if "geran" in combined or "2g redirect" in combined:
                e["has_geran_redirect"] = True

            if "proximity" in combined:
                e["has_prose"] = True

            if "handover" in combined:
                e["has_mobility_control"] = True

        # ── Rule 1: Full null cipher (EEA0 + EIA0) ────────────────────
        # Only match genuine SecurityModeCommand events — not capability ads
        full_null = [
            e for e in events
            if _is_genuine_smc(e)
            and e.get("cipher_alg") == "EEA0"
            and e.get("integrity_alg") == "EIA0"
        ]
        if full_null:
            findings.append(make_finding(
                detector=self.name,
                title="CRITICAL: Full Null-Cipher Attack (EEA0 + EIA0)",
                description=(
                    f"{len(full_null)} Security Mode Command(s) negotiated with "
                    f"EEA0 (no encryption) AND EIA0 (no integrity protection). "
                    f"This violates 3GPP TS 33.401 §5.1.3.2 which prohibits EIA0 "
                    f"in normal operation. Traffic is transmitted in PLAINTEXT with "
                    f"no tamper detection. This is the signature of a Man-in-the-Middle "
                    f"attack by a rogue base station.\n\n"
                    f"NOTE: If running against M7350 dual-unit captures from the "
                    f"Cranbourne East investigation (January 2026 onwards), zero EEA0 "
                    f"events are expected — Harris Transparent Proxy mode uses EEA2/EIA2. "
                    f"Verify against raw tshark output before submitting."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="Null-Cipher Downgrade (EEA0/EIA0 — 3GPP TS 33.401 violation)",
                evidence=self._fmt(full_null),
                events=full_null,
                hardware_hint=(
                    "Rogue eNodeB / IMSI catcher with active MitM capability "
                    "(Stingray, Cobham UMTS/LTE, Septier IMSI Catcher, or similar). "
                    "NOTE: Harris commercial devices in Transparent Proxy mode do NOT "
                    "produce EEA0 — if this fires on Cranbourne East data it is likely "
                    "a false positive from UE capability fields. Verify with tshark."
                ),
                action=(
                    "VERIFY FIRST: Run tshark -r <file> -Y "
                    "'lte_rrc.SecurityModeCommand_element' -T fields "
                    "-e lte_rrc.cipheringAlgorithm to confirm EEA0 in actual SMC.\n\n"
                    "If confirmed:\n"
                    "1. Preserve QMDL files — the SecurityModeCommand is logged with timestamp.\n"
                    "2. Cross-reference timestamps with known rogue cell activity.\n"
                    "3. Cite 3GPP TS 33.401 §5.1.3.2 in ACMA complaint.\n"
                    "4. Submit to AFP/ACORN with SecurityModeCommand decoded packet as exhibit."
                ),
                spec_ref="3GPP TS 33.401 §5.1.3.2, TS 24.301 §5.4.3",
            ))

        # ── Rule 2: EEA0 only (no encryption, has integrity) ──────────
        eea0_only = [
            e for e in events
            if _is_genuine_smc(e)
            and e.get("cipher_alg") == "EEA0"
            and e.get("integrity_alg") not in ("EIA0", None)
        ]
        if eea0_only:
            findings.append(make_finding(
                detector=self.name,
                title="Null Encryption Negotiated (EEA0) in SecurityModeCommand",
                description=(
                    f"{len(eea0_only)} Security Mode Command(s) negotiated with EEA0 "
                    f"(null encryption). Traffic is UNENCRYPTED but integrity-protected. "
                    f"Rogue device can intercept and read all NAS traffic in cleartext."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="Null Encryption (EEA0) — partial cipher downgrade",
                evidence=self._fmt(eea0_only),
                events=eea0_only,
                hardware_hint="Passive IMSI catcher or active MitM rogue eNodeB",
                action=(
                    "Document null encryption sessions. While integrity is present, "
                    "all NAS content is readable by the rogue device. "
                    "Cite 3GPP TS 33.401 §5.1.3.2 — EEA0 is prohibited in normal operation."
                ),
                spec_ref="3GPP TS 33.401 §5.1.3.2",
            ))

        # ── Rule 3: EIA0 only (no integrity, has encryption) ──────────
        eia0_only = [
            e for e in events
            if _is_genuine_smc(e)
            and e.get("integrity_alg") == "EIA0"
            and e.get("cipher_alg") not in ("EEA0", None)
        ]
        if eia0_only:
            findings.append(make_finding(
                detector=self.name,
                title="Null Integrity Protection Negotiated (EIA0)",
                description=(
                    f"{len(eia0_only)} Security Mode Command(s) negotiated with EIA0 "
                    f"(no integrity protection). Encrypted traffic can be modified in transit "
                    f"without detection. This allows command injection attacks."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="Null Integrity (EIA0) — 3GPP TS 33.401 §5.1.3.2 violation",
                evidence=self._fmt(eia0_only),
                events=eia0_only,
                hardware_hint="Rogue eNodeB with command injection capability",
                action=(
                    "EIA0 is unconditionally prohibited per 3GPP TS 33.401 §5.1.3.2. "
                    "This confirms a 3GPP standards violation by the network or rogue device."
                ),
                spec_ref="3GPP TS 33.401 §5.1.3.2",
            ))

        # ── Rule 4: Forced 2G downgrade (GERAN redirect) ──────────────
        geran_redirect = [
            e for e in events
            if e.get("has_geran_redirect")
            or "geran" in str(e.get("msg_subtype", "")).lower()
        ]
        rrc_release   = self.filter_by_type(events, ["RRC Connection Release"])
        geran_release = [e for e in rrc_release if e.get("has_geran_redirect")] or geran_redirect

        if geran_release:
            findings.append(make_finding(
                detector=self.name,
                title="Forced 2G Downgrade (GERAN Redirect in RRC Release)",
                description=(
                    f"{len(geran_release)} RRC Connection Release message(s) contained "
                    f"a GERAN (GSM/2G) redirected carrier. This forces the device to drop "
                    f"to 2G where GSM's A5/1 cipher (or A5/0 — no cipher) is trivially "
                    f"broken. This is a classic IMSI catcher downgrade attack."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="LTE→2G Forced Downgrade via GERAN Redirect",
                evidence=self._fmt(geran_release),
                events=geran_release,
                hardware_hint=(
                    "Rogue LTE eNodeB with 2G fallback — forces victim to 2G "
                    "where a paired GSM IMSI catcher operates"
                ),
                action=(
                    "1. Document the RRC Connection Release packet with GERAN IEs.\n"
                    "2. Note the target ARFCN — correlate with GSM scan data.\n"
                    "3. This is a two-stage attack: LTE rogue → forced 2G → passive intercept.\n"
                    "4. Alert: Do not use voice calls or SMS while this is active."
                ),
                spec_ref="3GPP TS 36.331 §5.3.12, TS 33.401 §C.1",
            ))

        # ── Rule 5: GSM A5/0 on 2G channel ───────────────────────────
        gsm_cipher = [
            e for e in events
            if e.get("layer") in ("GSM/2G", "NAS")
            and e.get("cipher_alg") in ("A5/0", "EEA0")
            and e.get("has_geran_redirect")
        ]
        if gsm_cipher:
            findings.append(make_finding(
                detector=self.name,
                title="GSM Null-Cipher (A5/0) on 2G Channel",
                description=(
                    f"{len(gsm_cipher)} GSM Cipher Mode Command(s) with A5/0 (no cipher). "
                    f"After being forced to 2G, the device was assigned zero encryption. "
                    f"All 2G voice and data traffic is transmitted in clear plaintext."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="GSM A5/0 Null Cipher after 2G Downgrade",
                evidence=self._fmt(gsm_cipher),
                events=gsm_cipher,
                hardware_hint="Passive GSM interceptor (paired with LTE rogue for downgrade attack)",
                action=(
                    "Combined with the LTE→2G redirect, this confirms a full "
                    "downgrade→intercept chain. Treat all communications during "
                    "this window as compromised."
                ),
                spec_ref="3GPP TS 43.020 §3.3 (A5/0)",
            ))

        # ── Rule 6: SecurityModeCommand with no prior Auth ────────────
        smc_events  = self.filter_by_type(events, ["Security Mode Command"])
        auth_events = self.filter_by_type(
            events, ["Authentication Request", "Authentication Response"]
        )
        if smc_events and not auth_events:
            findings.append(make_finding(
                detector=self.name,
                title="Security Mode Command Without Prior Authentication",
                description=(
                    f"Security Mode Command observed with no preceding Authentication "
                    f"Request/Response sequence. Legitimate LTE authentication must precede "
                    f"security mode setup. This indicates a rogue device skipping authentication "
                    f"to negotiate cipher parameters with an unauthenticated identity."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique="Unauthenticated Security Mode Negotiation",
                evidence=self._fmt(smc_events[:3]),
                events=smc_events,
                hardware_hint="Rogue eNodeB bypassing mutual authentication",
                action=(
                    "Cross-reference with Identity Request events. "
                    "No-auth → SMC combined with EEA0 is definitive IMSI catcher evidence."
                ),
                spec_ref="3GPP TS 33.401 §8.2, TS 24.301 §5.4.3",
            ))

        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts        = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg       = e.get("msg_type", "?")
            cipher    = e.get("cipher_alg", "?")
            integrity = e.get("integrity_alg", "?")
            src       = e.get("source_file", "")
            lines.append(f"[{ts}] {msg} | EEA={cipher} EIA={integrity} ({src})")
        return lines
