#!/usr/bin/env python3
"""
Cipher Downgrade Detector
=========================
Detects null-cipher attacks (EEA0/EIA0) and 2G forced downgrades from
explicit protocol fields without mutating caller event dicts or firing
on raw capability text alone.
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


_CAPABILITY_MSG_TYPES = {
    "UECapabilityInformation",
    "UECapabilityEnquiry",
    "UECapabilityInfo",
    "RRCConnectionSetupComplete",
    "AttachRequest",
}


def _is_genuine_smc(event: dict) -> bool:
    msg_type = (event.get("msg_type") or "").strip()
    if "Security Mode Command" not in msg_type:
        return False
    if any(cap in msg_type for cap in _CAPABILITY_MSG_TYPES):
        return False
    return True


class CipherDowngradeDetector(BaseDetector):
    name = "CipherDowngradeDetector"
    description = "Detects null-cipher (EEA0/EIA0) and 2G forced-downgrade attacks"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Rule 1: Full null cipher (EEA0 + EIA0) on explicit SMC
        full_null = [
            e for e in events
            if _is_genuine_smc(e)
            and e.get("cipher_alg") == "EEA0"
            and e.get("integrity_alg") == "EIA0"
        ]
        if full_null:
            findings.append(make_finding(
                detector=self.name,
                title="Null Cipher Attack Detected (EEA0 + EIA0)",
                description=(
                    f"{len(full_null)} Security Mode Command(s) negotiated with "
                    f"EEA0 (null encryption) and EIA0 (null integrity)."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="Null Cipher Downgrade (EEA0/EIA0 ? 3GPP TS 33.401 ?5.1.3.2)",
                evidence=self._fmt(full_null),
                events=full_null,
                spec_ref="3GPP TS 33.401 ?5.1.3.2, TS 24.301 ?5.4.3",
            ))

        # Rule 2: EEA0 only (no encryption, has integrity) on explicit SMC
        eea0_only = [
            e for e in events
            if _is_genuine_smc(e)
            and e.get("cipher_alg") == "EEA0"
            and e.get("integrity_alg") not in ("EIA0", None)
        ]
        if eea0_only:
            findings.append(make_finding(
                detector=self.name,
                title="Null Cipher Encryption Negotiated (EEA0) in SecurityModeCommand",
                description=(
                    f"{len(eea0_only)} Security Mode Command(s) negotiated with EEA0 "
                    f"(null encryption) and integrity protection."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="Null Cipher Encryption (EEA0)",
                evidence=self._fmt(eea0_only),
                events=eea0_only,
                spec_ref="3GPP TS 33.401 ?5.1.3.2",
            ))

        # Rule 3: EIA0 only (no integrity, has encryption) on explicit SMC
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
                    f"(no integrity protection)."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="Null Integrity (EIA0 ? 3GPP TS 33.401 ?5.1.3.2)",
                evidence=self._fmt(eia0_only),
                events=eia0_only,
                spec_ref="3GPP TS 33.401 ?5.1.3.2",
            ))

        # Rule 4: Forced 2G downgrade (GERAN redirect in RRC Connection Release only)
        rrc_release = self.filter_by_type(events, ["RRC Connection Release"])
        geran_release = [
            e for e in rrc_release
            if bool(e.get("has_geran_redirect"))
            or "geran" in str(e.get("msg_subtype", "")).lower()
        ]
        if geran_release:
            findings.append(make_finding(
                detector=self.name,
                title="Forced 2G Downgrade (GERAN Redirect in RRC Release)",
                description=(
                    f"{len(geran_release)} RRC Connection Release message(s) contained "
                    f"a GERAN redirect."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="LTE->2G Forced Downgrade via GERAN Redirect",
                evidence=self._fmt(geran_release),
                events=geran_release,
                spec_ref="3GPP TS 36.331 ?5.3.12, TS 33.401 ?C.1",
            ))

        # Rule 5: GSM A5/0 on 2G channel with redirect
        gsm_cipher = [
            e for e in events
            if e.get("layer") in ("GSM/2G",)
            and e.get("cipher_alg") == "A5/0"
            and bool(e.get("has_geran_redirect"))
        ]
        if gsm_cipher:
            findings.append(make_finding(
                detector=self.name,
                title="GSM Null-Cipher (A5/0) on 2G Channel",
                description=(
                    f"{len(gsm_cipher)} GSM Cipher Mode Command(s) with A5/0."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="GSM A5/0 Null Cipher after 2G Downgrade",
                evidence=self._fmt(gsm_cipher),
                events=gsm_cipher,
                spec_ref="3GPP TS 43.020 ?3.3 (A5/0)",
            ))

        # Rule 6: SecurityModeCommand with no prior Auth
        smc_events = [
            e for e in events
            if _is_genuine_smc(e)
            and (e.get("cipher_alg") is not None or e.get("integrity_alg") is not None)
        ]
        auth_events = self.filter_by_type(
            events, ["Authentication Request", "Authentication Response"]
        )
        if smc_events and not auth_events:
            findings.append(make_finding(
                detector=self.name,
                title="Security Mode Command Without Prior Authentication",
                description=(
                    "Security Mode Command observed with no preceding Authentication "
                    "Request/Response sequence."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique="Unauthenticated Security Mode Negotiation",
                evidence=self._fmt(smc_events[:3]),
                events=smc_events,
                spec_ref="3GPP TS 33.401 ?8.2, TS 24.301 ?5.4.3",
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
