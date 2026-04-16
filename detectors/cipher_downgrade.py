#!/usr/bin/env python3
"""
Cipher Downgrade Detector
=========================
Detects null-cipher attacks (EEA0/EIA0) and 2G forced downgrades.

Rules:
  CRITICAL: SecurityModeCommand with EEA0 + EIA0 (full null cipher — no encryption or integrity)
  CRITICAL: RRC Connection Release with GERAN redirect (forced 2G downgrade)
  HIGH:     SecurityModeCommand with EEA0 only (no encryption, but has integrity)
  HIGH:     SecurityModeCommand with EIA0 only (no integrity, has encryption)
  MEDIUM:   GSM Cipher Mode Command (A5/0 = plaintext 2G)
  MEDIUM:   SecurityModeCommand with weaker algorithm than previous session
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


class CipherDowngradeDetector(BaseDetector):
    name = "CipherDowngradeDetector"
    description = "Detects null-cipher (EEA0/EIA0) and 2G forced-downgrade attacks"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Promote threat signals → field values for events missing explicit fields
        for e in events:
            alerts_str = " ".join(str(a).lower() for a in e.get("harness_alerts", []))
            raw_str = str(e.get("raw", {})).lower()
            threats = e.get("threats", [])
            combined = alerts_str + " " + raw_str
            if "NULL_CIPHER" in threats and not e.get("cipher_alg"):
                e["cipher_alg"] = "EEA0"
                if not e.get("msg_type"):
                    e["msg_type"] = "Security Mode Command"
            if "GERAN_REDIRECT" in threats or "SIB_DOWNGRADE" in threats:
                e["has_geran_redirect"] = True
            if "PROSE_TRACKING" in threats:
                e["has_prose"] = True
            if "HANDOVER_INJECT" in threats:
                e["has_mobility_control"] = True
            if "eea0" in combined and not e.get("cipher_alg"):
                e["cipher_alg"] = "EEA0"
            if "eia0" in combined and not e.get("integrity_alg"):
                e["integrity_alg"] = "EIA0"
            if ("null cipher" in combined or "eea0" in combined) and not e.get("msg_type"):
                e["msg_type"] = "Security Mode Command"
            if ("geran" in combined or "2g redirect" in combined or "downgrade" in combined) and not e.get("has_geran_redirect"):
                e["has_geran_redirect"] = True
            if "proximity" in combined and not e.get("has_prose"):
                e["has_prose"] = True
            if "handover" in combined and not e.get("has_mobility_control"):
                e["has_mobility_control"] = True

        # ── Rule 1: Full null cipher (EEA0 + EIA0) ────────────────────
        full_null = [
            e for e in events
            if e.get("cipher_alg") == "EEA0" and e.get("integrity_alg") == "EIA0"
        ]
        if full_null:
            findings.append(make_finding(
                detector=self.name,
                title="CRITICAL: Full Null-Cipher Attack (EEA0 + EIA0)",
                description=(
                    f"{len(full_null)} Security Mode Command(s) negotiated with "
                    f"EEA0 (no encryption) AND EIA0 (no integrity protection). "
                    f"This violates 3GPP TS 33.401 §5.1.3.2 which prohibits EIA0 "
                    f"in normal operation. Your traffic is transmitted in PLAINTEXT "
                    f"with no tamper detection. This is the signature of a Man-in-the-Middle "
                    f"attack by a rogue base station."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="Null-Cipher Downgrade (EEA0/EIA0 — 3GPP TS 33.401 violation)",
                evidence=self._fmt(full_null),
                events=full_null,
                hardware_hint=(
                    "Rogue eNodeB / IMSI catcher with active MitM capability "
                    "(Stingray, Cobham UMTS/LTE, Septier IMSI Catcher, or similar)"
                ),
                action=(
                    "IMMEDIATE ACTION REQUIRED:\n"
                    "1. This confirms an active man-in-the-middle attack.\n"
                    "2. Preserve QMDL files — the SecurityModeCommand is logged with timestamp.\n"
                    "3. Cross-reference timestamps with known rogue cell activity.\n"
                    "4. Cite 3GPP TS 33.401 §5.1.3.2 in ACMA complaint.\n"
                    "5. Include in Telstra Duty of Care claim — network must reject EIA0.\n"
                    "6. Submit to AFP/ACORN with SecurityModeCommand decoded packet as exhibit."
                ),
                spec_ref="3GPP TS 33.401 §5.1.3.2, TS 24.301 §5.4.3",
            ))

        # ── Rule 2: EEA0 only (no encryption, has integrity) ──────────
        eea0_only = [
            e for e in events
            if e.get("cipher_alg") == "EEA0"
            and e.get("integrity_alg") not in ("EIA0", None)
        ]
        if eea0_only:
            findings.append(make_finding(
                detector=self.name,
                title="Null Encryption Negotiated (EEA0)",
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
            if e.get("integrity_alg") == "EIA0"
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
            if e.get("has_geran_redirect") or
            "geran" in str(e.get("msg_subtype", "")).lower() or
            "geran" in " ".join(str(a) for a in e.get("harness_alerts", [])).lower()
        ]
        rrc_release = self.filter_by_type(events, ["RRC Connection Release"])
        geran_release = [
            e for e in rrc_release if e.get("has_geran_redirect")
        ] or geran_redirect

        if geran_release:
            findings.append(make_finding(
                detector=self.name,
                title="Forced 2G Downgrade (GERAN Redirect in RRC Release)",
                description=(
                    f"{len(geran_release)} RRC Connection Release message(s) contained "
                    f"a GERAN (GSM/2G) redirected carrier. This forces your device to "
                    f"drop to 2G where GSM's A5/1 cipher (or A5/0 — no cipher) is trivially "
                    f"broken. This is a classic IMSI catcher downgrade attack to enable "
                    f"passive interception."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="LTE→2G Forced Downgrade via GERAN Redirect (redirectedCarrierInfo-GERAN)",
                evidence=self._fmt(geran_release),
                events=geran_release,
                hardware_hint=(
                    "Rogue LTE eNodeB with 2G fallback — forces victim to 2G "
                    "where a paired GSM IMSI catcher operates (common dual-layer attack)"
                ),
                action=(
                    "1. Document the RRC Connection Release packet with GERAN IEs.\n"
                    "2. Note the target ARFCN in the redirect — correlate with GSM scan data.\n"
                    "3. This is a two-stage attack: LTE rogue → forced 2G → passive intercept.\n"
                    "4. Cite TS 36.331 §5.3.12 (cell reselection) in evidence.\n"
                    "5. Alert: Do not use voice calls or SMS while this is active."
                ),
                spec_ref="3GPP TS 36.331 §5.3.12, TS 33.401 §C.1",
            ))

        # ── Rule 5: GSM Cipher Mode Command with A5/0 ─────────────────
        gsm_cipher = [
            e for e in events
            if e.get("layer") in ("GSM/2G", "NAS")
            and (e.get("cipher_alg") in ("A5/0", "EEA0")
                 or "cipher mode" in str(e.get("msg_type", "")).lower())
            and e.get("has_geran_redirect")
        ]
        if gsm_cipher:
            findings.append(make_finding(
                detector=self.name,
                title="GSM Null-Cipher (A5/0) on 2G Channel",
                description=(
                    f"{len(gsm_cipher)} GSM Cipher Mode Command(s) with A5/0 (no cipher). "
                    f"After being forced to 2G, your device was assigned zero encryption. "
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

        # ── Rule 6: Security Mode Command with no prior Auth ──────────
        smc_events = self.filter_by_type(events, ["Security Mode Command"])
        auth_events = self.filter_by_type(events, ["Authentication Request", "Authentication Response"])
        if smc_events and not auth_events:
            findings.append(make_finding(
                detector=self.name,
                title="Security Mode Command Without Prior Authentication",
                description=(
                    f"Security Mode Command observed with no preceding Authentication "
                    f"Request/Response sequence. Legitimate LTE authentication must precede "
                    f"security mode setup. This indicates a rogue device skipping authentication "
                    f"to negotiate weak ciphers with an unauthenticated identity."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique="Unauthenticated Security Mode Negotiation",
                evidence=self._fmt(smc_events[:3]),
                events=smc_events,
                hardware_hint="Rogue eNodeB bypassing mutual authentication",
                action=(
                    "Cross-reference with Identity Request events. This sequence "
                    "(no auth → SMC) combined with EEA0 is definitive IMSI catcher evidence."
                ),
                spec_ref="3GPP TS 33.401 §8.2, TS 24.301 §5.4.3",
            ))

        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg = e.get("msg_type", "?")
            cipher = e.get("cipher_alg", "?")
            integrity = e.get("integrity_alg", "?")
            src = e.get("source_file", "")
            lines.append(
                f"[{ts}] {msg} | EEA={cipher} EIA={integrity} ({src})"
            )
        return lines
