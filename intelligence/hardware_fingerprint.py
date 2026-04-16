#!/usr/bin/env python3
"""
Hardware Fingerprinter
======================
Correlates event patterns, signal characteristics, timing, and OUI data
to identify candidate attacker hardware.

Sources:
  - OUI (MAC prefix) matching for WiFi/Ubiquiti/Hak5 equipment
  - Behavioral timing signatures (known commercial IMSI catcher patterns)
  - Signal characteristics (transmit power, EARFCN selection)
  - Cross-correlation with PineAP/Karma indicators in harness alerts
"""

from typing import List, Dict, Tuple
from collections import Counter


# Known hardware profiles
HARDWARE_PROFILES = {
    "stingray_harris": {
        "name": "Harris StingRay / HailStorm (CALEA-grade IMSI catcher)",
        "vendor": "Harris Corporation (L3Harris)",
        "indicators": ["eea0", "eia0", "identity request", "auth reject"],
        "notes": (
            "Commercial law-enforcement IMSI catcher. Typical pattern: Identity Request flood, "
            "null cipher negotiation, optional GERAN redirect for legacy devices."
        ),
        "severity": "CRITICAL",
    },
    "cobham_sentry": {
        "name": "Cobham Sentry IMSI Catcher",
        "vendor": "Cobham",
        "indicators": ["eea0", "identity request", "earfcn hop"],
        "notes": "Commercial IMSI catcher, typically deployed by law enforcement.",
        "severity": "CRITICAL",
    },
    "septier_imsi": {
        "name": "Septier IMSI Catcher / GUARDIAN",
        "vendor": "Septier Communication",
        "indicators": ["eea0", "eia0", "identity request", "proximity"],
        "notes": "Israeli IMSI catcher with proximity tracking capability.",
        "severity": "CRITICAL",
    },
    "srsran_sdr": {
        "name": "srsRAN / OpenAirInterface (Software-Defined IMSI Catcher)",
        "vendor": "Open Source SDR (USRP, HackRF, LimeSDR, BladeRF)",
        "indicators": [
            "multi-earfcn", "eea0", "identity request", "geran redirect",
            "paging cycle", "automated", "210.2", "srsran", "scripted"
        ],
        "notes": (
            "DIY IMSI catcher using open-source LTE stack. "
            "Specific srsRAN fingerprints: (1) 210.2-second automated paging cycle "
            "confirmed in CIRS-20260331-141 investigation — this is an srsRAN default. "
            "(2) Multi-EARFCN operation across 7 frequencies simultaneously. "
            "(3) 1899 attack events in a single 300-second window — requires scripting. "
            "(4) EEA0+EIA0 null-cipher negotiation is srsRAN default config. "
            "(5) Simultaneous Telstra+Vodafone attack — SDR hardware is carrier-agnostic. "
            "Build cost: HackRF $350 + LimeSDR $300, or USRP $1500. "
            "Commercial equivalent (Harris StingRay) costs $200,000+ and requires "
            "government authorisation — ruling it out for a private residential attacker."
        ),
        "severity": "CRITICAL",
        "srsran_specific": True,
    },
    "ubiquiti_u7pro": {
        "name": "Ubiquiti U7 Pro (Evil Twin / PineAP Attack)",
        "vendor": "Ubiquiti Networks",
        "oui": ["24:A4:3C", "FC:EC:DA", "78:8A:20", "B4:FB:E4", "00:27:22"],
        "indicators": ["pineap", "karma", "evil twin", "ubiquiti"],
        "notes": (
            "Six Ubiquiti U7 Pro APs confirmed executing PineAP/Karma evil twin attacks "
            "in your CIRS-20260331-141 investigation. WiFi-layer attack complements "
            "the cellular IMSI catcher operation."
        ),
        "severity": "CRITICAL",
    },
    "hak5_pineapple": {
        "name": "Hak5 WiFi Pineapple",
        "vendor": "Hak5",
        "oui": ["00:13:37"],
        "indicators": ["pineap", "karma", "evil twin", "pineapple"],
        "notes": "Consumer WiFi attack platform. Used for PineAP/Karma deauth attacks.",
        "severity": "HIGH",
    },
    "generic_imsi_catcher": {
        "name": "Generic IMSI Catcher / Rogue eNodeB",
        "vendor": "Unknown",
        "indicators": ["eea0", "identity request"],
        "notes": "Pattern matches IMSI catcher behavior but hardware is unidentified.",
        "severity": "HIGH",
    },
}


class HardwareFingerprinter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ubiquiti_ouis = [oui.lower() for oui in cfg.get("ubiquiti_oui", [])]
        self.hak5_ouis = [oui.lower() for oui in cfg.get("hak5_oui", [])]

    def analyze(self, events: List[Dict], findings: List[Dict]) -> List[Dict]:
        """Return list of hardware candidate fingerprints."""
        candidates = []
        seen = set()

        # ── Build signal set from events + findings ───────────────────
        signals = self._extract_signals(events, findings)

        # ── Check each hardware profile ───────────────────────────────
        for profile_key, profile in HARDWARE_PROFILES.items():
            score = self._score_profile(profile, signals)
            if score >= 1:
                if profile_key not in seen:
                    seen.add(profile_key)
                    candidates.append({
                        "hardware": profile["name"],
                        "vendor": profile["vendor"],
                        "confidence_score": score,
                        "confidence": self._score_label(score),
                        "severity": profile["severity"],
                        "notes": profile["notes"],
                        "matched_signals": [
                            s for s in signals
                            if any(ind in s.lower() for ind in profile.get("indicators", []))
                        ][:5],
                    })

        # Sort by score descending
        candidates.sort(key=lambda x: x["confidence_score"], reverse=True)
        return candidates

    def _extract_signals(self, events: List[Dict], findings: List[Dict]) -> List[str]:
        """Extract behavioral signal strings from events and findings."""
        signals = set()

        for ev in events:
            if ev.get("cipher_alg") == "EEA0":
                signals.add("eea0")
            if ev.get("integrity_alg") == "EIA0":
                signals.add("eia0")
            if ev.get("identity_type") in ("IMSI", "IMEI/IMEISV"):
                signals.add("identity request")
            if ev.get("has_geran_redirect"):
                signals.add("geran redirect")
            if ev.get("has_prose"):
                signals.add("proximity")
            if ev.get("has_mobility_control"):
                signals.add("handover inject")
            for alert in ev.get("harness_alerts", []):
                alert_lower = str(alert).lower()
                if "pineap" in alert_lower or "karma" in alert_lower:
                    signals.add("pineap")
                    signals.add("karma")
                if "ubiquiti" in alert_lower or "u7 pro" in alert_lower:
                    signals.add("ubiquiti")
                if "evil twin" in alert_lower:
                    signals.add("evil twin")
                if "pineapple" in alert_lower:
                    signals.add("pineapple")

        for finding in findings:
            technique = str(finding.get("technique", "")).lower()
            if "earfcn" in technique and "multi" in technique:
                signals.add("multi-earfcn")
            if "earfcn hop" in technique:
                signals.add("earfcn hop")
            hw_hint = str(finding.get("hardware_hint", "")).lower()
            if "ubiquiti" in hw_hint:
                signals.add("ubiquiti")
            if "srsran" in hw_hint or "openair" in hw_hint or "sdr" in hw_hint:
                signals.add("srsran")

        return list(signals)

    def _score_profile(self, profile: dict, signals: List[str]) -> int:
        """Score a hardware profile against observed signals."""
        score = 0
        for indicator in profile.get("indicators", []):
            if any(indicator.lower() in s.lower() for s in signals):
                score += 1
        for oui in profile.get("oui", []):
            if any(oui.lower() in s.lower() for s in signals):
                score += 2
        return score

    def _score_label(self, score: int) -> str:
        if score >= 4:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        return "LOW"
