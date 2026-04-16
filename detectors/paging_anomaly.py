#!/usr/bin/env python3
"""
Paging Anomaly Detector
=======================
Legitimate LTE networks page devices using Temporary Mobile Subscriber Identity
(S-TMSI / TMSI), never IMSI. IMSI-targeted paging is a surveillance technique
used by IMSI catchers to locate a specific subscriber.

Rules:
  CRITICAL: Any paging using IMSI (should always be S-TMSI/TMSI)
  HIGH:     Paging rate significantly above baseline (silent SMS / stealth ping)
  MEDIUM:   Paging observed immediately after IMSI Identity Request
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


class PagingAnomalyDetector(BaseDetector):
    name = "PagingAnomalyDetector"
    description = "Detects IMSI-targeted paging and abnormal paging patterns"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        paging_events = [
            e for e in events
            if e.get("paging_type") is not None
            or "paging" in str(e.get("msg_type", "")).lower()
        ]

        if not paging_events:
            return findings

        # ── Rule 1: IMSI-targeted paging ──────────────────────────────
        imsi_pages = [e for e in paging_events if e.get("paging_type") == "IMSI"]
        if imsi_pages:
            findings.append(make_finding(
                detector=self.name,
                title="IMSI-Targeted Paging Detected",
                description=(
                    f"{len(imsi_pages)} Paging message(s) used IMSI as the paging identity. "
                    f"3GPP TS 24.301 requires networks to use S-TMSI for paging in LTE. "
                    f"IMSI-targeted paging reveals the subscriber's permanent identity and "
                    f"is used by IMSI catchers to locate a specific target subscriber."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="IMSI-Targeted Paging (location surveillance)",
                evidence=self._fmt(imsi_pages),
                events=imsi_pages,
                hardware_hint="IMSI catcher in location-tracking mode",
                action=(
                    "1. This is a direct violation of 3GPP TS 24.301 §5.6.2.\n"
                    "2. Document paging channel content and timestamps.\n"
                    "3. IMSI-paging combined with forced downgrade = location tracking chain.\n"
                    "4. Report to ACMA and include in AFP referral."
                ),
                spec_ref="3GPP TS 24.301 §5.6.2, TS 36.304 §7",
            ))

        # ── Rule 2: High paging rate (silent SMS / stealth ping) ──────
        total = len(paging_events)
        imsi_ratio = len(imsi_pages) / total if total > 0 else 0
        threshold = self.thresholds.get("paging_imsi_ratio_threshold", 0.20)

        if imsi_ratio > threshold and total > 5:
            findings.append(make_finding(
                detector=self.name,
                title=f"High IMSI Paging Ratio ({imsi_ratio:.0%} of pages use IMSI)",
                description=(
                    f"{len(imsi_pages)} of {total} paging messages ({imsi_ratio:.0%}) "
                    f"used IMSI. Threshold is {threshold:.0%}. "
                    f"This sustained rate suggests active location tracking via "
                    f"repeated silent paging (type 0 SMS / stealth ping)."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique="Silent SMS / Stealth Paging (sustained IMSI location tracking)",
                evidence=self._fmt(paging_events[:5]),
                events=imsi_pages,
                hardware_hint="Persistent IMSI catcher in location-tracking mode",
                action=(
                    "Silent SMS (Type 0) does not appear on the device but triggers paging. "
                    "This is used for real-time location tracking. "
                    "Include paging timeline in AFP referral."
                ),
                spec_ref="3GPP TS 23.040 §9.2.3.9 (Type 0 SMS)",
            ))

        # ── Rule 3: Paging burst after Identity Request ────────────────
        id_requests = self.filter_by_type(events, ["Identity Request"])
        if id_requests and imsi_pages:
            for ir in id_requests:
                ir_ts = self.parse_timestamp(ir)
                nearby_pages = [
                    p for p in imsi_pages
                    if 0 < self.parse_timestamp(p) - ir_ts < 30
                ]
                if nearby_pages:
                    findings.append(make_finding(
                        detector=self.name,
                        title="IMSI Paging Within 30s of Identity Request",
                        description=(
                            "IMSI-targeted paging occurred within 30 seconds of an "
                            "Identity Request. This sequence: Identity Request → IMSI harvest "
                            "→ IMSI-targeted paging confirms active subscriber tracking — "
                            "the attacker is confirming device location after harvesting IMSI."
                        ),
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        technique="IMSI Harvest → Location Confirmation (correlated event chain)",
                        evidence=self._fmt([ir] + nearby_pages[:3]),
                        events=[ir] + nearby_pages,
                        action=(
                            "This correlated event chain (Identity Request → IMSI Paging) is "
                            "the strongest possible indicator of active targeting. "
                            "Submit as primary evidence to AFP."
                        ),
                        spec_ref="3GPP TS 24.301 §5.4.4, §5.6.2",
                    ))
                    break

        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg = e.get("msg_type", "?")
            pt = e.get("paging_type", "?")
            cell = e.get("cell_id", "?")
            src = e.get("source_file", "")
            lines.append(f"[{ts}] {msg} paging_id={pt} cell={cell} ({src})")
        return lines
