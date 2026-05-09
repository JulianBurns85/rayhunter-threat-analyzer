#!/usr/bin/env python3
"""
Identity Harvest Detector — IMSI/IMEI Catcher Detection
========================================================
Flags abnormal Identity Request patterns consistent with IMSI catchers.

Rules:
  CRITICAL: >2 IMSI Identity Requests within a 120-second window
  HIGH:     Identity Request for IMEI/IMEISV (device fingerprinting)
  HIGH:     Identity Request with no preceding Attach / TAU Request
  MEDIUM:   Identity Request immediately following Authentication Reject
  LOW:      Single IMSI Identity Request (baseline)
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


class IdentityHarvestDetector(BaseDetector):
    name = "IdentityHarvestDetector"
    description = "Detects IMSI/IMEI catcher patterns via abnormal Identity Request sequences"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        id_requests = self.filter_by_type(events, ["Identity Request"])
        if not id_requests:
            id_requests = [
                e for e in events
                if (
                    "IMSI_HARVEST" in e.get("threats", [])
                    or "IMSI_EXPOSURE_CONTEXT" in e.get("threats", [])
                    or any("imsi" in str(a).lower() or "identity" in str(a).lower()
                           for a in e.get("harness_alerts", []))
                )
            ]

        if not id_requests:
            return findings

        # ── Rule 1: IMSI requests ─────────────────────────────────────
        imsi_reqs = [
            e for e in id_requests
            if e.get("identity_type") in ("IMSI", None)
            and (
                "Identity Request" in str(e.get("msg_type", ""))
                or any("imsi" in str(a).lower() or "identity" in str(a).lower()
                       for a in e.get("harness_alerts", []))
                or e.get("msg_type") is None  # harness-alert sourced events
            )
        ]

        window = self.thresholds.get("identity_request_window_seconds", 120)
        max_normal = self.thresholds.get("identity_request_max_normal", 2)

        if len(imsi_reqs) > max_normal:
            timestamps = [self.parse_timestamp(e) for e in imsi_reqs]
            valid_ts = [t for t in timestamps if t > 0]
            # If timestamps are missing/unparseable, treat all events as in-window
            in_window = self._count_in_window(valid_ts, window) if valid_ts else len(imsi_reqs)

            if in_window > max_normal:
                findings.append(make_finding(
                    detector=self.name,
                    title="IMSI Catcher — Excessive Identity Requests",
                    description=(
                        f"{in_window} IMSI Identity Requests detected within a "
                        f"{window}-second window. Normal LTE operation requires "
                        f"≤{max_normal} Identity Requests. This pattern is the "
                        f"primary signature of active IMSI catcher (Stingray) operation."
                    ),
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    technique="IMSI Harvesting via Identity Request Flood",
                    evidence=self._format_evidence(imsi_reqs[:8]),
                    events=imsi_reqs,
                    hardware_hint="Active IMSI catcher (IMSI grabber / Stingray / Cobham / Septier)",
                    action=(
                        "1. Preserve all NDJSON/QMDL files with SHA-256 manifest.\n"
                        "2. Document exact timestamps for legal evidence.\n"
                        "3. Reference 3GPP TS 24.301 §5.4.4 (Identity Procedure).\n"
                        "4. Submit to ACMA under Radiocommunications Act 1992 s.189.\n"
                        "5. Include in AFP/ACORN referral as primary IMSI catcher evidence."
                    ),
                    spec_ref="3GPP TS 24.301 §5.4.4, TS 33.401 §8.2",
                ))
            elif len(imsi_reqs) == 1:
                # Single IMSI request — log but don't alarm
                findings.append(make_finding(
                    detector=self.name,
                    title="IMSI Identity Request Observed",
                    description="A single IMSI Identity Request was observed. Alone this is "
                                "not conclusive — monitor for repeated requests.",
                    severity="LOW",
                    confidence="SUSPECTED",
                    technique="Identity Request",
                    evidence=self._format_evidence(imsi_reqs[:2]),
                    events=imsi_reqs,
                    action="Monitor for repeated IMSI requests. Cross-reference with cell ID.",
                    spec_ref="3GPP TS 24.301 §5.4.4",
                ))

        # ── Rule 2: IMEI/IMEISV request (device fingerprinting) ───────
        imei_reqs = [
            e for e in id_requests
            if e.get("identity_type") in ("IMEI/IMEISV", "IMEI", "IMEISV")
        ]
        if imei_reqs:
            findings.append(make_finding(
                detector=self.name,
                title="IMEI/IMEISV Device Fingerprinting Detected",
                description=(
                    f"{len(imei_reqs)} Identity Request(s) for IMEI/IMEISV observed. "
                    f"Networks should never request IMEI in normal operation — this is "
                    f"a strong indicator of targeted device fingerprinting by a rogue device."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="IMEI Harvesting / Device Fingerprinting",
                evidence=self._format_evidence(imei_reqs),
                events=imei_reqs,
                hardware_hint="IMSI catcher with device fingerprinting capability (IMEI mode)",
                action=(
                    "IMEI collection by rogue device is illegal under the "
                    "Telecommunications (Interception and Access) Act 1979 (Cth).\n"
                    "Document and include in AFP complaint."
                ),
                spec_ref="3GPP TS 24.301 §5.4.4.3, TS 33.401",
            ))

        # ── Rule 3: Identity Request with no prior Attach/TAU ─────────
        attach_events = self.filter_by_type(
            events, ["Attach Request", "Tracking Area Update Request"]
        )
        if imsi_reqs and not attach_events:
            findings.append(make_finding(
                detector=self.name,
                title="Unprovoked Identity Request — No Prior Attach",
                description=(
                    "Identity Request(s) observed with no preceding Attach or "
                    "Tracking Area Update Request. Legitimate networks only request "
                    "identity during attach procedures. Unprovoked requests indicate "
                    "a rogue device is probing for IMSI."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique="Unprovoked IMSI Solicitation",
                evidence=self._format_evidence(imsi_reqs[:4]),
                events=imsi_reqs,
                hardware_hint="Rogue base station (IMSI catcher in active mode)",
                action="Cross-reference with cell ID and timing to locate transmitter.",
                spec_ref="3GPP TS 24.301 §5.4.4",
            ))

        # ── Rule 4: Identity Request after Auth Reject ─────────────────
        auth_rejects = self.filter_by_type(events, ["Authentication Reject"])
        if auth_rejects and imsi_reqs:
            for ar in auth_rejects:
                ar_ts = self.parse_timestamp(ar)
                nearby_reqs = [
                    r for r in imsi_reqs
                    if abs(self.parse_timestamp(r) - ar_ts) < 10
                ]
                if nearby_reqs:
                    findings.append(make_finding(
                        detector=self.name,
                        title="Identity Request Following Authentication Reject",
                        description=(
                            "An Identity Request was sent within 10 seconds of an "
                            "Authentication Reject. This is a known IMSI catcher technique: "
                            "reject auth to force the UE to reveal its IMSI in plaintext."
                        ),
                        severity="HIGH",
                        confidence="CONFIRMED",
                        technique="Auth Reject → Identity Request (IMSI extraction)",
                        evidence=self._format_evidence([ar] + nearby_reqs),
                        events=[ar] + nearby_reqs,
                        hardware_hint="Active IMSI catcher (auth reject + re-request pattern)",
                        action="This sequence is a textbook Stingray attack. Preserve evidence.",
                        spec_ref="3GPP TS 24.301 §5.4.3.2",
                    ))
                    break

        return findings

    def _count_in_window(self, timestamps: List[float], window: float) -> int:
        """Return max number of timestamps falling within any window-second span."""
        if not timestamps:
            return 0
        timestamps = sorted(timestamps)
        max_count = 1
        start = 0
        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > window:
                start += 1
            max_count = max(max_count, end - start + 1)
        return max_count

    def _format_evidence(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg = e.get("msg_type", "?")
            id_t = e.get("identity_type", "")
            cell = e.get("cell_id", "")
            earfcn = e.get("earfcn", "")
            src = e.get("source_file", "")
            line = f"[{ts}] {msg}"
            if id_t:
                line += f" id_type={id_t}"
            if cell:
                line += f" cell={cell}"
            if earfcn:
                line += f" EARFCN={earfcn}"
            if src:
                line += f" ({src})"
            lines.append(line)
        return lines
