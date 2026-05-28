#!/usr/bin/env python3
"""
RRCReconfigurationPeriodicityDetector — Detects metronomic reconfig cycles.

Refactored from new_detectors.py to use BaseDetector + make_finding().
Place in: detectors/rrc_reconfig_periodicity.py

Known signatures:
  - T4: ~88.1s reconfiguration cycle (observed Cranbourne East, May 2026)

References:
  - 3GPP TS 36.331 §5.3.5 (RRC Connection Reconfiguration)
  - Harris operator manuals (leaked via The Intercept, 2016)
"""

import statistics
from typing import List, Dict
from .base import BaseDetector, make_finding

CV_THRESHOLD  = 0.05    # metronomic — < 5% coefficient of variation
CV_MODERATE   = 0.15    # periodic — < 15%
MIN_INTERVALS = 4
PAIR_THRESHOLD= 5.0     # seconds — ignore rapid paired events
MAX_GAP       = 600.0   # seconds — ignore overnight gaps

KNOWN_RECONFIG_PERIODS = {
    88.1:  "T4 signature — observed Cranbourne East May 2026",
    210.2: "srsRAN default timer — confirmed investigation primary signature",
    60.0:  "Harris periodic measurement sweep (1-minute)",
    30.0:  "Aggressive measurement sweep",
}
PERIOD_TOLERANCE = 0.05


class RRCReconfigurationPeriodicityDetector(BaseDetector):
    """
    Detects metronomic periodicity in RRCConnectionReconfiguration events.

    The existing RRCPeriodicityDetector covers RRCConnectionRelease timing.
    This detector covers periodic Reconfiguration events WITHOUT connection
    release — a distinct IMSI catcher mode for timed measurement sweeps.
    """

    name        = "RRCReconfigurationPeriodicityDetector"
    description = "Detects metronomic RRC Reconfiguration cycles (timed measurement sweep)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        reconfig_times = sorted([
            self.parse_timestamp(ev)
            for ev in events
            if "rrcconnectionreconfiguration" in str(ev.get("msg_type","")).lower()
            and "complete" not in str(ev.get("msg_type","")).lower()
            and self.parse_timestamp(ev) > 0
        ])

        if len(reconfig_times) < MIN_INTERVALS + 1:
            return findings

        raw_deltas = [
            reconfig_times[i] - reconfig_times[i-1]
            for i in range(1, len(reconfig_times))
        ]

        major = [d for d in raw_deltas if PAIR_THRESHOLD < d < MAX_GAP]

        if len(major) < MIN_INTERVALS:
            return findings

        mean_iv = statistics.mean(major)
        sd_iv   = statistics.stdev(major) if len(major) > 1 else 0.0
        cv      = sd_iv / mean_iv if mean_iv > 0 else float("inf")

        if cv >= CV_MODERATE:
            return findings

        # Check known periods
        matched_period = matched_note = None
        for period, note in KNOWN_RECONFIG_PERIODS.items():
            if abs(mean_iv - period) / period <= PERIOD_TOLERANCE:
                matched_period = period
                matched_note   = note
                break

        if   cv < CV_THRESHOLD:   severity, confidence = "CRITICAL", "CONFIRMED"
        elif cv < CV_MODERATE:    severity, confidence = "HIGH",     "PROBABLE"
        else: return findings

        # Longest consecutive streak within 5% tolerance
        streak = max_streak = 0
        tol = mean_iv * 0.05
        for d in major:
            if abs(d - mean_iv) <= tol:
                streak += 1
                max_streak = max(max_streak, streak)
            else:
                streak = 0

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"RRC Reconfiguration Periodicity — "
                f"{mean_iv:.1f}s ± {sd_iv:.3f}s "
                f"(CV={cv:.4f})"
                + (f" — MATCHES {matched_period}s" if matched_period else "")
            ),
            description=(
                f"{len(major)} major RRCConnectionReconfiguration intervals "
                f"with mean {mean_iv:.3f}s, SD {sd_iv:.3f}s, CV {cv:.4f}. "
                f"{'Metronomic-grade (CV < 5%)' if cv < CV_THRESHOLD else 'Periodic'}. "
                f"Longest consecutive streak: {max_streak} intervals. "
                + (f"MATCHES known period {matched_period}s — {matched_note}. " if matched_period else "")
                + f"Metronomic RRC reconfiguration is not produced by legitimate "
                f"network operations — consistent with a cell site simulator "
                f"performing timed measurement sweeps."
            ),
            severity=severity,
            confidence=confidence,
            technique="Metronomic RRC Reconfiguration cycle — timed measurement sweep",
            evidence=[
                f"Total reconfigurations: {len(reconfig_times)}",
                f"Major intervals: {len(major)}",
                f"Mean: {mean_iv:.4f}s | SD: {sd_iv:.4f}s | CV: {cv:.6f}",
                f"Longest streak: {max_streak}",
                f"Range: {min(major):.3f}s – {max(major):.3f}s",
                (f"Matched period: {matched_period}s ({matched_note})"
                 if matched_period else "No known period match"),
            ],
            events=[],
            action=(
                "Document RRC Reconfiguration period as evidence of timed measurement sweep. "
                "Cross-reference with RRCConnectionRelease timing for composite signature. "
                "Include in VicPol USB evidence package."
            ),
            spec_ref="3GPP TS 36.331 §5.3.5 (RRC Connection Reconfiguration)",
            hardware_hint="Harris HailStorm / StingRay II timed measurement sweep mode",
        ))

        return findings
