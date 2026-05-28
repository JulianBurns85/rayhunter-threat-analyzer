#!/usr/bin/env python3
"""
MeasurementReportRateDetector — Flags forced high-frequency measurement reporting.

Refactored from new_detectors.py to use BaseDetector + make_finding().
Place in: detectors/measurement_report_rate.py

References:
  - 3GPP TS 36.331 §5.5.5 (Measurement reporting)
  - 3GPP TS 36.331 §6.3.5 (ReportConfigEUTRA — reportInterval IE)
"""

import statistics
from typing import List, Dict
from .base import BaseDetector, make_finding

HIGH_THRESHOLD   = 10.0   # seconds — tracking-grade
MEDIUM_THRESHOLD = 30.0   # seconds — aggressive
MIN_REPORTS      = 10
MIN_INTERVAL     = 1.0    # filter sub-second duplicates
MAX_INTERVAL     = 15.0   # filter cross-release boundary gaps

# 3GPP TS 36.331 reportInterval enum values (ms)
REPORT_INTERVALS_MS = [
    120, 240, 480, 640, 1024, 2048, 5120, 10240,
    20480, 40960, 60000, 360000, 720000, 1800000, 3600000
]


class MeasurementReportRateDetector(BaseDetector):
    """
    Detects forced high-frequency MeasurementReport intervals.

    Legitimate cells use reportInterval 120s–240s.
    IMSI catchers tracking location configure aggressive intervals
    (e.g. ms5120 = 5.12s) to continuously monitor target RF environment.
    """

    name        = "MeasurementReportRateDetector"
    description = "Detects tracking-grade measurement report rates"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        mr_times = sorted([
            self.parse_timestamp(ev)
            for ev in events
            if "measurementreport" in str(ev.get("msg_type","")).lower()
            and self.parse_timestamp(ev) > 0
        ])

        if len(mr_times) < MIN_REPORTS:
            return findings

        intervals = [
            mr_times[i] - mr_times[i-1]
            for i in range(1, len(mr_times))
            if MIN_INTERVAL <= mr_times[i] - mr_times[i-1] <= MAX_INTERVAL
        ]

        if len(intervals) < MIN_REPORTS:
            return findings

        mean_iv = statistics.mean(intervals)
        sd_iv   = statistics.stdev(intervals) if len(intervals) > 1 else 0.0

        if   mean_iv < HIGH_THRESHOLD:   severity, confidence = "HIGH",   "CONFIRMED"
        elif mean_iv < MEDIUM_THRESHOLD: severity, confidence = "MEDIUM", "PROBABLE"
        else: return findings

        connection_count = sum(
            1 for ev in events
            if "securitymodecommand" in str(ev.get("msg_type","")).lower()
            and "complete" not in str(ev.get("msg_type","")).lower()
        )
        rpc = len(mr_times) / connection_count if connection_count > 0 else len(mr_times)

        # Nearest 3GPP reportInterval
        ri_ms    = round(mean_iv * 1000)
        ri_3gpp  = min(REPORT_INTERVALS_MS, key=lambda v: abs(v - ri_ms))

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Forced MeasurementReport — {mean_iv:.2f}s interval "
                f"(≈ reportInterval ms{ri_3gpp})"
            ),
            description=(
                f"{len(mr_times)} MeasurementReports with mean interval "
                f"{mean_iv:.3f}s ± {sd_iv:.3f}s (n={len(intervals)}). "
                f"Corresponds to reportInterval ≈ ms{ri_3gpp} in RRC Reconfiguration. "
                f"Normal cells use reportInterval 120s–240s. "
                f"A {mean_iv:.1f}s interval is tracking-grade, consistent with "
                f"an IMSI catcher performing continuous RF environment monitoring. "
                f"Reports per connection: {rpc:.1f}."
            ),
            severity=severity,
            confidence=confidence,
            technique="Forced high-frequency measurement reporting for location tracking",
            evidence=[
                f"Total reports: {len(mr_times)}",
                f"Valid intervals: {len(intervals)}",
                f"Mean: {mean_iv:.4f}s | SD: {sd_iv:.4f}s",
                f"Min: {min(intervals):.3f}s | Max: {max(intervals):.3f}s",
                f"Estimated reportInterval: ms{ri_3gpp}",
                f"Reports per connection: {rpc:.1f}",
            ],
            events=[],
            action=(
                "Compare against legitimate baseline (expected >120s for normal cells). "
                "Cross-reference with RRC Reconfiguration to extract exact reportInterval IE. "
                "Include in evidence package."
            ),
            spec_ref="3GPP TS 36.331 §5.5.5, §6.3.5 (ReportConfigEUTRA)",
            hardware_hint="Harris HailStorm active location tracking mode",
        ))

        return findings
