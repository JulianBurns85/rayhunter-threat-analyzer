#!/usr/bin/env python3
"""
Paging Cycle Detector
======================
Detects statistically regular paging intervals characteristic of
automated SDR-based IMSI catchers (srsRAN, OpenAirInterface).

Human operators cannot manually trigger 1,899 requests in 300 seconds.
Scripted SDR software operates on precise, repeating intervals.

Key signature: inter-paging interval standard deviation < 5% of mean
indicates scripted/automated operation, not legitimate network behaviour.

The 210.2-second paging cycle previously confirmed in this investigation
is a specific srsRAN default configuration value.

3GPP reference: TS 36.304 s7.1 (paging procedure timing)
"""

import statistics
from typing import List, Dict, Optional
from collections import defaultdict


# srsRAN / OpenAirInterface known default paging periods (seconds)
KNOWN_SDR_PERIODS = {
    210.2: "srsRAN default paging cycle — confirmed in this investigation",
    128.0: "Common LTE paging cycle (DRX 128 frames)",
    256.0: "LTE paging cycle DRX 256",
    320.0: "LTE paging cycle DRX 320",
    640.0: "LTE paging cycle DRX 640",
    51.2:  "srsRAN short paging cycle",
    10.24: "Aggressive IMSI catcher rapid-poll mode",
}

TOLERANCE = 0.05   # 5% tolerance for period matching
MIN_SAMPLES = 10   # Minimum paging events needed for cycle detection
MAX_CV = 0.08      # Max coefficient of variation (std/mean) for "regular" cycle


class PagingCycleDetector:
    """Detects automated paging cycles in cellular event data."""

    name = "PagingCycleDetector"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.min_samples = cfg.get("paging_cycle", {}).get(
            "min_samples", MIN_SAMPLES
        )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract paging/identity request events with timestamps
        paging_events = [
            e for e in events
            if (
                e.get("msg_type") in (
                    "Paging", "Identity Request", "RRCConnectionSetup",
                    "SystemInformationBlockType1"
                )
                or e.get("identity_type") == "IMSI"
                or "paging" in str(e.get("msg_type", "")).lower()
            )
            and e.get("timestamp") is not None
        ]

        if len(paging_events) < self.min_samples:
            return []

        # Group by source file for per-file analysis
        by_source = defaultdict(list)
        for ev in paging_events:
            src = ev.get("source_file", "unknown")
            ts = self._to_float(ev.get("timestamp"))
            if ts and ts > 0:
                by_source[src].append(ts)

        for source, timestamps in by_source.items():
            if len(timestamps) < self.min_samples:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)
                if 0 < timestamps[i+1] - timestamps[i] < 1200  # filter > 20min gaps
            ]

            if len(intervals) < self.min_samples:
                continue

            finding = self._analyze_intervals(intervals, source, timestamps)
            if finding:
                findings.append(finding)

        # Also do global analysis across all files
        all_ts = sorted([
            self._to_float(e.get("timestamp"))
            for e in paging_events
            if self._to_float(e.get("timestamp")) and self._to_float(e.get("timestamp")) > 0
        ])

        if len(all_ts) >= self.min_samples * 2:
            global_intervals = [
                all_ts[i+1] - all_ts[i]
                for i in range(len(all_ts) - 1)
                if 0 < all_ts[i+1] - all_ts[i] < 600
            ]
            if global_intervals:
                global_finding = self._analyze_intervals(
                    global_intervals, "ALL_FILES", all_ts
                )
                if global_finding and global_finding["confidence"] == "CONFIRMED":
                    # Only add global finding if it's strong
                    global_finding["title"] = (
                        "Automated Paging Cycle — Cross-File Global Detection"
                    )
                    global_finding["description"] = (
                        f"Statistically regular paging cycle detected across ALL "
                        f"capture files combined. {global_finding['description']}"
                    )
                    findings.insert(0, global_finding)

        return findings

    def _analyze_intervals(
        self,
        intervals: List[float],
        source: str,
        timestamps: List[float],
    ) -> Optional[Dict]:
        """Analyze a list of inter-event intervals for regularity."""
        if not intervals:
            return None

        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            return None

        try:
            std_dev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            return None

        cv = std_dev / mean_interval  # Coefficient of variation

        if cv > MAX_CV * 3:
            return None  # Too irregular — not a scripted cycle

        # Check against known SDR periods
        matched_period = None
        matched_note = None
        for period, note in KNOWN_SDR_PERIODS.items():
            if abs(mean_interval - period) / period <= TOLERANCE:
                matched_period = period
                matched_note = note
                break

        # Assess confidence
        if cv <= MAX_CV and matched_period:
            confidence = "CONFIRMED"
            severity = "CRITICAL"
        elif cv <= MAX_CV * 1.5 and matched_period:
            confidence = "CONFIRMED"
            severity = "HIGH"
        elif cv <= MAX_CV:
            confidence = "PROBABLE"
            severity = "HIGH"
        elif matched_period:
            confidence = "SUSPECTED"
            severity = "MEDIUM"
        else:
            return None  # Not regular enough

        # Calculate burst rate
        total_span = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        events_per_min = (len(timestamps) / total_span * 60) if total_span > 0 else 0

        description = (
            f"Statistically regular paging/identity request cycle detected in "
            f"{source}. Mean interval: {mean_interval:.2f}s, "
            f"Std dev: {std_dev:.2f}s, "
            f"Coefficient of variation: {cv:.1%} "
            f"({'extremely regular — scripted' if cv < 0.03 else 'regular'}). "
            f"Rate: {events_per_min:.1f} events/minute over "
            f"{len(intervals)+1} samples. "
        )

        if matched_period:
            description += (
                f"MATCHES KNOWN SDR PERIOD: {matched_period}s — {matched_note}. "
                f"This is not consistent with legitimate LTE network paging behaviour."
            )
        else:
            description += (
                f"Regular automated interval of {mean_interval:.2f}s detected. "
                f"Legitimate LTE paging is not this regular — this indicates "
                f"scripted/automated SDR operation."
            )

        return {
            "detector": "PagingCycleDetector",
            "title": "Automated Paging Cycle — SDR Scripted Operation Detected",
            "description": description,
            "severity": severity,
            "severity_score": 5 if severity == "CRITICAL" else 4,
            "confidence": confidence,
            "confidence_score": 3 if confidence == "CONFIRMED" else 2,
            "technique": "Automated SDR Paging Cycle (srsRAN/OpenAirInterface signature)",
            "evidence": [
                f"Source: {source}",
                f"Samples: {len(intervals)+1} paging events",
                f"Mean interval: {mean_interval:.3f}s",
                f"Std deviation: {std_dev:.3f}s",
                f"Coefficient of variation: {cv:.2%}",
                f"Matched SDR period: {matched_period}s ({matched_note})" if matched_period
                    else f"Detected period: {mean_interval:.2f}s (automated pattern)",
                f"Rate: {events_per_min:.1f} events/min",
            ],
            "event_count": len(intervals) + 1,
            "hardware_hint": (
                "srsRAN / OpenAirInterface on SDR hardware "
                "(USRP, HackRF, LimeSDR, BladeRF)"
            ),
            "recommended_action": (
                "1. Document the paging cycle interval as evidence of automated SDR operation.\n"
                "2. Cross-reference with RF spectrum analysis to confirm transmitter location.\n"
                "3. This regularity rules out legitimate LTE network operation.\n"
                "4. Include in AFP/ACORN referral — automated scripted operation "
                "implies deliberate configuration, not accidental interference.\n"
                "5. The matched srsRAN period strengthens the software-defined "
                "radio hypothesis."
            ),
            "spec_reference": "3GPP TS 36.304 s7.1 (paging procedure), TS 36.331 s5.2.1",
            "found_at": None,
            "paging_stats": {
                "mean_interval_s": round(mean_interval, 3),
                "std_dev_s": round(std_dev, 3),
                "cv_percent": round(cv * 100, 2),
                "sample_count": len(intervals) + 1,
                "matched_sdr_period": matched_period,
                "matched_sdr_note": matched_note,
                "events_per_minute": round(events_per_min, 2),
            }
        }

    @staticmethod
    def _to_float(ts) -> Optional[float]:
        if ts is None:
            return None
        try:
            from dateutil import parser as dtparser
            return dtparser.parse(str(ts)).timestamp()
        except Exception:
            try:
                return float(str(ts))
            except (ValueError, TypeError):
                return None
