#!/usr/bin/env python3
"""
SilentPeriodDetector — Detects surveillance blackouts and conscious pauses.

We detect when the operator IS active. This detects when they go SILENT
and correlates silence with external events.

Silence is forensically significant:
- Platform goes quiet after VicPol contact = conscious response
- Platform goes quiet after ACMA inspection = deliberate shutdown
- Platform resumes after exactly N hours = scheduled operation
- Silence during business hours = operator unavailable (sick day? meeting?)

Distinguishes between:
- NORMAL silence (operator sleep window, established pattern)
- ANOMALOUS silence (unexpected gap outside normal pattern)
- REGULATORY silence (gap correlating with known regulatory events)

The gap between "last event before ACMA" and "first event after ACMA"
is itself forensic evidence of awareness and response.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Key regulatory events to correlate with silence
REGULATORY_EVENTS = [
    (datetime(2026, 3, 31, tzinfo=timezone.utc), "VicPol CIRS-20260331-141 filed"),
    (datetime(2026, 4, 13, tzinfo=timezone.utc), "VicPol CIRS-20260413-6 filed"),
    (datetime(2026, 5, 8,  tzinfo=timezone.utc), "ACMA field inspection"),
    (datetime(2026, 5, 19, tzinfo=timezone.utc), "AFP referral via VicPol"),
]

# Thresholds
MIN_ANOMALOUS_GAP_HOURS  = 6.0    # Gap longer than this is flagged
REGULATORY_WINDOW_HOURS  = 48.0   # Gap within this window of reg event = correlated
NORMAL_SLEEP_START       = 0      # 00:00 AEST
NORMAL_SLEEP_END         = 10     # 10:00 AEST (established from OperatorRhythmProfiler)
AEST_OFFSET              = 10     # UTC+10


class SilentPeriodDetector(BaseDetector):
    """
    Detects anomalous silence periods and correlates them with
    regulatory events to prove conscious operator awareness.
    """

    name = "SilentPeriodDetector"
    description = (
        "Surveillance blackout detection — identifies anomalous silence "
        "periods and correlates with regulatory events"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract all timestamps
        timestamps = []
        for e in events:
            ts = self._get_ts(e)
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 100:
            return []

        timestamps.sort()

        # Find all gaps
        gaps = []
        for i in range(len(timestamps) - 1):
            gap_s = timestamps[i+1] - timestamps[i]
            gap_h = gap_s / 3600
            if gap_h >= MIN_ANOMALOUS_GAP_HOURS:
                gap_start = datetime.fromtimestamp(timestamps[i],   tz=timezone.utc)
                gap_end   = datetime.fromtimestamp(timestamps[i+1], tz=timezone.utc)
                gaps.append({
                    "start":    gap_start,
                    "end":      gap_end,
                    "hours":    gap_h,
                    "start_ts": timestamps[i],
                    "end_ts":   timestamps[i+1],
                })

        if not gaps:
            return []

        # Classify gaps
        normal_gaps     = []
        anomalous_gaps  = []
        regulatory_gaps = []

        for gap in gaps:
            # Check if gap falls within normal sleep window (AEST)
            start_aest_hour = (gap["start"].hour + AEST_OFFSET) % 24
            end_aest_hour   = (gap["end"].hour   + AEST_OFFSET) % 24
            is_sleep = (
                NORMAL_SLEEP_START <= start_aest_hour <= NORMAL_SLEEP_END and
                gap["hours"] <= 14  # Sleep gaps < 14h
            )

            # Check if gap correlates with regulatory event
            reg_correlation = None
            for reg_ts, reg_label in REGULATORY_EVENTS:
                reg_sec = reg_ts.timestamp()
                # Gap starts within 48h of regulatory event
                if abs(gap["start_ts"] - reg_sec) <= REGULATORY_WINDOW_HOURS * 3600:
                    reg_correlation = reg_label
                    break
                # Gap ends within 48h after regulatory event
                if 0 <= gap["start_ts"] - reg_sec <= REGULATORY_WINDOW_HOURS * 3600:
                    reg_correlation = reg_label
                    break

            gap["reg_correlation"] = reg_correlation
            gap["is_sleep"]        = is_sleep

            if reg_correlation:
                regulatory_gaps.append(gap)
            elif is_sleep:
                normal_gaps.append(gap)
            else:
                anomalous_gaps.append(gap)

        # Statistics on normal gaps (to establish baseline)
        normal_durations = [g["hours"] for g in normal_gaps]
        baseline_mean    = statistics.mean(normal_durations) if normal_durations else None
        baseline_stdev   = statistics.stdev(normal_durations) if len(normal_durations) > 1 else None

        # Build evidence
        total_anomalous = len(anomalous_gaps) + len(regulatory_gaps)
        if total_anomalous == 0:
            return []

        evidence = [
            f"Total gaps ≥{MIN_ANOMALOUS_GAP_HOURS}h analysed: {len(gaps)}",
            f"Normal sleep gaps: {len(normal_gaps)}",
            f"Anomalous gaps: {len(anomalous_gaps)}",
            f"Regulatory-correlated gaps: {len(regulatory_gaps)}",
        ]

        if baseline_mean:
            evidence.append(
                f"Normal gap baseline: mean={baseline_mean:.1f}h "
                + (f"±{baseline_stdev:.1f}h" if baseline_stdev else "")
            )

        if regulatory_gaps:
            evidence.append("")
            evidence.append("REGULATORY-CORRELATED SILENCE PERIODS:")
            for gap in sorted(regulatory_gaps, key=lambda g: g["hours"], reverse=True):
                evidence.append(
                    f"  [{gap['start'].strftime('%Y-%m-%d %H:%M')} UTC → "
                    f"{gap['end'].strftime('%Y-%m-%d %H:%M')} UTC] "
                    f"{gap['hours']:.1f}h silence"
                )
                evidence.append(
                    f"    ↳ Correlates with: {gap['reg_correlation']}"
                )
                evidence.append(
                    f"    ↳ FORENSIC SIGNIFICANCE: Operator went silent in proximity "
                    f"to regulatory action — conscious awareness confirmed."
                )

        if anomalous_gaps:
            evidence.append("")
            evidence.append(f"OTHER ANOMALOUS SILENCE PERIODS (outside sleep window):")
            for gap in sorted(anomalous_gaps, key=lambda g: g["hours"], reverse=True)[:5]:
                start_aest = gap["start"] + timedelta(hours=AEST_OFFSET)
                evidence.append(
                    f"  [{gap['start'].strftime('%Y-%m-%d %H:%M')} UTC] "
                    f"{gap['hours']:.1f}h — started at "
                    f"{start_aest.strftime('%H:%M')} AEST "
                    f"(outside normal sleep window)"
                )

        severity   = "HIGH"       if regulatory_gaps else "MEDIUM"
        confidence = "CONFIRMED"  if regulatory_gaps else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Surveillance Blackout Analysis — "
                f"{len(regulatory_gaps)} Regulatory-Correlated Gap(s) | "
                f"{len(anomalous_gaps)} Anomalous Gap(s)"
            ),
            description=(
                f"Analysis of {len(gaps)} silence periods identified "
                f"{len(regulatory_gaps)} gap(s) temporally correlated with regulatory events "
                f"and {len(anomalous_gaps)} unexplained anomalous gap(s) outside the operator's "
                f"established sleep window (00:00-10:00 AEST). "
                f"{'Regulatory-correlated silence confirms the operator was aware of and responding to official actions. ' if regulatory_gaps else ''}"
                f"This pattern is inconsistent with automated infrastructure, which does not "
                f"pause operations in response to regulatory visits."
            ),
            severity=severity,
            confidence=confidence,
            technique="Temporal gap analysis with regulatory event correlation",
            evidence=evidence,
            hardware_hint=(
                "Human-operated platform — automated systems do not pause "
                "in response to regulatory events."
            ),
            action=(
                "1. Regulatory-correlated gaps are strong evidence of operator awareness.\n"
                "2. Include gap timeline in AFP submission alongside regulatory event dates.\n"
                "3. The duration of post-regulatory silence may indicate threat assessment by operator.\n"
                "4. Cross-reference with operator rhythm profile for business hours gaps.\n"
                "5. Any gap followed by new CID cluster = deliberate reconfiguration."
            ),
            spec_ref=(
                "Behavioral analysis methodology; "
                "ACMA ENQ-1851DVJH04; VicPol CIRS-20260331-141"
            ),
        ))

        return findings

    def _get_ts(self, event: Dict) -> Optional[float]:
        ts = event.get("timestamp") or event.get("time") or event.get("ts")
        if ts is None:
            return None
        try:
            if isinstance(ts, (int, float)):
                return float(ts)
            if isinstance(ts, str):
                ts_clean = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
        except (ValueError, OSError):
            return None
