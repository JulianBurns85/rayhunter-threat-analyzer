#!/usr/bin/env python3
"""
OperatorRhythmProfiler — Temporal pattern analysis across multi-day captures.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import math
import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


def binom_sf(k: int, n: int, p: float) -> float:
    """Return P(X >= k) for X ~ Binomial(n, p)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if not 0 <= p <= 1:
        raise ValueError("p must be between 0 and 1")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p == 0:
        return 0.0
    if p == 1:
        return 1.0

    tail = 0.0
    term = math.comb(n, k) * (p ** k) * ((1.0 - p) ** (n - k))
    tail += term
    for i in range(k + 1, n + 1):
        term *= (n - i + 1) / i * (p / (1.0 - p))
        tail += term
    return tail


ACMA_INSPECTION_DATE = datetime(2026, 5, 8, tzinfo=timezone.utc)
VICPOL_REFERRAL_DATE = datetime(2026, 3, 31, tzinfo=timezone.utc)
EARLIEST_KNOWN_ATTACK = datetime(2026, 1, 23, tzinfo=timezone.utc)

AEST = timezone(timedelta(hours=10))
AEDT = timezone(timedelta(hours=11))


class OperatorRhythmProfiler(BaseDetector):
    """
    Extracts temporal activity patterns over multi-day event series.
    Requires at least 5 distinct days of coverage and caps severity at MEDIUM
    and confidence below CONFIRMED.
    """

    name = "OperatorRhythmProfiler"
    description = "Temporal pattern analysis over multi-day captures"
    min_days: int = 5

    ATTACK_TYPES = {
        "rrcconnectionreconfiguration",
        "identityrequest",
        "authenticationreject",
        "attachreject",
        "trackingareaupdatereject",
        "rrcconnectionrelease",
        "securitymodecmd",
        "uecapabilityenquiry",
        "ueinformationrequest",
    }

    def analyze(self, events: List[Dict]) -> List[Dict]:
        timestamped = self._extract_timestamps(events)
        if len(timestamped) < 50:
            return []

        hour_counts: Dict[int, int] = defaultdict(int)
        hour_aest: Dict[int, int] = defaultdict(int)
        dow_counts: Dict[int, int] = defaultdict(int)
        date_counts: Dict[str, int] = defaultdict(int)
        pre_acma: Dict[int, int] = defaultdict(int)
        post_acma: Dict[int, int] = defaultdict(int)

        for ts in timestamped:
            hour_counts[ts.hour] += 1
            ts_aest = ts.astimezone(AEST)
            hour_aest[ts_aest.hour] += 1
            dow_counts[ts_aest.weekday()] += 1
            date_counts[ts_aest.strftime("%Y-%m-%d")] += 1

            if ts < ACMA_INSPECTION_DATE:
                pre_acma[ts_aest.hour] += 1
            else:
                post_acma[ts_aest.hour] += 1

        if len(date_counts) < self.min_days:
            return []

        total = sum(hour_aest.values())
        peak_hour = max(hour_aest, key=hour_aest.get)

        biz_events = sum(hour_aest.get(h, 0) for h in range(8, 18))
        biz_ratio = biz_events / total if total else 0.0

        weekday_events = sum(dow_counts.get(d, 0) for d in range(5))
        weekend_events = sum(dow_counts.get(d, 0) for d in (5, 6))
        wd_ratio = weekday_events / (weekday_events + weekend_events) if (weekday_events + weekend_events) else 0.0

        sleep_window = self._find_longest_quiet_block(hour_aest)

        morning_avg = sum(hour_aest.get(h, 0) for h in range(8, 11)) / 3.0
        lunch_avg = sum(hour_aest.get(h, 0) for h in range(11, 14)) / 3.0
        afternoon_avg = sum(hour_aest.get(h, 0) for h in range(14, 18)) / 4.0
        lunch_dip = (
            morning_avg > 0
            and afternoon_avg > 0
            and lunch_avg < (morning_avg + afternoon_avg) / 2.0 * 0.7
        )

        tz_score = self._infer_timezone(hour_counts)
        acma_shift = self._detect_behavioral_shift(pre_acma, post_acma)

        evidence: List[str] = [
            f"Total events analysed: {total:,} across {len(date_counts)} unique days",
            f"Peak activity hour (AEST): {peak_hour:02d}:00",
            f"Business hours (08:00-18:00 AEST): {biz_ratio:.1%} of events",
            f"Weekday/weekend ratio: {wd_ratio:.1%} weekday",
        ]

        if sleep_window:
            evidence.append(
                f"Quiet window (AEST): {sleep_window['start']:02d}:00 - "
                f"{sleep_window['end']:02d}:00 ({sleep_window['hours']}h)"
            )

        if lunch_dip:
            evidence.append(
                f"Midday activity dip: {lunch_avg:.0f} events/hr vs "
                f"{morning_avg:.0f} morning / {afternoon_avg:.0f} afternoon"
            )

        evidence.append(f"Inferred timezone: {tz_score['tz']} (confidence: {tz_score['confidence']})")

        if acma_shift:
            evidence.append(
                f"Shift detected: pre peak {acma_shift['pre_peak']:02d}:00 -> "
                f"post peak {acma_shift['post_peak']:02d}:00"
            )

        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        dow_str = " | ".join(f"{days[d]}:{dow_counts.get(d, 0):,}" for d in range(7))
        evidence.append(f"Day-of-week activity: {dow_str}")

        is_business_hours = biz_ratio > 0.6
        is_weekday_heavy = wd_ratio > 0.7
        has_sleep_window = sleep_window is not None
        pattern_score = sum([is_business_hours, is_weekday_heavy, has_sleep_window])

        # Cap severity at MEDIUM and avoid CONFIRMED for temporal rhythm alone
        severity = "MEDIUM" if pattern_score >= 2 else "LOW"
        confidence = "PROBABLE" if pattern_score >= 1 else "LOW"

        description = (
            f"Temporal activity profile extracted from {total:,} events across "
            f"{len(date_counts)} unique days (business-hours ratio: {biz_ratio:.0%}, "
            f"weekday ratio: {wd_ratio:.0%})."
        )

        return [
            make_finding(
                detector=self.name,
                title=f"Temporal Activity Rhythm ({len(date_counts)} days)",
                description=description,
                severity=severity,
                confidence=confidence,
                technique="Temporal pattern analysis",
                evidence=evidence,
                hardware_hint="Temporal distribution alone is indicative rather than conclusive.",
                action="Correlate temporal clustering with independent RF and protocol findings.",
                spec_ref="Statistical temporal analysis",
            )
        ]

    def _extract_timestamps(self, events: List[Dict]) -> List[datetime]:
        """Extract UTC timestamps from events."""
        timestamps: List[datetime] = []
        for e in events:
            ts = e.get("timestamp") or e.get("time") or e.get("ts")
            if ts is None:
                continue
            try:
                if isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                elif isinstance(ts, str):
                    ts_clean = ts.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts_clean)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                else:
                    continue
                timestamps.append(dt)
            except (ValueError, OSError, OverflowError):
                continue
        return timestamps

    def _find_longest_quiet_block(self, hour_counts: dict) -> dict | None:
        """Find the longest consecutive block of low/zero activity hours."""
        threshold = max(hour_counts.values()) * 0.05 if hour_counts else 0
        quiet = [h for h in range(24) if hour_counts.get(h, 0) <= threshold]

        if len(quiet) < 3:
            return None

        best_start, best_len = None, 0
        i = 0
        while i < len(quiet):
            j = i
            while j + 1 < len(quiet) and quiet[j + 1] == quiet[j] + 1:
                j += 1
            run_len = j - i + 1
            if run_len > best_len:
                best_len = run_len
                best_start = quiet[i]
            i = j + 1

        if best_len >= 3:
            return {
                "start": best_start,
                "end": (best_start + best_len) % 24,
                "hours": best_len,
            }
        return None

    def _infer_timezone(self, hour_counts_utc: dict) -> dict:
        """Infer UTC offset with highest 08:00-18:00 local alignment."""
        best_tz, best_score = "UTC", 0
        for offset in range(-12, 15):
            score = sum(
                count for h_utc, count in hour_counts_utc.items()
                if 8 <= ((h_utc + offset) % 24) < 18
            )
            if score > best_score:
                best_score = score
                best_tz = f"UTC+{offset}" if offset >= 0 else f"UTC{offset}"

        total = sum(hour_counts_utc.values())
        ratio = (best_score / total) if total else 0.0
        confidence = "HIGH" if ratio > 0.65 else "MEDIUM" if ratio > 0.5 else "LOW"

        if best_tz in ("UTC+9", "UTC+10", "UTC+11"):
            return {"tz": "UTC+10 (AEST)", "confidence": "HIGH"}

        return {"tz": best_tz, "confidence": confidence}

    def _detect_behavioral_shift(self, pre: dict, post: dict) -> dict | None:
        """Detect if hourly peak shifted significantly between pre and post windows."""
        if sum(pre.values()) < 20 or sum(post.values()) < 20:
            return None
        pre_peak = max(pre, key=pre.get) if pre else None
        post_peak = max(post, key=post.get) if post else None
        if pre_peak is None or post_peak is None:
            return None
        if abs(pre_peak - post_peak) >= 2:
            return {"pre_peak": pre_peak, "post_peak": post_peak}
        return None
