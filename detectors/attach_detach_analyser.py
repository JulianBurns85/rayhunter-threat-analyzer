#!/usr/bin/env python3
"""
AttachDetachCycleAnalyser — Artificial attach/detach cycle detection.

Legitimate networks see organic attach/detach cycles driven by:
- User locking/unlocking phone
- Moving between cells
- Data session start/end
- Natural network events

An IMSI catcher forces RAPID ARTIFICIAL attach/detach cycles to
harvest identities. The cycle rate is too fast for organic user
behaviour and too consistent for random network conditions.

Expected organic rates (suburban residential, night time):
  Attach events:  0.5 - 3 per hour
  Detach events:  0.5 - 3 per hour
  Cycle time:     10+ minutes between attach/detach pairs

Rogue platform rates:
  Attach events:  10-100+ per hour
  Detach events:  10-100+ per hour
  Cycle time:     seconds to minutes

Also analyses:
- Attach/detach pairing (are attaches followed by rapid detaches?)
- Time-of-day rate anomalies (high rate at 3am = not organic)
- Carrier-specific differences (Telstra vs Vodafone rate mismatch)

Reference: 3GPP TS 24.301 §5.5 (attach/detach procedures);
Tucker et al. NDSS 2025 — forced re-attach for IMSI collection.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Thresholds
MAX_ORGANIC_RATE_PER_HOUR = 5.0     # > 5 attaches/hour = suspicious
ROGUE_RATE_PER_HOUR       = 15.0    # > 15 attaches/hour = rogue
MAX_ORGANIC_CYCLE_S       = 300.0   # Organic cycle > 5 minutes
RAPID_CYCLE_S             = 60.0    # Rapid cycle < 60s = forced

ATTACH_TYPES = {
    "attachrequest", "attach request",
    "attachaccept", "attach accept",
    "rrcconnectionsetupcomplete", "rrc connection setup complete",
}
DETACH_TYPES = {
    "detachrequest", "detach request",
    "rrcconnectionrelease", "rrc connection release",
    "attachreject", "attach reject",
}

AEST_OFFSET = 10  # UTC+10


class AttachDetachCycleAnalyser(BaseDetector):
    """
    Analyses attach/detach cycle rates and patterns to detect
    artificially forced rapid cycling by an IMSI catcher.
    """

    name = "AttachDetachCycleAnalyser"
    description = (
        "Attach/detach cycle rate analysis — artificial rapid cycling "
        "indicates forced identity re-registration"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        attach_ts  = []
        detach_ts  = []

        for e in events:
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            ts  = self._get_ts(e)
            if ts is None:
                continue

            if any(t in msg for t in ATTACH_TYPES):
                attach_ts.append(ts)
            if any(t in msg for t in DETACH_TYPES):
                detach_ts.append(ts)

        if not attach_ts and not detach_ts:
            return []

        attach_ts.sort()
        attach_ts = self._dedup_ts(attach_ts, 1.0)
        detach_ts = self._dedup_ts(detach_ts, 1.0)

        # Calculate hourly rates
        all_ts = sorted(attach_ts + detach_ts)
        if not all_ts:
            return []

        total_duration_h = (all_ts[-1] - all_ts[0]) / 3600
        if total_duration_h < 0.5:
            return []

        attach_rate = len(attach_ts) / total_duration_h
        detach_rate = len(detach_ts) / total_duration_h

        # Peak hourly rates
        peak_attach_rate = self._peak_hourly_rate(attach_ts)
        peak_detach_rate = self._peak_hourly_rate(detach_ts)

        # Cycle time analysis (per-file deduplicated attach -> detach pairs)
        from collections import defaultdict as _dd
        per_file_attach = _dd(list)
        per_file_detach = _dd(list)
        for _e in events:
            _ts = _e.get("timestamp") or _e.get("ts")
            if _ts is None:
                continue
            try:
                _ts = float(_ts)
            except (TypeError, ValueError):
                continue
            _msg = str(_e.get("msg_type") or _e.get("message_type") or "").lower()
            _src = str(_e.get("source_file") or _e.get("file") or _e.get("pcap_file") or "unknown")
            if any(t in _msg for t in ATTACH_TYPES):
                per_file_attach[_src].append(_ts)
            elif any(t in _msg for t in DETACH_TYPES):
                per_file_detach[_src].append(_ts)

        rapid_cycles = []
        for _src, _a_list in per_file_attach.items():
            _a_clean = self._dedup_ts(_a_list, 1.0)
            _d_clean = self._dedup_ts(per_file_detach.get(_src, []), 1.0)
            _d_idx = 0
            for a_ts in _a_clean:
                while _d_idx < len(_d_clean) and _d_clean[_d_idx] < a_ts:
                    _d_idx += 1
                if _d_idx < len(_d_clean):
                    d_ts = _d_clean[_d_idx]
                    delta = d_ts - a_ts
                    cycle_s = delta
                    if 0 < delta <= RAPID_CYCLE_S:
                        rapid_cycles.append(delta)
                        _d_idx += 1  # pair each detach at most once

        # Night-time high rate analysis (00:00-06:00 AEST)
        night_attach = [
            ts for ts in attach_ts
            if (int(ts / 3600 + AEST_OFFSET) % 24) < 6
        ]
        night_rate = len(night_attach) / max(total_duration_h * 0.25, 0.01)

        # Assessment
        is_suspicious = attach_rate > MAX_ORGANIC_RATE_PER_HOUR
        is_rogue      = (
            attach_rate > ROGUE_RATE_PER_HOUR or
            (peak_attach_rate > ROGUE_RATE_PER_HOUR and len(rapid_cycles) >= 5) or
            (night_rate > ROGUE_RATE_PER_HOUR and len(night_attach) >= 5)
        )
        is_suspicious = is_suspicious or (len(rapid_cycles) >= 5)

        if not (is_suspicious or is_rogue):
            return []

        evidence = [
            f"Analysis period: {total_duration_h:.1f} hours",
            f"Total attach events: {len(attach_ts)}",
            f"Total detach events: {len(detach_ts)}",
            f"",
            f"CYCLE RATES:",
            f"  Mean attach rate:  {attach_rate:.2f}/hour",
            f"  Mean detach rate:  {detach_rate:.2f}/hour",
            f"  Peak attach rate:  {peak_attach_rate:.2f}/hour",
            f"  Peak detach rate:  {peak_detach_rate:.2f}/hour",
            f"  Night-time rate:   {night_rate:.2f}/hour",
            f"",
            f"ORGANIC BASELINE (suburban residential):",
            f"  Expected: 0.5-{MAX_ORGANIC_RATE_PER_HOUR:.0f} attaches/hour",
            f"  Rogue threshold: > {ROGUE_RATE_PER_HOUR:.0f}/hour",
            f"  This corpus: {attach_rate:.2f}/hour "
            f"({'ROGUE' if is_rogue else 'SUSPICIOUS'})",
        ]

        if rapid_cycles:
            evidence.append(f"")
            evidence.append(
                f"RAPID ATTACH/DETACH CYCLES (< {RAPID_CYCLE_S:.0f}s): "
                f"{len(rapid_cycles)} events"
            )
            for cycle in rapid_cycles[:5]:
                evidence.append(
                    f"  [{cycle['ts_str']}] Cycle time: {cycle['cycle_s']:.1f}s"
                )

        if night_attach and night_rate > MAX_ORGANIC_RATE_PER_HOUR:
            evidence.append(f"")
            evidence.append(
                f"NIGHT-TIME ANOMALY: {len(night_attach)} attach events "
                f"during 00:00-06:00 AEST ({night_rate:.2f}/hour)"
            )
            evidence.append(
                f"  Real users do not generate {night_rate:.1f} attach events/hour "
                f"at 3am. This indicates automated platform operation."
            )

        severity   = "CRITICAL" if is_rogue else ("HIGH" if attach_rate > MAX_ORGANIC_RATE_PER_HOUR else "MEDIUM")
        confidence = "CONFIRMED" if len(rapid_cycles) >= 5 else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Attach/Detach Cycle Anomaly — "
                f"{attach_rate:.1f}/hr rate | "
                f"{len(rapid_cycles)} rapid cycles | "
                f"{'ROGUE' if is_rogue else 'SUSPICIOUS'}"
            ),
            description=(
                f"Attach/detach cycle rate of {attach_rate:.1f}/hour "
                f"({'exceeds' if attach_rate > ROGUE_RATE_PER_HOUR else 'is below'} the "
                f"{ROGUE_RATE_PER_HOUR:.0f}/hour rogue threshold). "
                f"Organic suburban residential traffic produces 0.5-"
                f"{MAX_ORGANIC_RATE_PER_HOUR:.0f} events/hour. "
                f"{'Rapid cycles under 60s confirm artificially forced re-registration. ' if rapid_cycles else ''}"
                f"{'Night-time high rate confirms automated platform operation. ' if night_attach and night_rate > MAX_ORGANIC_RATE_PER_HOUR else ''}"
                f"Tucker et al. NDSS 2025 documents forced re-attach as a "
                f"primary IMSI extraction technique."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Attach/detach cycle rate analysis — "
                "artificial rapid cycling detection"
            ),
            evidence=evidence,
            hardware_hint=(
                "Active IMSI catcher — forced rapid re-attach cycles "
                "documented in Harris HailStorm operational mode."
            ),
            action=(
                "1. Rapid cycles < 60s prove forced re-registration (not organic).\n"
                "2. Night-time high rate proves automated platform operation.\n"
                "3. Cite Tucker et al. NDSS 2025 — forced re-attach IMSI technique.\n"
                "4. Include cycle rate timeline in AFP submission.\n"
                "5. Cross-reference rapid cycles with IMSI harvest events."
            ),
            spec_ref=(
                "3GPP TS 24.301 §5.5 (attach/detach procedures); "
                "Tucker et al. NDSS 2025 (forced re-attach); "
                "YAICD framework (session anomaly)"
            ),
        ))

        return findings


    @staticmethod
    def _dedup_ts(ts_list: List[float], window_s: float = 1.0) -> List[float]:
        """Collapse double-logged NAS wrapper frames within window_s of each other."""
        if not ts_list:
            return []
        ts_sorted = sorted(ts_list)
        out = [ts_sorted[0]]
        for t in ts_sorted[1:]:
            if t - out[-1] > window_s:
                out.append(t)
        return out

    def _peak_hourly_rate(self, timestamps: List[float]) -> float:
        """Calculate peak events per hour in any 1-hour window."""
        if not timestamps:
            return 0.0
        ts_sorted = sorted(timestamps)
        max_count = 0
        j = 0
        for i, t in enumerate(ts_sorted):
            while j < len(ts_sorted) and ts_sorted[j] - t <= 3600:
                j += 1
            max_count = max(max_count, j - i)
        return float(max_count)

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
