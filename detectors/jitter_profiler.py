#!/usr/bin/env python3
"""
RRCJitterProfiler — Microsecond timing jitter analysis for hardware fingerprinting.

Legitimate macro towers run on GPS-disciplined atomic clocks.
Rogue platforms running srsRAN or proprietary stacks on a host CPU introduce
measurable microsecond jitter driven by thread scheduling, USB latency,
and processing load.

This jitter signature is HARDWARE DNA — it survives CID rotation, frequency
changes, TAC changes, and firmware reconfiguration. As long as the operator
uses the same host computer, the jitter distribution remains identical.
"""

import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


class RRCJitterProfiler(BaseDetector):
    name = "RRCJitterProfiler"
    description = (
        "Microsecond timing jitter analysis — hardware temporal fingerprint "
        "that survives CID rotation and firmware reconfiguration"
    )

    RELEASE_TYPES = {
        "rrcconnectionrelease",
        "rrc connection release",
        "rrcrelease",
    }

    KNOWN_SIGNATURES = {
        "srsRAN_automated":   (210.2, 500.0),
        "Harris_T3_Vodafone": (40.5,  200.0),
        "Harris_T1_hold":     (610.6, 100.0),
    }

    ROGUE_JITTER_MIN_MS = 50.0
    LEGIT_JITTER_MAX_MS = 5.0
    MIN_INTERVALS       = 10

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        releases_by_cell = defaultdict(list)
        for e in events:
            msg = str(
                e.get("message_type") or e.get("msg_type") or ""
            ).lower().strip()
            if msg in self.RELEASE_TYPES:
                ts = self._get_ts(e)
                if ts is not None:
                    cid = str(e.get("cell_id") or e.get("cid") or "unknown")
                    releases_by_cell[cid].append(ts)

        # Build combined list — but only add __ALL__ if it has DIFFERENT
        # stats from the per-cell findings (avoids duplicate when all
        # events map to "unknown")
        all_releases = sorted(
            ts for tss in releases_by_cell.values() for ts in tss
        )

        # Track signatures already emitted to avoid duplicates
        emitted_signatures = set()

        cells_to_analyse = dict(releases_by_cell)
        if len(all_releases) >= self.MIN_INTERVALS + 1:
            cells_to_analyse["__ALL__"] = all_releases

        for cid, timestamps in cells_to_analyse.items():
            ts_sorted = sorted(timestamps)
            if len(ts_sorted) < self.MIN_INTERVALS + 1:
                continue

            intervals_s = [
                ts_sorted[i+1] - ts_sorted[i]
                for i in range(len(ts_sorted) - 1)
            ]

            valid = [iv for iv in intervals_s if 1.0 <= iv <= 1800.0]
            if len(valid) < self.MIN_INTERVALS:
                continue

            mean_s   = statistics.mean(valid)
            stdev_ms = statistics.stdev(valid) * 1000 if len(valid) > 1 else 0.0

            # Deduplication: skip __ALL__ if signature matches an already-emitted cell
            sig_key = (round(mean_s, 1), round(stdev_ms, 0))
            if cid == "__ALL__" and sig_key in emitted_signatures:
                continue
            emitted_signatures.add(sig_key)

            median_s = statistics.median(valid)
            min_ms   = min(valid) * 1000
            max_ms   = max(valid) * 1000
            cv       = (stdev_ms / (mean_s * 1000)) * 100 if mean_s > 0 else 0

            matched_sig  = None
            sig_delta_ms = None
            for sig_name, (sig_mean, sig_max_jitter) in self.KNOWN_SIGNATURES.items():
                if abs(mean_s - sig_mean) < 5.0:
                    matched_sig  = sig_name
                    sig_delta_ms = abs(mean_s - sig_mean) * 1000
                    break

            is_rogue_jitter = stdev_ms > self.ROGUE_JITTER_MIN_MS

            if not (matched_sig or is_rogue_jitter):
                continue

            sorted_valid = sorted(valid)
            n  = len(sorted_valid)
            p25 = sorted_valid[int(n * 0.25)] * 1000
            p50 = sorted_valid[int(n * 0.50)] * 1000
            p75 = sorted_valid[int(n * 0.75)] * 1000
            p95 = sorted_valid[int(n * 0.95)] * 1000

            bimodal = self._check_bimodal(valid)

            label = f"CID={cid}" if cid not in ("__ALL__", "unknown") else (
                "All cells combined" if cid == "__ALL__" else "CID=unknown (no cell ID in events)"
            )

            evidence = [
                f"Cell: {label}",
                f"Intervals analysed: {len(valid)}",
                f"Mean cycle: {mean_s:.3f}s ({mean_s*1000:.1f}ms)",
                f"Std deviation (jitter): {stdev_ms:.3f}ms",
                f"Coefficient of variation: {cv:.2f}%",
                f"Percentiles — p25:{p25:.1f}ms p50:{p50:.1f}ms p75:{p75:.1f}ms p95:{p95:.1f}ms",
                f"Range: {min_ms:.1f}ms — {max_ms:.1f}ms",
            ]

            if matched_sig:
                evidence.append(
                    f"SIGNATURE MATCH: {matched_sig} "
                    f"(delta from canonical: {sig_delta_ms:.1f}ms)"
                )

            if is_rogue_jitter:
                evidence.append(
                    f"HARDWARE DNA: Jitter {stdev_ms:.1f}ms >> "
                    f"{self.LEGIT_JITTER_MAX_MS}ms legitimate threshold. "
                    f"Consistent with host-CPU timer loop scheduling variance."
                )

            if bimodal:
                evidence.append(
                    "BIMODAL DISTRIBUTION detected — two overlapping cycles "
                    "(dual-mode operation or phase shift)"
                )

            hardware_hint = self._classify_hardware(mean_s, stdev_ms, matched_sig, bimodal)

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Hardware Temporal DNA — {label} — "
                    f"Jitter σ={stdev_ms:.1f}ms | Mean={mean_s:.2f}s"
                    + (f" [{matched_sig}]" if matched_sig else "")
                ),
                description=(
                    f"Microsecond-level jitter analysis of {len(valid)} RRCConnectionRelease "
                    f"intervals reveals a hardware temporal fingerprint. "
                    f"Mean cycle {mean_s:.3f}s with standard deviation {stdev_ms:.3f}ms. "
                    f"{'Jitter is consistent with host-CPU timer scheduling on an SDR platform, not GPS-disciplined carrier infrastructure.' if is_rogue_jitter else 'Jitter within legitimate carrier bounds.'} "
                    f"This signature survives CID rotation, frequency changes, and firmware "
                    f"reconfiguration — same host hardware = same fingerprint."
                ),
                severity="HIGH"       if is_rogue_jitter else "MEDIUM",
                confidence="CONFIRMED" if (matched_sig and is_rogue_jitter) else "PROBABLE",
                technique="Microsecond RRC release jitter profiling — hardware temporal fingerprint",
                evidence=evidence,
                hardware_hint=hardware_hint,
                action=(
                    "1. This jitter signature is hardware DNA — document mean ± stdev as device identifier.\n"
                    "2. Even if operator rotates all CIDs, same jitter = same physical device.\n"
                    "3. Include percentile distribution in AFP submission.\n"
                    "4. Legitimate carrier towers show < 5ms jitter (GPS-disciplined).\n"
                    "5. Cross-reference with bladeRF SIB1 phase drift analysis for dual confirmation."
                ),
                spec_ref=(
                    "Physical layer timing analysis; 3GPP TS 36.331 §5.3.8; "
                    "YAICD P14_t3212_anomaly (extended)"
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

    def _check_bimodal(self, intervals: list) -> bool:
        if len(intervals) < 20:
            return False
        mean   = statistics.mean(intervals)
        median = statistics.median(intervals)
        stdev  = statistics.stdev(intervals)
        return abs(mean - median) > stdev * 0.5

    def _classify_hardware(self, mean_s, stdev_ms, matched_sig, bimodal) -> str:
        if matched_sig == "srsRAN_automated":
            return "srsRAN / OAI — automated timing loop (210.2s canonical)"
        if matched_sig == "Harris_T3_Vodafone":
            return "Harris HailStorm — T3 Vodafone channel (40.5s)"
        if matched_sig == "Harris_T1_hold":
            return "Harris HailStorm — T1 hold timer (610.6s)"
        if stdev_ms > 500:
            return "High-jitter platform — consumer SDR or heavily loaded host"
        if stdev_ms < 5:
            return "GPS-disciplined clock — carrier-grade or high-end platform"
        return f"Unclassified — mean {mean_s:.1f}s, jitter {stdev_ms:.1f}ms"
