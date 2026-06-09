#!/usr/bin/env python3
"""
PagingTargetDetector — Detects aggressive targeted device polling via m-TMSI.

Evidence basis:
  - m-TMSI d8736117 paged 402 times over 2.04 hours (25 May 2026)
  - Base quantum ~10.880s (SD=0.3285s) — machine precision, not organic network behaviour
  - 3GPP TS 36.331 §7.1 (Paging) & TS 24.301

Integrated into rayhunter-threat-analyzer v2.4+
Place this file in: detectors/paging_target.py
"""

from collections import Counter
from typing import List, Dict
import statistics

from .base import BaseDetector, make_finding


# Thresholds — tuned to Cranbourne East investigation data
_MIN_PAGES_TO_ANALYSE   = 50    # minimum pages on one m-TMSI to bother scoring
_CRITICAL_PAGE_COUNT    = 150   # above this → CRITICAL severity
_BASE_INTERVAL_LO       = 9.0   # seconds — lower bound of base quantum window
_BASE_INTERVAL_HI       = 13.0  # seconds — upper bound of base quantum window
_BASE_QUANTUM           = 10.880 # seconds — confirmed machine-precision quantum
_BASE_QUANTUM_CONFIRMED = 40    # occurrences needed for CONFIRMED confidence
_SD_CONFIRMED           = 2.0   # SD threshold for CONFIRMED (machine precision)
_TOP_N_TARGETS          = 8     # report at most N highest-count m-TMSIs


class PagingTargetDetector(BaseDetector):
    """
    Flags devices under heavy, machine-precision targeted paging.

    Methodology:
      1. Extract all m-TMSI values from paging events.
      2. Count occurrences per m-TMSI.
      3. For high-count m-TMSIs, analyse inter-page intervals:
         - Mean and SD of all intervals
         - Count of intervals falling in the base quantum window (~10.88s)
         - Count of double (~21.76s) and triple (~32.64s) multiples
      4. Score severity / confidence and emit a finding.

    The double/triple interval pattern is diagnostically significant:
    it confirms the platform has a fixed quantum and simply skips cycles
    when the target is unreachable rather than adjusting the timer.
    """

    name        = "PagingTargetDetector"
    description = "Detects devices under heavy targeted paging (strong surveillance indicator)"

    # ------------------------------------------------------------------ #
    #  Main analysis entry point
    # ------------------------------------------------------------------ #

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        # Collect paging events from all sources
        paging_events = [
            e for e in events
            if any(
                k in str(e.get("msg", "")).lower()
                for k in ["paging", "m-tmsi", "s-tmsi", "ue-identity", "pagingrec"]
            )
        ]

        if len(paging_events) < 20:
            return findings

        # ── Count m-TMSI occurrences and map events ──────────────────── #
        counter: Counter = Counter()
        tmsi_events: Dict[str, List[Dict]] = {}

        for ev in paging_events:
            msg = str(ev.get("msg", ""))
            if "m-TMSI:" not in msg:
                continue
            try:
                # e.g.  "m-TMSI: d8736117 [bit length 32 ...]"
                raw = msg.split("m-TMSI:")[1].split()[0].strip()
                # strip any surrounding brackets / commas
                tmsi = raw.strip("[](),")
                if not tmsi:
                    continue
                counter[tmsi] += 1
                tmsi_events.setdefault(tmsi, []).append(ev)
            except (IndexError, AttributeError):
                continue

        if not counter:
            return findings

        # ── Analyse each significant target ──────────────────────────── #
        for tmsi, count in counter.most_common(_TOP_N_TARGETS):
            if count < _MIN_PAGES_TO_ANALYSE:
                break  # sorted descending — nothing below threshold

            ev_list = tmsi_events.get(tmsi, [])
            timestamps = sorted(
                t for t in (self.parse_timestamp(e) for e in ev_list) if t > 0
            )

            if len(timestamps) < 15:
                continue

            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            mean_int = statistics.mean(intervals)
            sd_int   = statistics.stdev(intervals) if len(intervals) > 1 else 0.0

            # Quantum analysis
            base_count   = sum(1 for i in intervals if _BASE_INTERVAL_LO <= i <= _BASE_INTERVAL_HI)
            double_count  = sum(1 for i in intervals if 2 * _BASE_INTERVAL_LO <= i <= 2 * _BASE_INTERVAL_HI)
            triple_count  = sum(1 for i in intervals if 3 * _BASE_INTERVAL_LO <= i <= 3 * _BASE_INTERVAL_HI)

            # Gaps > 60s indicate device was pulled off network or unreachable
            gaps = [i for i in intervals if i > 60]
            missed_cycles_total = sum(round(g / _BASE_QUANTUM) - 1 for g in gaps if g > _BASE_QUANTUM)

            # Severity and confidence
            severity   = "CRITICAL" if count > _CRITICAL_PAGE_COUNT else "HIGH"
            confidence = (
                "CONFIRMED"
                if base_count >= _BASE_QUANTUM_CONFIRMED and sd_int < _SD_CONFIRMED
                else "PROBABLE"
            )

            evidence = [
                f"m-TMSI: {tmsi}",
                f"Total pages: {count}",
                f"Base quantum (~{_BASE_QUANTUM}s) intervals: {base_count}",
                f"Double intervals (~{2*_BASE_QUANTUM:.2f}s): {double_count}",
                f"Triple intervals (~{3*_BASE_QUANTUM:.2f}s): {triple_count}",
                f"Mean interval: {mean_int:.3f}s | SD: {sd_int:.3f}s",
                f"Gaps >60s: {len(gaps)} ({missed_cycles_total} estimated missed pages)",
            ]

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Targeted Device Polling — m-TMSI {tmsi} "
                    f"({count} pages, {mean_int:.2f}s base)"
                ),
                description=(
                    f"Device paged {count} times with base interval "
                    f"~{mean_int:.3f}s (SD={sd_int:.3f}s). "
                    f"{base_count} intervals at machine-precision quantum "
                    f"~{_BASE_QUANTUM}s. "
                    f"Double/triple multiples ({double_count}/{triple_count}) "
                    f"confirm fixed-quantum automated polling — not organic "
                    f"network paging. {len(gaps)} gaps >60s indicate "
                    f"~{missed_cycles_total} additional missed polling cycles."
                ),
                severity=severity,
                confidence=confidence,
                technique="Targeted device location tracking via machine-precision paging",
                evidence=evidence,
                events=ev_list[:8],
                action=(
                    "Strong evidence of active targeted surveillance. "
                    "Correlate m-TMSI with victim IMSI via TAC/EARFCN overlap. "
                    "Include full timestamp series in USB evidence package."
                ),
                spec_ref="3GPP TS 36.331 §7.1 (Paging) & TS 24.301",
                hardware_hint=(
                    "Harris HailStorm / StingRay II active tracking — "
                    "fixed-quantum paging matches documented Harris "
                    "'Catch and Release' polling behaviour"
                ),
            ))

        return findings
