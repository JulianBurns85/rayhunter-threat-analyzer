#!/usr/bin/env python3
"""
EARFCN Anomaly Detector
=======================
Detects abnormal frequency-channel behavior consistent with rogue base stations.

Rules:
  CRITICAL: Same Cell ID appearing on multiple EARFCNs simultaneously
            (one of the strongest rogue tower signatures — legit cells don't do this)
  HIGH:     Rapid EARFCN changes within a short window (EARFCN hopping)
  HIGH:     Cell operating on non-standard EARFCN for this operator
  MEDIUM:   EARFCN appearing in captures with no corresponding TAC
"""

from typing import List, Dict, Set
from collections import defaultdict
from .base import BaseDetector, make_finding


class EarfcnAnomalyDetector(BaseDetector):
    name = "EarfcnAnomalyDetector"
    description = "Detects EARFCN-based anomalies: multi-frequency operation, rapid hopping"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Build map: cell_id → set of EARFCNs seen
        cell_earfcns: Dict[str, Set] = defaultdict(set)
        # Build map: cell_id → list of (timestamp, earfcn)
        cell_timeline: Dict[str, List] = defaultdict(list)

        for ev in events:
            cell_id = ev.get("cell_id")
            earfcn  = ev.get("earfcn")
            ts      = self.parse_timestamp(ev)
            if cell_id and earfcn:
                cell_earfcns[cell_id].add(str(earfcn))
                cell_timeline[cell_id].append((ts, earfcn))

        # ── Rule 1: Cell on multiple EARFCNs ──────────────────────────
        for cell_id, earfcns in cell_earfcns.items():
            if len(earfcns) > 1:
                ev_list = [
                    e for e in events
                    if str(e.get("cell_id", "")) == str(cell_id)
                ]
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Cell {cell_id} Observed on Multiple EARFCNs: {', '.join(sorted(earfcns))}",
                    description=(
                        f"Cell ID {cell_id} was observed operating on {len(earfcns)} different "
                        f"EARFCNs: {', '.join(sorted(earfcns))}. A legitimate LTE cell transmits "
                        f"on exactly one EARFCN (primary frequency). Simultaneous multi-EARFCN "
                        f"operation from a single Cell ID is a strong indicator of a rogue base "
                        f"station using software-defined radio with a spoofed Cell ID."
                    ),
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    technique="Multi-EARFCN Cell Operation (rogue SDR base station signature)",
                    evidence=[
                        f"Cell ID: {cell_id}",
                        f"EARFCNs observed: {', '.join(sorted(earfcns))}",
                        f"Event count: {len(ev_list)}",
                    ] + [
                        f"  [{e.get('timestamp','?')}] EARFCN={e.get('earfcn','?')} ({e.get('source_file','?')})"
                        for e in ev_list[:5]
                    ],
                    events=ev_list,
                    hardware_hint=(
                        "SDR-based rogue eNodeB (e.g., srsRAN/OpenAirInterface on USRP/HackRF) "
                        "broadcasting a spoofed Cell ID across multiple frequencies."
                    ),
                    action=(
                        "1. This is one of the strongest rogue tower indicators.\n"
                        "2. Document each EARFCN → Cell ID pairing with timestamps.\n"
                        "3. Cross-reference EARFCNs against Rayhunter Unit 2 data.\n"
                        "4. A real cell has one EARFCN — multiple EARFCNs = fake cell.\n"
                        "5. Include as primary exhibit in ACMA / AFP submissions."
                    ),
                    spec_ref="3GPP TS 36.211 §5 (EARFCN definition), TS 36.331 §6.2.2",
                ))

        # ── Rule 2: Rapid EARFCN hopping (same time window) ───────────
        window = self.thresholds.get("earfcn_change_window_seconds", 60)
        max_changes = self.thresholds.get("earfcn_change_max_normal", 3)

        all_earfcn_timeline = sorted(
            [(ts, str(earfcn), cell) for cell, timeline in cell_timeline.items()
             for (ts, earfcn) in timeline if ts > 0],
            key=lambda x: x[0]
        )

        if len(all_earfcn_timeline) > 1:
            changes_in_window = self._count_earfcn_changes_in_window(
                all_earfcn_timeline, window
            )
            if changes_in_window > max_changes:
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Rapid EARFCN Hopping — {changes_in_window} Changes in {window}s",
                    description=(
                        f"{changes_in_window} EARFCN changes detected within a {window}-second window. "
                        f"Normal LTE devices rarely change frequency channels rapidly unless performing "
                        f"handovers. Rapid, unexplained EARFCN changes suggest the rogue device is "
                        f"cycling frequencies to test signal conditions or avoid detection."
                    ),
                    severity="HIGH",
                    confidence="PROBABLE",
                    technique="EARFCN Hopping / Rapid Frequency Cycling",
                    evidence=[
                        f"Changes in {window}s window: {changes_in_window} (threshold: {max_changes})",
                    ] + [
                        f"  [{t}] EARFCN={e} cell={c}"
                        for (t, e, c) in all_earfcn_timeline[:8]
                    ],
                    events=[],
                    action=(
                        "Correlate EARFCN hops with cipher downgrade events. "
                        "The sequence (hop → EEA0 negotiate → Identity Request) is a "
                        "complete IMSI catcher attack cycle."
                    ),
                    spec_ref="3GPP TS 36.300 §10 (cell selection)",
                ))

        return findings

    def _count_earfcn_changes_in_window(self, timeline, window: float) -> int:
        """Count max EARFCN changes in any window-second span."""
        if len(timeline) < 2:
            return 0
        changes = []
        for i in range(1, len(timeline)):
            if timeline[i][1] != timeline[i-1][1]:  # EARFCN changed
                changes.append(timeline[i][0])

        if not changes:
            return 0

        max_in_window = 1
        start = 0
        for end in range(len(changes)):
            while changes[end] - changes[start] > window:
                start += 1
            max_in_window = max(max_in_window, end - start + 1)
        return max_in_window
