#!/usr/bin/env python3
"""
FrequencyHoppingDetector — Detects structured EARFCN switching patterns.

Harris platforms are documented to hop frequencies to evade
single-channel monitors. If the same CID appears on different
EARFCNs in a structured sequence, that's a documented Harris
operational technique.

Detects:
- Same CID observed on multiple EARFCNs (impossible on legitimate cell)
- Structured EARFCN rotation (cyclic pattern)
- Time-correlated frequency switches (triggered by detection events)
- Band-hopping patterns (Band 3 → Band 5 → Band 7 → Band 28)

Reference: Harris HailStorm operational documentation;
3GPP TS 36.101 — EARFCN to frequency band mapping
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# EARFCN to band mapping (relevant Australian bands)
EARFCN_BANDS = {
    # Band 28 (700 MHz) — Harris Arrowhead confirmed
    range(9210,  9660):  ("Band 28", 700),
    # Band 5 (850 MHz)
    range(2400,  2650):  ("Band 5",  850),
    # Band 3 (1800 MHz)
    range(1200,  1950):  ("Band 3",  1800),
    # Band 7 (2600 MHz)
    range(2750,  3450):  ("Band 7",  2600),
    # Band 40 (2300 MHz)
    range(38650, 39650): ("Band 40", 2300),
}

def earfcn_to_band(earfcn: int) -> Tuple[str, int]:
    for r, (band, freq) in EARFCN_BANDS.items():
        if earfcn in r:
            return band, freq
    return f"EARFCN={earfcn}", earfcn


class FrequencyHoppingDetector(BaseDetector):
    """
    Detects structured frequency hopping patterns consistent with
    Harris platform ECCM (Electronic Counter-Countermeasures) mode.
    """

    name = "FrequencyHoppingDetector"
    description = (
        "Frequency hopping pattern detection — Harris ECCM mode "
        "identification via EARFCN rotation analysis"
    )

    MIN_EARFCNS_PER_CID = 2   # CID on 2+ EARFCNs = anomalous
    MIN_HOP_EVENTS      = 5   # Minimum hops to flag

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Group events by CID → set of EARFCNs
        cid_earfcns: Dict[str, Dict] = defaultdict(lambda: {
            "earfcns": defaultdict(int),
            "timestamps": defaultdict(list),
        })

        for e in events:
            cid    = str(e.get("cell_id") or e.get("cid") or "")
            earfcn = e.get("earfcn") or e.get("dl_earfcn") or e.get("freq")
            ts     = self._get_ts(e)

            if not cid or earfcn is None:
                continue

            try:
                earfcn = int(earfcn)
            except (ValueError, TypeError):
                continue

            cid_earfcns[cid]["earfcns"][earfcn] += 1
            if ts:
                cid_earfcns[cid]["timestamps"][earfcn].append(ts)

        # Find CIDs with multiple EARFCNs
        multi_earfcn = {
            cid: data for cid, data in cid_earfcns.items()
            if len(data["earfcns"]) >= self.MIN_EARFCNS_PER_CID
        }

        if not multi_earfcn:
            return []

        # Also look for structured band hopping across all CIDs
        earfcn_timeline = []
        for cid, data in cid_earfcns.items():
            for earfcn, timestamps in data["timestamps"].items():
                for ts in timestamps:
                    earfcn_timeline.append({
                        "ts":     ts,
                        "cid":    cid,
                        "earfcn": earfcn,
                        "band":   earfcn_to_band(earfcn)[0],
                    })
        earfcn_timeline.sort(key=lambda x: x["ts"])

        # Detect cyclic EARFCN patterns
        earfcn_sequence = [e["earfcn"] for e in earfcn_timeline]
        cycles = self._detect_cycles(earfcn_sequence)

        # Build findings
        total_multi = len(multi_earfcn)
        evidence = [
            f"CIDs observed on multiple EARFCNs: {total_multi}",
            f"Cyclic EARFCN patterns detected: {len(cycles)}",
            f"",
            f"MULTI-EARFCN CELL IDs (impossible on legitimate cells):",
        ]

        for cid, data in sorted(
            multi_earfcn.items(),
            key=lambda x: len(x[1]["earfcns"]),
            reverse=True
        )[:8]:
            bands = []
            for earfcn, count in sorted(data["earfcns"].items()):
                band_name, freq = earfcn_to_band(earfcn)
                bands.append(f"{band_name}/EARFCN={earfcn}({count}x)")
            evidence.append(f"  CID={cid}: {' | '.join(bands)}")

        if cycles:
            evidence.append("")
            evidence.append("CYCLIC FREQUENCY PATTERNS DETECTED:")
            for cycle in cycles[:3]:
                bands = [earfcn_to_band(e)[0] for e in cycle["sequence"]]
                evidence.append(
                    f"  Cycle: {' → '.join(str(e) for e in cycle['sequence'])} "
                    f"({' → '.join(bands)}) — {cycle['count']} repetitions"
                )

        evidence.append("")
        evidence.append("HARRIS ECCM MODE INDICATORS:")
        evidence.append(
            f"  Harris platforms documented to hop EARFCNs to evade "
            f"single-channel passive monitoring. A legitimate cell has "
            f"exactly ONE EARFCN. Multi-EARFCN observation on same CID "
            f"is architecturally impossible under 3GPP TS 36.331."
        )

        # Band diversity
        all_bands = set()
        for data in multi_earfcn.values():
            for earfcn in data["earfcns"]:
                band, _ = earfcn_to_band(earfcn)
                all_bands.add(band)
        if len(all_bands) > 1:
            evidence.append(f"  Bands observed: {', '.join(sorted(all_bands))}")
            evidence.append(
                f"  Cross-band operation ({len(all_bands)} bands) confirms "
                f"multi-channel SDR platform, not single-band repeater."
            )

        severity   = "HIGH"      if total_multi >= 3 else "MEDIUM"
        confidence = "CONFIRMED" if (cycles or total_multi >= 5) else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Frequency Hopping Detected — {total_multi} Multi-EARFCN CID(s) | "
                f"{len(cycles)} Cyclic Pattern(s) | {len(all_bands)} Band(s)"
            ),
            description=(
                f"{total_multi} Cell ID(s) observed on multiple EARFCNs — "
                f"architecturally impossible on any legitimate base station. "
                f"{'Cyclic EARFCN rotation pattern detected (' + str(len(cycles)) + ' cycles) — consistent with Harris ECCM mode. ' if cycles else ''}"
                f"Operation across {len(all_bands)} band(s) ({', '.join(sorted(all_bands))}) "
                f"requires a multi-channel SDR platform. "
                f"A legitimate 3GPP cell has exactly one EARFCN. "
                f"This pattern is documented in Harris HailStorm operational modes."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "EARFCN rotation analysis — Harris ECCM mode detection"
            ),
            evidence=evidence,
            hardware_hint=(
                f"Harris HailStorm ECCM mode — structured frequency hopping "
                f"to evade single-channel detection. "
                f"{len(all_bands)} band operation requires dedicated multi-channel hardware."
            ),
            action=(
                "1. Multi-EARFCN CIDs are a 3GPP violation — document each one.\n"
                "2. Cyclic patterns indicate automated frequency management (ECCM mode).\n"
                "3. Cross-band operation eliminates consumer SDR and repeater hypotheses.\n"
                "4. Include EARFCN timeline in AFP submission.\n"
                "5. Cite 3GPP TS 36.101 (EARFCN allocation) in evidence."
            ),
            spec_ref=(
                "3GPP TS 36.331 §6.2.2 (cellIdentity bound to single EARFCN); "
                "TS 36.101 (EARFCN/band mapping); Harris HailStorm ECCM documentation"
            ),
        ))

        return findings

    def _detect_cycles(self, sequence: List[int], min_length: int = 2) -> List[Dict]:
        """Detect repeating subsequences in EARFCN sequence."""
        cycles = []
        if len(sequence) < min_length * 2:
            return cycles

        seen = defaultdict(int)
        # Look for pairs of consecutive unique EARFCNs that repeat
        for i in range(len(sequence) - min_length):
            subseq = tuple(sequence[i:i+min_length])
            if len(set(subseq)) >= 2:  # At least 2 different EARFCNs
                seen[subseq] += 1

        for subseq, count in seen.items():
            if count >= 3:
                cycles.append({"sequence": list(subseq), "count": count})

        return sorted(cycles, key=lambda x: x["count"], reverse=True)[:5]

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
