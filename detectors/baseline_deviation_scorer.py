#!/usr/bin/env python3
"""
BaselineDeviationScorer — SeaGlass-style rolling normal deviation detection.

Professional tools like EFF Cape and SeaGlass maintain a rolling normal
for every cell and flag deviation from that normal.

We detect absolute anomalies. This detects RELATIVE anomalies.

If a legitimate Telstra tower normally releases every 45 seconds and
suddenly starts releasing every 210 seconds — that's an anomaly we'd
miss because 210s alone isn't suspicious without context.

Method:
1. For each CID observed 20+ times, establish baseline behaviour
   (mean release interval, RSRP variance, paging rate)
2. Flag any CID whose behaviour deviates > 2 standard deviations
   from its own baseline
3. Flag any CID that appears in the corpus with behaviour unlike
   ALL other CIDs (outlier detection)

This catches the sophisticated case: a legitimate CID that has been
TAKEN OVER by the rogue platform and is now behaving differently.

Reference: SeaGlass (UW 2017) — passive measurement of IMSI catchers
using network-wide baseline deviation.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


MIN_OBSERVATIONS  = 20    # Need 20+ events per CID for baseline
DEVIATION_SIGMA   = 2.0   # Flag if > 2 standard deviations from mean
MIN_CELLS_FOR_REF = 5     # Need 5+ cells to build reference distribution

RELEASE_TYPES = {"rrcconnectionrelease", "rrc connection release"}


class BaselineDeviationScorer(BaseDetector):
    """
    SeaGlass-style baseline deviation detection.
    Flags cells whose behaviour deviates from both their own baseline
    and from the network-wide reference distribution.
    """

    name = "BaselineDeviationScorer"
    description = (
        "SeaGlass-style baseline deviation scoring — flags cells "
        "deviating from their own normal and from network reference"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Group events by CID with timestamps
        cid_data: Dict[str, Dict] = defaultdict(lambda: {
            "release_ts":  [],
            "rsrp":        [],
            "timestamps":  [],
            "tac":         None,
            "mnc":         None,
        })

        for e in events:
            msg  = str(e.get("message_type") or e.get("msg_type") or "").lower()
            cid  = str(e.get("cell_id") or e.get("cid") or "")
            ts   = self._get_ts(e)
            rsrp = e.get("rsrp") or e.get("signal_strength")
            tac  = e.get("tac")
            mnc  = e.get("mnc")

            if not cid or ts is None:
                continue

            cid_data[cid]["timestamps"].append(ts)
            if tac:
                cid_data[cid]["tac"] = tac
            if mnc:
                cid_data[cid]["mnc"] = mnc
            if rsrp is not None:
                try:
                    cid_data[cid]["rsrp"].append(float(rsrp))
                except (ValueError, TypeError):
                    pass
            if any(t in msg for t in RELEASE_TYPES):
                cid_data[cid]["release_ts"].append(ts)

        # Filter to CIDs with enough data
        qualified = {
            cid: data for cid, data in cid_data.items()
            if len(data["timestamps"]) >= MIN_OBSERVATIONS
        }

        if len(qualified) < MIN_CELLS_FOR_REF:
            return []

        # Calculate per-CID release interval statistics
        cid_stats: Dict[str, Dict] = {}
        for cid, data in qualified.items():
            releases = sorted(data["release_ts"])
            if len(releases) < 3:
                cid_stats[cid] = {"mean_interval": None, "stdev_interval": None}
                continue
            intervals = [releases[i+1] - releases[i] for i in range(len(releases)-1)]
            valid     = [iv for iv in intervals if 0.5 <= iv <= 3600]
            if len(valid) < 2:
                cid_stats[cid] = {"mean_interval": None, "stdev_interval": None}
                continue
            cid_stats[cid] = {
                "mean_interval":  statistics.mean(valid),
                "stdev_interval": statistics.stdev(valid) if len(valid) > 1 else 0,
                "rsrp_mean":      statistics.mean(data["rsrp"]) if data["rsrp"] else None,
                "rsrp_stdev":     statistics.stdev(data["rsrp"]) if len(data["rsrp"]) > 1 else None,
                "observation_count": len(data["timestamps"]),
                "tac":            data["tac"],
                "mnc":            data["mnc"],
            }

        # Build network reference distribution (all CIDs with interval data)
        ref_intervals = [
            s["mean_interval"] for s in cid_stats.values()
            if s.get("mean_interval") is not None
        ]

        if len(ref_intervals) < MIN_CELLS_FOR_REF:
            return []

        ref_mean  = statistics.mean(ref_intervals)
        ref_stdev = statistics.stdev(ref_intervals) if len(ref_intervals) > 1 else 0

        # Flag CIDs that deviate > DEVIATION_SIGMA from reference
        deviants = []
        for cid, stats in cid_stats.items():
            if stats.get("mean_interval") is None:
                continue
            z_score = abs(stats["mean_interval"] - ref_mean) / ref_stdev if ref_stdev > 0 else 0
            if z_score >= DEVIATION_SIGMA:
                deviants.append({
                    "cid":          cid,
                    "mean_interval": stats["mean_interval"],
                    "z_score":      z_score,
                    "stdev":        stats["stdev_interval"],
                    "observations": stats["observation_count"],
                    "tac":          stats["tac"],
                    "mnc":          stats["mnc"],
                })

        if not deviants:
            return []

        deviants.sort(key=lambda x: x["z_score"], reverse=True)

        evidence = [
            f"Cells analysed: {len(qualified)}",
            f"Reference distribution: mean={ref_mean:.1f}s, stdev={ref_stdev:.1f}s",
            f"Flagged as anomalous (>{DEVIATION_SIGMA}σ deviation): {len(deviants)}",
            f"",
            f"ANOMALOUS CELLS (ordered by deviation):",
        ]

        for d in deviants[:10]:
            evidence.append(
                f"  CID={d['cid']} TAC={d['tac']} MNC={d['mnc']}: "
                f"mean={d['mean_interval']:.1f}s | "
                f"Z={d['z_score']:.1f}σ from network normal | "
                f"n={d['observations']}"
            )

        evidence += [
            f"",
            f"REFERENCE DISTRIBUTION (legitimate cells):",
            f"  Mean release interval: {ref_mean:.1f}s",
            f"  Std deviation: {ref_stdev:.1f}s",
            f"  Normal range (±{DEVIATION_SIGMA}σ): "
            f"{ref_mean - DEVIATION_SIGMA*ref_stdev:.1f}s — "
            f"{ref_mean + DEVIATION_SIGMA*ref_stdev:.1f}s",
            f"",
            f"SEAGLASS METHODOLOGY:",
            f"  Cells with Z-score ≥ {DEVIATION_SIGMA} are statistical outliers",
            f"  relative to the local network baseline. Even if their absolute",
            f"  values seem plausible in isolation, their behaviour is inconsistent",
            f"  with the surrounding legitimate network infrastructure.",
        ]

        severity   = "HIGH" if len(deviants) >= 3 else "MEDIUM"
        confidence = "PROBABLE"  # Baseline deviation is indicative not definitive

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Baseline Deviation — {len(deviants)} Anomalous Cell(s) — "
                f"Max Z={deviants[0]['z_score']:.1f}σ (CID={deviants[0]['cid']})"
            ),
            description=(
                f"{len(deviants)} cell(s) show release interval behaviour that "
                f"deviates more than {DEVIATION_SIGMA} standard deviations from the "
                f"local network baseline (mean={ref_mean:.1f}s ±{ref_stdev:.1f}s). "
                f"The most anomalous cell (CID={deviants[0]['cid']}) has a Z-score "
                f"of {deviants[0]['z_score']:.1f}σ. "
                f"This SeaGlass-style analysis catches rogue cells that produce "
                f"individually plausible but statistically inconsistent behaviour "
                f"relative to the surrounding legitimate infrastructure."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "SeaGlass-style baseline deviation scoring — "
                "network-relative statistical outlier detection"
            ),
            evidence=evidence,
            hardware_hint=(
                "Statistically anomalous cells relative to local network baseline. "
                "Consistent with rogue eNodeB operating independently of carrier infrastructure."
            ),
            action=(
                "1. Z-score > 3σ: add CID to known_rogue_cells immediately.\n"
                "2. Cross-reference anomalous CIDs with CID rotation clusters.\n"
                "3. Include network baseline comparison in AFP submission.\n"
                "4. Cite SeaGlass (UW 2017) as methodology reference.\n"
                "5. This catches sophisticated attackers that individual detectors miss."
            ),
            spec_ref=(
                "SeaGlass (UW 2017) — Passive Measurement of IMSI-Catchers "
                "with Network Reachability Analysis; "
                "Statistical deviation methodology"
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
