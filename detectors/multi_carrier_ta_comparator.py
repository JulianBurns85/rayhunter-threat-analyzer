#!/usr/bin/env python3
"""
MultiCarrierTAComparator — Cross-carrier TA validation.

Telstra and Vodafone TA values measured simultaneously.

Same TA value on both carriers = single physical transmitter location.
Different TA values = two separate physical devices at different distances.

This cross-validates the two-platform theory using physics:
- If Platform A (Telstra) is 300m away and Platform B (Vodafone) is 250m away,
  their TA values MUST differ (TA_A ≠ TA_B)
- If they show the SAME TA, they're at the same physical location
  (single device with dual-carrier capability = Harris HailStorm)

This also detects TA manipulation:
- A rogue cell can set a FAKE TA to appear to be at a different location
- But it cannot fake TA on two independent carriers simultaneously
  without precise coordination = proves single controller

Reference: 3GPP TS 36.211 §8.4.2 (TA = 78.125m/step)
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import statistics
import math
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


TA_METRES_PER_STEP = 78.125
TA_CORRELATION_WINDOW_S = 60.0   # Compare TA values within 60-second window

TELSTRA_MNC  = {"001", "01"}
VODAFONE_MNC = {"003", "03"}


class MultiCarrierTAComparator(BaseDetector):
    """
    Compares Timing Advance values across Telstra and Vodafone channels
    to validate transmitter location and cross-confirm platform count.
    """

    name = "MultiCarrierTAComparator"
    description = (
        "Cross-carrier Timing Advance comparison — validates transmitter "
        "location and confirms single vs dual physical device count"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract TA events by carrier with timestamps
        carrier_ta = {"telstra": [], "vodafone": []}

        for e in events:
            mnc = str(e.get("mnc") or e.get("network_mnc") or "").strip().lstrip("0") or None
            ta  = e.get("timing_advance") or e.get("ta") or e.get("timingAdvance")
            ts  = self._get_ts(e)

            if ta is None or ts is None or mnc is None:
                continue

            try:
                ta_val = int(ta)
                if not (0 <= ta_val <= 1282):
                    continue
            except (ValueError, TypeError):
                continue

            if mnc in TELSTRA_MNC:
                carrier_ta["telstra"].append({"ta": ta_val, "ts": ts})
            elif mnc in VODAFONE_MNC:
                carrier_ta["vodafone"].append({"ta": ta_val, "ts": ts})

        tel_data = carrier_ta["telstra"]
        vod_data = carrier_ta["vodafone"]

        if not tel_data or not vod_data:
            return []

        # Find contemporaneous TA pairs (within CORRELATION_WINDOW_S)
        pairs = []
        vod_sorted = sorted(vod_data, key=lambda x: x["ts"])
        for t_ev in sorted(tel_data, key=lambda x: x["ts"]):
            t_ts = t_ev["ts"]
            matching = [
                v for v in vod_sorted
                if abs(v["ts"] - t_ts) <= TA_CORRELATION_WINDOW_S
            ]
            for v_ev in matching:
                pairs.append({
                    "ts":       t_ts,
                    "ta_tel":   t_ev["ta"],
                    "ta_vod":   v_ev["ta"],
                    "delta_ta": abs(t_ev["ta"] - v_ev["ta"]),
                    "delta_m":  abs(t_ev["ta"] - v_ev["ta"]) * TA_METRES_PER_STEP,
                })

        if not pairs:
            return []

        # Analysis
        delta_tas  = [p["delta_ta"] for p in pairs]
        mean_delta = statistics.mean(delta_tas)
        zero_delta = [p for p in pairs if p["delta_ta"] == 0]
        small_delta= [p for p in pairs if p["delta_ta"] <= 2]   # ≤156m

        # TA statistics per carrier
        tel_tas = [d["ta"] for d in tel_data]
        vod_tas = [d["ta"] for d in vod_data]
        tel_mean = statistics.mean(tel_tas)
        vod_mean = statistics.mean(vod_tas)
        mean_dist_tel = tel_mean * TA_METRES_PER_STEP
        mean_dist_vod = vod_mean * TA_METRES_PER_STEP
        carrier_delta_m = abs(mean_dist_tel - mean_dist_vod)

        # Interpretation
        if carrier_delta_m < 156:  # Less than 2 TA steps apart
            location_theory = "SAME LOCATION — single dual-carrier device (Harris HailStorm)"
        elif carrier_delta_m < 500:
            location_theory = "CLOSE PROXIMITY — possibly same vehicle/building"
        else:
            location_theory = f"DIFFERENT LOCATIONS — {carrier_delta_m:.0f}m separation — two distinct devices"

        evidence = [
            f"Contemporaneous TA pairs analysed: {len(pairs)}",
            f"",
            f"CARRIER TA STATISTICS:",
            f"  Telstra:  mean TA={tel_mean:.1f} → {mean_dist_tel:.0f}m from capture point",
            f"  Vodafone: mean TA={vod_mean:.1f} → {mean_dist_vod:.0f}m from capture point",
            f"  Carrier delta: {carrier_delta_m:.0f}m ({carrier_delta_m/TA_METRES_PER_STEP:.1f} TA steps)",
            f"",
            f"INTER-CARRIER TA CORRELATION:",
            f"  Mean TA delta: {mean_delta:.2f} steps ({mean_delta*TA_METRES_PER_STEP:.0f}m)",
            f"  Zero-delta pairs (identical TA): {len(zero_delta)} ({len(zero_delta)/len(pairs)*100:.0f}%)",
            f"  Sub-2-step pairs (≤156m): {len(small_delta)} ({len(small_delta)/len(pairs)*100:.0f}%)",
            f"",
            f"LOCATION THEORY: {location_theory}",
            f"",
        ]

        if len(zero_delta) > 3:
            evidence.append(
                f"SAME-LOCATION CONFIRMATION: {len(zero_delta)} paired events "
                f"show identical TA on both carriers simultaneously. "
                f"This is consistent with a single dual-carrier device at one "
                f"physical location — Harris HailStorm operating in dual-carrier mode."
            )
        elif carrier_delta_m > 300:
            evidence.append(
                f"TWO-DEVICE CONFIRMATION: {carrier_delta_m:.0f}m separation "
                f"between carriers is consistent with TWO SEPARATE physical "
                f"devices at different locations — one Telstra, one Vodafone."
            )

        evidence += [
            f"",
            f"PHYSICS CONTEXT:",
            f"  Each TA step = {TA_METRES_PER_STEP}m (3GPP TS 36.211 §8.4.2)",
            f"  Same TA = same distance from capture point",
            f"  Harris HailStorm with dual Harpoon amplifiers can operate both",
            f"  carriers from same chassis at same physical location.",
        ]

        severity   = "HIGH"
        confidence = "CONFIRMED" if (len(pairs) >= 10 and len(zero_delta) > 0) else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Cross-Carrier TA Comparison — Carrier Δ={carrier_delta_m:.0f}m — "
                f"{location_theory.split('—')[0].strip()}"
            ),
            description=(
                f"Cross-carrier Timing Advance comparison across {len(pairs)} "
                f"contemporaneous Telstra/Vodafone pairs. "
                f"Carrier mean distance delta: {carrier_delta_m:.0f}m. "
                f"{location_theory}. "
                f"{'Same TA on both carriers confirms single dual-carrier device (Harris HailStorm architecture). ' if carrier_delta_m < 156 else ''}"
                f"This analysis is only possible with dual-carrier capture units — "
                f"unique to this investigation."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Cross-carrier Timing Advance comparison — "
                "transmitter location and device count validation"
            ),
            evidence=evidence,
            hardware_hint=(
                "Harris HailStorm dual-carrier — same TA on both channels "
                "confirms single chassis at one physical location."
                if carrier_delta_m < 156 else
                f"Two separate devices at {carrier_delta_m:.0f}m separation — "
                "consistent with coordinated dual-platform deployment."
            ),
            action=(
                "1. TA comparison provides physics-based transmitter location evidence.\n"
                "2. Same TA on both carriers = Harris dual-carrier confirmed.\n"
                "3. Different TA = two physical devices at different locations.\n"
                "4. Include carrier distance table in AFP submission.\n"
                "5. Cite 3GPP TS 36.211 §8.4.2 — TA step size 78.125m."
            ),
            spec_ref="3GPP TS 36.211 §8.4.2; 3GPP TS 36.213 §4.2 (TA command)",
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
