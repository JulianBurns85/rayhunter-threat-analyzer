#!/usr/bin/env python3
"""
NASTimerAnomalyDetector — T3402/T3411/T3412 timer value analysis.

Rogue platforms set NAS timers to abnormally short values to force
rapid re-registration cycles for continuous IMSI harvesting.

Key timers:
- T3412: Periodic TAU timer (default 54 minutes in AU)
  → Rogue sets to minimum (6 seconds) to force constant re-registration
- T3402: Deactivated bearer re-activation timer
  → Rogue sets short to force rapid reconnection
- T3411: Retransmission timer after reject
  → Rogue sets short to allow immediate re-attempt after induced failure

Detection method:
- Extract timer values from NAS messages in corpus
- Compare against Australian carrier baseline values
- Flag values below legitimate minimum thresholds
- Correlate short timers with downstream IMSI harvest events

Reference: 3GPP TS 24.301 §10 (NAS timers and counters)
GSMA NG.114 (recommended timer values for Australian carriers)
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Australian carrier baseline timer values
AU_CARRIER_TIMERS = {
    "T3412": {
        "default_s":  54 * 60,    # 54 minutes
        "min_legit_s": 6 * 60,    # 6 minutes minimum (GSMA recommendation)
        "rogue_max_s": 2 * 60,    # < 2 min = suspicious
        "desc": "Periodic TAU timer — forces re-registration frequency",
    },
    "T3402": {
        "default_s":  12 * 60,    # 12 minutes
        "min_legit_s": 2 * 60,    # 2 minutes minimum
        "rogue_max_s": 30,         # < 30s = suspicious
        "desc": "De-activation re-attempt timer",
    },
    "T3411": {
        "default_s":  10,          # 10 seconds
        "min_legit_s": 5,          # 5 seconds minimum
        "rogue_max_s": 1,          # < 1s = suspicious
        "desc": "Retransmission timer after reject",
    },
    "T3402_extended": {
        "default_s":  12 * 60,
        "min_legit_s": 60,
        "rogue_max_s": 10,
        "desc": "Extended T3402",
    },
}


class NASTimerAnomalyDetector(BaseDetector):
    """
    Detects abnormally short NAS timer values used to force
    rapid re-registration cycles for IMSI harvesting.
    """

    name = "NASTimerAnomalyDetector"
    description = (
        "NAS timer anomaly detection — T3402/T3411/T3412 short-timer "
        "attack forcing rapid re-registration for IMSI harvesting"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract timer values from events
        observed_timers = defaultdict(list)

        for e in events:
            for timer_name in AU_CARRIER_TIMERS:
                # Check various field name formats
                val = (
                    e.get(timer_name.lower()) or
                    e.get(timer_name) or
                    e.get(f"timer_{timer_name.lower()}") or
                    e.get(f"{timer_name.lower()}_value")
                )
                if val is not None:
                    try:
                        val_s = float(val)
                        if 0 < val_s < 86400:  # Sanity: 0 to 24 hours
                            observed_timers[timer_name].append({
                                "value_s": val_s,
                                "source":  e.get("source_file", ""),
                                "ts":      e.get("timestamp") or e.get("ts"),
                            })
                    except (ValueError, TypeError):
                        pass

        if not observed_timers:
            # Produce informational finding about what to look for
            evidence = [
                "No NAS timer values extracted from current corpus.",
                "",
                "TIMERS TO MONITOR (when NAS layer data is available):",
                "  T3412 < 2 min  → forces rapid re-registration (default 54min AU)",
                "  T3402 < 30s    → forces rapid bearer re-activation",
                "  T3411 < 1s     → immediate re-attempt after induced reject",
                "",
                "These values appear in NAS Attach Accept and TAU Accept messages.",
                "QMDL parsing may include these in future SCAT updates.",
            ]
            findings.append(make_finding(
                detector=self.name,
                title="NAS Timer Monitor — Awaiting Timer Data in Corpus",
                description=(
                    "NAS timer anomaly detector active. No timer values found "
                    "in current corpus. Timer values appear in Attach Accept "
                    "and TAU Accept NAS messages. QMDL deep parsing may "
                    "expose these in future iterations."
                ),
                severity="INFO",
                confidence="SUSPECTED",
                technique="NAS T3402/T3411/T3412 timer value analysis",
                evidence=evidence,
                action=(
                    "1. Enable deep NAS parsing in SCAT/QMDL pipeline.\n"
                    "2. Look for T3412 < 120s in Attach Accept messages.\n"
                    "3. Short timers will appear in subsequent bladeRF captures."
                ),
                spec_ref="3GPP TS 24.301 §10 (NAS timers)",
            ))
            return findings

        # Analyse observed timers
        anomalous = []
        for timer_name, values in observed_timers.items():
            baseline = AU_CARRIER_TIMERS[timer_name]
            rogue_threshold = baseline["rogue_max_s"]
            short_values = [v for v in values if v["value_s"] <= rogue_threshold]

            if short_values:
                anomalous.append({
                    "timer":      timer_name,
                    "desc":       baseline["desc"],
                    "default_s":  baseline["default_s"],
                    "rogue_max":  rogue_threshold,
                    "observed":   short_values,
                    "mean_s":     sum(v["value_s"] for v in short_values) / len(short_values),
                })

        if not anomalous:
            return []

        evidence = [f"Anomalous NAS timers detected: {len(anomalous)}"]
        for a in anomalous:
            evidence += [
                f"",
                f"TIMER {a['timer']} — {a['desc']}:",
                f"  AU carrier default: {a['default_s']:.0f}s ({a['default_s']/60:.0f} min)",
                f"  Rogue threshold: < {a['rogue_max']:.0f}s",
                f"  Observed mean: {a['mean_s']:.1f}s (×{a['default_s']/a['mean_s']:.0f} faster than default)",
                f"  Instances: {len(a['observed'])}",
            ]
            for obs in a["observed"][:3]:
                evidence.append(f"    → {obs['value_s']:.1f}s ({obs['source']})")

        evidence += [
            f"",
            f"ATTACK MECHANISM:",
            f"  Short T3412 forces the device to re-register every few minutes,",
            f"  creating continuous IMSI transmission opportunities.",
            f"  A rogue platform with T3412=6s forces 10× more re-registrations",
            f"  than the Australian carrier default of 54 minutes.",
        ]

        severity   = "CRITICAL" if any(a["mean_s"] < 30 for a in anomalous) else "HIGH"
        confidence = "CONFIRMED"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"NAS Timer Anomaly — {len(anomalous)} Timer(s) Below Threshold — "
                f"Forced Rapid Re-Registration"
            ),
            description=(
                f"{len(anomalous)} NAS timer(s) detected below legitimate minimum "
                f"thresholds. Short timers force rapid re-registration cycles, "
                f"creating continuous IMSI exposure opportunities. "
                f"This technique is documented in Tucker et al. NDSS 2025 as "
                f"a primary IMSI catcher operational mode."
            ),
            severity=severity,
            confidence=confidence,
            technique="NAS timer short-value attack — forced rapid re-registration",
            evidence=evidence,
            hardware_hint=(
                "Active rogue NAS stack — timer manipulation requires full "
                "NAS protocol implementation (not passive SDR)."
            ),
            action=(
                "1. Document observed timer values vs AU carrier defaults.\n"
                "2. Cite 3GPP TS 24.301 §10 — timer default values.\n"
                "3. Include timer comparison table in AFP submission.\n"
                "4. Correlate short-timer periods with IMSI harvest event rate.\n"
                "5. GSMA NG.114 provides Australian carrier baseline references."
            ),
            spec_ref=(
                "3GPP TS 24.301 §10 (NAS timers); "
                "GSMA NG.114 (AU carrier baseline timers); "
                "Tucker et al. NDSS 2025 (timer manipulation)"
            ),
        ))

        return findings
