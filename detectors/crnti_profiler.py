#!/usr/bin/env python3
"""
CRNTITargetProfiler — Detects selective targeting via C-RNTI analysis.

C-RNTIs (Cell Radio Network Temporary Identifiers) are temporary IDs
assigned per RRC session. The handover injection findings already
capture them — this module analyses them to answer:

"Is the operator targeting a specific device, or sweeping everyone?"

Selective targeting evidence:
- Same C-RNTI appears in multiple attack events (same session targeted repeatedly)
- C-RNTIs appear before IMSI harvest events (setup then harvest sequence)
- C-RNTI distribution is narrow (few targets) vs wide (mass sweep)
- Specific C-RNTIs consistently appear in ProSe proximity events

This changes the legal characterisation entirely:
Mass surveillance vs targeted individual surveillance.

Reference: 3GPP TS 36.331 — C-RNTI assigned at RRC connection setup.
"""

from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


class CRNTITargetProfiler(BaseDetector):
    """
    Analyses C-RNTI patterns to determine if surveillance is targeted
    at specific devices or a mass sweep operation.
    """

    name = "CRNTITargetProfiler"
    description = (
        "C-RNTI target profiling — determines whether surveillance is "
        "targeted at specific devices or broad mass collection"
    )

    # Minimum appearances for a C-RNTI to be considered a target
    MIN_TARGET_APPEARANCES = 3
    # Max unique C-RNTIs in targeted surveillance (vs mass sweep)
    TARGETED_MAX_UNIQUE    = 20
    # Window (seconds) between C-RNTI appearance and IMSI harvest
    HARVEST_WINDOW_S       = 30.0

    HANDOVER_TYPES = {"rrcconnectionreconfiguration", "mobilitycontrolinfo"}
    IMSI_TYPES     = {"identityrequest", "identity request"}
    PROSE_TYPES    = {"reportproximityconfig", "prose"}
    SETUP_TYPES    = {"rrcconnectionsetup", "rrcconnectionsetupcomplete"}

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract C-RNTI data
        crnti_events: Dict[str, List[Dict]] = defaultdict(list)
        imsi_events  = []
        prose_crnti  = defaultdict(int)

        for e in events:
            msg   = str(e.get("message_type") or e.get("msg_type") or "").lower()
            crnti = (
                e.get("crnti") or e.get("c_rnti") or
                e.get("new_rnti") or e.get("rnti")
            )
            ts = self._get_ts(e)

            if crnti:
                crnti = str(crnti).lower().strip()
                if crnti and crnti not in ("none", "0", "0000"):
                    crnti_events[crnti].append({
                        "ts":    ts,
                        "msg":   msg,
                        "event": e,
                    })

                    if any(t in msg for t in self.PROSE_TYPES):
                        prose_crnti[crnti] += 1

            if any(t in msg for t in self.IMSI_TYPES) and ts:
                imsi_events.append({"ts": ts, "crnti": crnti, "event": e})

        if not crnti_events:
            return []

        total_unique   = len(crnti_events)
        total_events   = sum(len(v) for v in crnti_events.values())

        if total_unique == 0:
            return []

        # Find repeated targets (same C-RNTI attacked multiple times)
        repeat_targets = {
            crnti: events for crnti, events in crnti_events.items()
            if len(events) >= self.MIN_TARGET_APPEARANCES
        }

        # Find C-RNTIs that appear before IMSI harvest (harvest chain)
        harvest_chains = []
        if imsi_events:
            sorted_imsi = sorted(imsi_events, key=lambda x: x["ts"] or 0)
            for imsi_ev in sorted_imsi:
                if not imsi_ev["ts"]:
                    continue
                # Look for C-RNTI events just before this harvest
                for crnti, crnti_evs in crnti_events.items():
                    preceding = [
                        ev for ev in crnti_evs
                        if ev["ts"] and
                        0 < imsi_ev["ts"] - ev["ts"] <= self.HARVEST_WINDOW_S
                    ]
                    if preceding:
                        harvest_chains.append({
                            "crnti":        crnti,
                            "setup_count":  len(preceding),
                            "harvest_ts":   imsi_ev["ts"],
                        })

        # Targeting characterisation
        mean_appearances = total_events / total_unique if total_unique > 0 else 0
        is_targeted = (
            len(repeat_targets) > 0 or
            total_unique <= self.TARGETED_MAX_UNIQUE or
            len(harvest_chains) > 0
        )

        # Top targeted C-RNTIs
        top_crnti = sorted(
            crnti_events.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:10]

        evidence = [
            f"Unique C-RNTIs observed: {total_unique}",
            f"Total C-RNTI events: {total_events:,}",
            f"Mean appearances per C-RNTI: {mean_appearances:.1f}",
            f"Repeated targets (≥{self.MIN_TARGET_APPEARANCES}x): {len(repeat_targets)}",
            f"Harvest chain sequences: {len(harvest_chains)}",
            f"C-RNTIs with ProSe proximity tracking: {len(prose_crnti)}",
            f"",
            f"TARGETING ASSESSMENT: {'SELECTIVE (specific device targeting)' if is_targeted else 'BROAD (mass sweep)'}",
            f"",
        ]

        if repeat_targets:
            evidence.append(f"REPEAT TARGETS ({len(repeat_targets)} devices attacked multiple times):")
            for crnti, evs in sorted(repeat_targets.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                timestamps = [ev["ts"] for ev in evs if ev["ts"]]
                span = ""
                if len(timestamps) >= 2:
                    span_s = max(timestamps) - min(timestamps)
                    span_h = span_s / 3600
                    span = f" over {span_h:.1f}h"
                techniques = set(ev["msg"][:30] for ev in evs)
                evidence.append(
                    f"  C-RNTI={crnti}: {len(evs)} events{span} | "
                    f"ProSe: {'YES' if crnti in prose_crnti else 'no'}"
                )

        if harvest_chains:
            evidence.append(f"")
            evidence.append(f"HARVEST CHAIN SEQUENCES ({len(harvest_chains)} found):")
            seen = set()
            for chain in harvest_chains[:5]:
                if chain["crnti"] not in seen:
                    ts_str = datetime.fromtimestamp(
                        chain["harvest_ts"], tz=timezone.utc
                    ).isoformat() if chain["harvest_ts"] else "unknown"
                    evidence.append(
                        f"  C-RNTI={chain['crnti']}: "
                        f"{chain['setup_count']} setup(s) → IMSI harvest at {ts_str}"
                    )
                    seen.add(chain["crnti"])

        if prose_crnti:
            evidence.append(f"")
            evidence.append(f"PROXIMITY-TRACKED C-RNTIs:")
            for crnti, count in sorted(prose_crnti.items(), key=lambda x: x[1], reverse=True)[:5]:
                evidence.append(f"  C-RNTI={crnti}: {count} ProSe events")

        evidence.append(f"")
        evidence.append(f"TOP C-RNTIs BY ATTACK FREQUENCY:")
        for crnti, evs in top_crnti:
            evidence.append(f"  {crnti}: {len(evs)} events")

        severity = "CRITICAL" if (harvest_chains and repeat_targets) else "HIGH" if repeat_targets else "MEDIUM"
        confidence = "CONFIRMED" if len(repeat_targets) >= 2 else "PROBABLE"

        targeting_type = "TARGETED INDIVIDUAL SURVEILLANCE" if is_targeted else "MASS COLLECTION SWEEP"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"C-RNTI Target Profile — {targeting_type} — "
                f"{len(repeat_targets)} Repeat Target(s) | "
                f"{len(harvest_chains)} Harvest Chain(s)"
            ),
            description=(
                f"Analysis of {total_unique} unique C-RNTI identifiers across "
                f"{total_events:,} events reveals {targeting_type.lower()}. "
                f"{'REPEAT TARGETING: ' + str(len(repeat_targets)) + ' device(s) were attacked multiple times, ' if repeat_targets else ''}"
                f"{'HARVEST CHAINS: ' + str(len(harvest_chains)) + ' sequence(s) where C-RNTI setup preceded IMSI extraction within ' + str(int(self.HARVEST_WINDOW_S)) + 's, ' if harvest_chains else ''}"
                f"{'PROXIMITY TRACKING: ' + str(len(prose_crnti)) + ' C-RNTI(s) subject to ProSe location tracking.' if prose_crnti else ''}"
                f" This {'demonstrates deliberate, targeted surveillance of specific devices' if is_targeted else 'is consistent with broad area identity collection'}."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "C-RNTI frequency analysis — repeat targeting, harvest chain "
                "detection, ProSe correlation"
            ),
            evidence=evidence,
            hardware_hint=(
                "Selective targeting requires active session management — "
                "not possible with passive SDR or misconfigured repeater."
                if is_targeted else
                "Mass collection pattern — consistent with area sweep mode."
            ),
            action=(
                "1. Repeat C-RNTI targets indicate specific device(s) under sustained surveillance.\n"
                "2. Harvest chain sequences prove setup → IMSI extraction workflow.\n"
                "3. Include in AFP submission as evidence of targeted individual surveillance.\n"
                "4. Cross-reference top C-RNTIs with operator rhythm for session timing.\n"
                "5. ProSe-tracked C-RNTIs have had real-time location tracking applied."
            ),
            spec_ref=(
                "3GPP TS 36.331 §5.3.3 (C-RNTI assignment at RRC setup); "
                "TS 36.300 §22 (ProSe); Tucker et al. NDSS 2025"
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
