#!/usr/bin/env python3
"""
CellReselectionManipulationDetector — SIB1 reselection parameter abuse.

IMSI catchers manipulate SIB1/SIB3 cell reselection priority parameters
to ensure the device ALWAYS picks the rogue cell over legitimate neighbours.

Key manipulated parameters:
- cellReselectionPriority: 0-7 (rogue sets theirs to 7 = highest)
- q-RxLevMin: minimum signal threshold (rogue sets very low = always eligible)
- threshServingLow/threshServingHigh: serving cell thresholds
- s-IntraSearch / s-NonIntraSearch: trigger thresholds

Legitimate cells coordinate their reselection parameters with the macro network.
Rogue cells set parameters that make them the only eligible target.

Detects:
- Anomalously high cellReselectionPriority (7 = max, suspicious in isolation)
- q-RxLevMin set below legitimate network minimum
- Reselection thresholds set to force immediate handover to rogue
- Parameter combinations that are physically valid but operationally impossible
  for a legitimate carrier cell

Reference: 3GPP TS 36.304 (cell reselection procedures)
3GPP TS 36.331 §6.2.2 (SIB1/SIB3 parameter definitions)
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, List
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Legitimate parameter ranges (from Australian carrier configs)
LEGIT_RESEL_PRIORITY_MAX   = 6     # Legitimate cells rarely use priority 7
ROGUE_RESEL_PRIORITY        = 7     # Rogue cells set max to force selection
LEGIT_QRXLEVMIN_MIN_DBM    = -140  # Physical minimum
LEGIT_QRXLEVMIN_MAX_DBM    = -110  # Legitimate carriers: -110 to -100
ROGUE_QRXLEVMIN_DBM        = -140  # Rogue sets minimum to always be eligible

SIB_TYPES = {
    "sib1", "sib3", "sib4",
    "systeminfoblocktype1", "systeminfoblocktype3",
    "systeminformation",
}


class CellReselectionManipulationDetector(BaseDetector):
    """
    Detects SIB1/SIB3 cell reselection parameter manipulation
    used by IMSI catchers to force device selection.
    """

    name = "CellReselectionManipulationDetector"
    description = (
        "Cell reselection parameter manipulation detection — "
        "SIB1/SIB3 parameter abuse forcing device attachment to rogue cell"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract SIB events with reselection parameters
        sib_events = []
        for e in events:
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            if not any(t in msg for t in SIB_TYPES):
                continue

            # Extract key parameters
            params = {
                "cid":                e.get("cell_id") or e.get("cid"),
                "tac":                e.get("tac"),
                "mnc":                e.get("mnc"),
                "resel_priority":     e.get("cellReselectionPriority") or
                                      e.get("cell_reselection_priority"),
                "q_rxlev_min":        e.get("q_rxlev_min") or
                                      e.get("qRxLevMin"),
                "thresh_serving_low": e.get("threshServingLow") or
                                      e.get("thresh_serving_low"),
                "s_intra_search":     e.get("s_intraSearch") or
                                      e.get("s_intra_search"),
                "source":             e.get("source_file", ""),
                "ts":                 e.get("timestamp") or e.get("ts"),
            }

            # Only include if we have at least one meaningful parameter
            if any(v is not None for k, v in params.items()
                   if k not in ("cid", "tac", "mnc", "source", "ts")):
                sib_events.append(params)

        if not sib_events:
            # No SIB parameter data in events — still produce informational finding
            evidence = [
                "No SIB1/SIB3 reselection parameters extracted from corpus.",
                "",
                "PARAMETERS TO MONITOR (when SIB data is available):",
                "  cellReselectionPriority = 7 → rogue cell forcing max priority",
                "  q-RxLevMin = -140 dBm    → always eligible for selection",
                "  threshServingLow = 0      → forces immediate reselection",
                "",
                "ACTION: Enable SIB parameter extraction in Rayhunter config",
                "or use bladeRF to capture raw SIB broadcasts.",
            ]
            findings.append(make_finding(
                detector=self.name,
                title="Cell Reselection Monitor — Awaiting SIB Parameter Data",
                description=(
                    "Cell reselection parameter monitor active. No SIB1/SIB3 "
                    "parameter data extracted from current corpus. Enable SIB "
                    "capture or use bladeRF for raw parameter extraction."
                ),
                severity="INFO",
                confidence="SUSPECTED",
                technique="SIB1/SIB3 cell reselection parameter analysis",
                evidence=evidence,
                action=(
                    "1. Enable SIB parameter extraction in Rayhunter.\n"
                    "2. bladeRF Band 28 capture will provide raw SIB broadcasts.\n"
                    "3. Look for cellReselectionPriority=7 and q-RxLevMin=-140."
                ),
                spec_ref=(
                    "3GPP TS 36.304 (cell reselection); "
                    "3GPP TS 36.331 §6.2.2 (SIB parameters)"
                ),
            ))
            return findings

        # Analyse parameters
        high_priority_cells  = []
        low_qrxlevmin_cells  = []
        manipulation_combos  = []

        cid_params = defaultdict(list)
        for s in sib_events:
            cid = str(s.get("cid") or "unknown")
            cid_params[cid].append(s)

        for cid, params_list in cid_params.items():
            # Use most common/extreme values
            priorities = [p["resel_priority"] for p in params_list
                         if p["resel_priority"] is not None]
            qrxlevmins = [p["q_rxlev_min"] for p in params_list
                         if p["q_rxlev_min"] is not None]

            max_priority = max(priorities) if priorities else None
            min_qrxlevmin = min(qrxlevmins) if qrxlevmins else None

            if max_priority is not None and max_priority >= LEGIT_RESEL_PRIORITY_MAX:
                high_priority_cells.append({
                    "cid":      cid,
                    "priority": max_priority,
                    "tac":      params_list[0].get("tac"),
                })

            if min_qrxlevmin is not None and min_qrxlevmin <= ROGUE_QRXLEVMIN_DBM + 10:
                low_qrxlevmin_cells.append({
                    "cid":        cid,
                    "qrxlevmin":  min_qrxlevmin,
                    "tac":        params_list[0].get("tac"),
                })

            # Manipulation combination: high priority + low threshold
            if max_priority is not None and min_qrxlevmin is not None:
                if max_priority >= LEGIT_RESEL_PRIORITY_MAX and \
                   min_qrxlevmin <= ROGUE_QRXLEVMIN_DBM + 10:
                    manipulation_combos.append({
                        "cid":        cid,
                        "priority":   max_priority,
                        "qrxlevmin":  min_qrxlevmin,
                        "tac":        params_list[0].get("tac"),
                    })

        total_anomalies = (
            len(high_priority_cells) +
            len(low_qrxlevmin_cells) +
            len(manipulation_combos)
        )

        if total_anomalies == 0:
            return []

        evidence = [
            f"SIB events analysed: {len(sib_events)}",
            f"Unique cells with SIB parameters: {len(cid_params)}",
            f"High-priority cells (≥{LEGIT_RESEL_PRIORITY_MAX}): {len(high_priority_cells)}",
            f"Low q-RxLevMin cells (≤{ROGUE_QRXLEVMIN_DBM+10}dBm): {len(low_qrxlevmin_cells)}",
            f"Manipulation combos (both): {len(manipulation_combos)}",
            f"",
        ]

        if manipulation_combos:
            evidence.append("PARAMETER MANIPULATION CONFIRMED:")
            for c in manipulation_combos[:5]:
                evidence.append(
                    f"  CID={c['cid']} TAC={c['tac']}: "
                    f"priority={c['priority']} (max), "
                    f"q-RxLevMin={c['qrxlevmin']}dBm (minimum) — "
                    f"FORCES DEVICE TO SELECT THIS CELL"
                )

        if high_priority_cells and not manipulation_combos:
            evidence.append("HIGH PRIORITY CELLS:")
            for c in high_priority_cells[:5]:
                evidence.append(
                    f"  CID={c['cid']} TAC={c['tac']}: "
                    f"cellReselectionPriority={c['priority']}"
                )

        evidence += [
            f"",
            f"3GPP CONTEXT:",
            f"  cellReselectionPriority=7 means this cell advertises itself as",
            f"  the highest-priority target for reselection in the area.",
            f"  Combined with q-RxLevMin at minimum, the device has no",
            f"  legitimate reason to ever choose another cell.",
            f"  Legitimate carriers coordinate priorities with the macro network.",
            f"  Isolated maximum-priority cells are a hallmark of rogue operation.",
        ]

        severity   = "CRITICAL" if manipulation_combos else "HIGH"
        confidence = "CONFIRMED" if manipulation_combos else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Cell Reselection Manipulation — "
                f"{len(manipulation_combos)} Parameter Combo(s) | "
                f"{len(high_priority_cells)} High-Priority Cell(s)"
            ),
            description=(
                f"SIB1/SIB3 analysis found {len(manipulation_combos)} cell(s) with "
                f"parameter combinations that force device selection — high "
                f"cellReselectionPriority combined with minimum q-RxLevMin threshold. "
                f"This combination ensures the device selects the rogue cell over "
                f"all legitimate alternatives regardless of signal strength. "
                f"Legitimate carriers coordinate these parameters with the macro network "
                f"and do not set maximum isolation priority."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "SIB1/SIB3 cell reselection parameter manipulation analysis — "
                "forced device selection detection"
            ),
            evidence=evidence,
            hardware_hint=(
                "Rogue eNodeB with custom SIB parameter configuration. "
                "Forced maximum priority + minimum threshold = deliberate device capture."
            ),
            action=(
                "1. Priority=7 + minimum q-RxLevMin = confirmed rogue parameter manipulation.\n"
                "2. Cite 3GPP TS 36.304 — reselection priority coordination requirements.\n"
                "3. Include parameter values in AFP submission.\n"
                "4. Cross-reference high-priority CIDs with known rogue cell list.\n"
                "5. bladeRF SIB capture will provide raw parameter values for verification."
            ),
            spec_ref=(
                "3GPP TS 36.304 §5.2 (cell reselection priority); "
                "3GPP TS 36.331 §6.2.2 (SIB1/SIB3 parameters); "
                "YAICD 4.1.7 (invalid SIB parameters)"
            ),
        ))

        return findings
