#!/usr/bin/env python3
"""
CIDRotationDetector — detects deliberate CID rotation within a TAC.

v2.5 INTEGRITY CORRECTION (12 Jun 2026)
=======================================
The previous version flagged numerically-adjacent CIDs as "synthetic rotation".
But in LTE the 28-bit E-UTRAN Cell Identity is structured:
        ECI = (eNodeB_ID * 256) + sector_ID
so the sectors of a single physical macro have ECIs that differ by small
amounts and ARE numerically adjacent BY DESIGN. The Cranbourne East "cluster"
137713155/165/175/195 decodes to ONE eNB (537942), sectors 3/13/23/43 — a
normal 3-4 sector macro, NOT a rogue rotating identifiers. main.py already had
to RECONCILE this away post-hoc; this fixes it at the detector.

Correction:
  * Compute eNB_ID = int(cid) // 256 for every CID in a candidate cluster.
  * If all CIDs share one eNB_ID  -> normal macro sectors -> NOT rotation
    (emit an INFO note at most, never HIGH/PROBABLE).
  * Genuine rotation requires multiple DISTINCT eNB_IDs being cycled, AND
    even then it is only a SUSPECTED lead requiring behavioural corroboration
    (redirect / EEA0 / pre-security IMSI) before it can rise above INFO.

Reference: 3GPP TS 36.331 §6.2.2 (SIB1 cellIdentity); TS 36.300 (ECI structure).
"""

from collections import defaultdict
from typing import List, Dict

from .base import BaseDetector, make_finding


_MIN_CIDS_FOR_ROTATION   = 3
_MIN_EVENTS_PER_CID      = 3
_ROTATION_WINDOW_SECONDS = 7200
_SUFFIX_STEP_THRESHOLD   = 50
_MIN_TRANSITIONS         = 4


def _enb_id(cid: str) -> int:
    """E-UTRAN Cell Identity -> eNodeB ID (top 20 bits)."""
    return int(cid) // 256


def _sector(cid: str) -> int:
    return int(cid) % 256


class CIDRotationDetector(BaseDetector):

    name        = "CIDRotationDetector"
    description = "Detects CID rotation within a TAC (same-eNB sectors excluded as normal)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        tac_cid_ts: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        for ev in events:
            cid = str(ev.get("cid") or ev.get("cell_id") or "")
            tac = str(ev.get("tac") or ev.get("lac") or "")
            if not cid or not tac or cid == "0":
                continue
            ts = self.parse_timestamp(ev)
            if ts > 0:
                tac_cid_ts[tac][cid].append(ts)

        for tac, cid_map in tac_cid_ts.items():
            qualified = {
                cid: sorted(tss) for cid, tss in cid_map.items()
                if len(tss) >= _MIN_EVENTS_PER_CID
            }
            if len(qualified) < _MIN_CIDS_FOR_ROTATION:
                continue

            try:
                sorted_cids = sorted(qualified.keys(), key=lambda c: int(c))
            except ValueError:
                continue

            # adjacency clusters
            clusters: List[List[str]] = []
            current = [sorted_cids[0]]
            for i in range(1, len(sorted_cids)):
                try:
                    gap = abs(int(sorted_cids[i]) - int(sorted_cids[i - 1]))
                except ValueError:
                    gap = _SUFFIX_STEP_THRESHOLD + 1
                if gap <= _SUFFIX_STEP_THRESHOLD:
                    current.append(sorted_cids[i])
                else:
                    if len(current) >= _MIN_CIDS_FOR_ROTATION:
                        clusters.append(current)
                    current = [sorted_cids[i]]
            if len(current) >= _MIN_CIDS_FOR_ROTATION:
                clusters.append(current)

            for cluster in clusters:
                cluster_cids = {c: qualified[c] for c in cluster}

                # ── CORE FIX: same-eNB check ──────────────────────────
                try:
                    enbs = {_enb_id(c) for c in cluster}
                except ValueError:
                    continue

                seq = sorted(
                    [(t, cid) for cid, tss in cluster_cids.items() for t in tss],
                    key=lambda x: x[0]
                )
                transitions = sum(1 for i in range(1, len(seq)) if seq[i][1] != seq[i-1][1])
                total_obs = sum(len(v) for v in cluster_cids.values())

                if len(enbs) == 1:
                    # Normal multi-sector macro — explicitly NOT rotation.
                    enb = next(iter(enbs))
                    sectors = sorted({_sector(c) for c in cluster})
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"Multi-sector macro (NOT rotation) — TAC={tac} eNB={enb}",
                        description=(
                            f"{len(cluster)} adjacent CIDs ({', '.join(cluster)}) within "
                            f"TAC={tac} all belong to ONE eNodeB (ID {enb}), sectors "
                            f"{sectors}. Per the E-UTRAN Cell Identity structure "
                            f"(ECI = eNB*256 + sector), these are the sectors of a single "
                            f"physical macro cell — normal infrastructure, not synthetic "
                            f"identifier rotation."
                        ),
                        severity="INFO",
                        confidence="CONFIRMED",
                        technique="ECI decomposition — same-eNB sector identification",
                        evidence=[
                            f"TAC: {tac}",
                            f"eNodeB ID: {enb}",
                            f"Sectors: {sectors}",
                            f"CIDs: {', '.join(cluster)}",
                            f"Total observations: {total_obs}",
                            "Verdict: normal multi-sector macro — excluded from rotation scoring.",
                        ],
                        action=(
                            "No action. This is a legitimate multi-sector cell. Do NOT add "
                            "to known_rogue_cids and do NOT cite as rotation/evasion."
                        ),
                        spec_ref="3GPP TS 36.300 (ECI structure); TS 36.331 §6.2.2",
                        hardware_hint="Standard multi-sector eNodeB.",
                    ))
                    continue

                # ── Multiple eNBs: a real rotation *candidate*, INFO-only ──
                if transitions < _MIN_TRANSITIONS:
                    continue

                window = seq[-1][0] - seq[0][0]
                window_label = (f"{window/3600:.1f}h span" if window > _ROTATION_WINDOW_SECONDS
                                else f"{window/60:.1f} min span")
                evidence = [
                    f"TAC: {tac}",
                    f"Distinct eNodeBs in cluster: {sorted(enbs)}",
                    f"CIDs: {', '.join(cluster)}",
                    f"Total observations: {total_obs}",
                    f"CID transitions: {transitions}",
                    f"Observation window: {window_label}",
                    "",
                    "NOTE: multiple distinct eNBs cycled. This is a LEAD ONLY. It is not "
                    "confirmed rogue unless one of these CIDs independently exhibits attack "
                    "behaviour (redirectedCarrierInfo, EEA0 selection, or pre-security IMSI).",
                ]
                findings.append(make_finding(
                    detector=self.name,
                    title=f"CID Rotation Candidate (multi-eNB, UNCONFIRMED) — TAC={tac}",
                    description=(
                        f"{len(cluster)} CIDs across {len(enbs)} distinct eNodeBs within "
                        f"TAC={tac} alternate over {total_obs} observations "
                        f"({transitions} transitions). Multi-eNB cycling can occur from "
                        f"normal mobility between neighbouring cells; treat as a lead "
                        f"requiring behavioural corroboration, not a confirmed attack."
                    ),
                    severity="INFO",
                    confidence="SUSPECTED",
                    technique="Multi-eNB CID alternation (unconfirmed lead)",
                    evidence=evidence,
                    events=[ev for ev in events if str(ev.get("cid", "")) in cluster][:8],
                    action=(
                        "1. Check each CID for independent attack behaviour in the decode.\n"
                        "2. Only escalate above INFO if behaviour corroborates.\n"
                        "3. Do NOT auto-add to known_rogue_cids."
                    ),
                    spec_ref="3GPP TS 36.331 §6.2.2 (SIB1 cellIdentity)",
                    hardware_hint="Inconclusive — could be normal neighbour mobility.",
                ))

        return findings
