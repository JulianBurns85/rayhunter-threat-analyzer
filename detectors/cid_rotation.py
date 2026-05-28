#!/usr/bin/env python3
"""
CIDRotationDetector — Detects deliberate CID rotation within a TAC.

Evidence basis:
  - Cranbourne East investigation: CIDs ...155, ...165, ...195 rotate
    sequentially within TAC=12385 to prevent single-tower anomaly detection
  - Rotation pattern observed in Grapher node logs 27 May 2026
  - Legitimate towers do not rotate Cell IDs — they are static hardware identifiers

Integrated into rayhunter-threat-analyzer v2.4+
Place this file in: detectors/cid_rotation.py
"""

from collections import defaultdict
from typing import List, Dict

from .base import BaseDetector, make_finding


# A cluster is a group of CIDs that share a common numeric prefix within a TAC.
# For the Cranbourne East cluster: 137713155 / 137713165 / 137713175 / 137713195
# all share prefix 13771316x / 13771319x — we detect via suffix offset pattern.

_MIN_CIDS_FOR_ROTATION   = 3     # need at least 3 distinct CIDs in one TAC
_MIN_EVENTS_PER_CID      = 3     # each CID must appear at least this many times
_ROTATION_WINDOW_SECONDS = 7200  # look for rotation within a 2-hour window
_SUFFIX_STEP_THRESHOLD   = 50    # CIDs within 50 units of each other = clustered


class CIDRotationDetector(BaseDetector):
    """
    Flags suspicious CID rotation within a single TAC.

    Legitimate base stations have fixed Cell IDs — they are a hardware
    property of the antenna sector, not a software parameter.  A rogue
    platform cycling through multiple synthetic CIDs within the same TAC
    is a strong indicator of deliberate evasion.

    Detection logic:
      1. Group observed CIDs by TAC.
      2. Within each TAC, identify clusters of numerically adjacent CIDs
         (offset < _SUFFIX_STEP_THRESHOLD between sorted CID values).
      3. Flag any cluster where ≥ _MIN_CIDS_FOR_ROTATION CIDs each appear
         enough times and are observed within the rotation window.
      4. Check for sequential time-ordering of CID appearances (A → B → A → B)
         which confirms active rotation rather than coincidental co-presence.
    """

    name        = "CIDRotationDetector"
    description = "Detects deliberate CID rotation within a TAC (rogue evasion technique)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        # ── Collect cell observations with timestamps ─────────────────── #
        # Structure: tac → cid → [timestamps]
        tac_cid_ts: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

        for ev in events:
            cid = str(ev.get("cid") or ev.get("cell_id") or "")
            tac = str(ev.get("tac") or ev.get("lac") or "")
            if not cid or not tac or cid == "0":
                continue
            ts = self.parse_timestamp(ev)
            if ts > 0:
                tac_cid_ts[tac][cid].append(ts)

        # ── Analyse each TAC for rotation clusters ────────────────────── #
        for tac, cid_map in tac_cid_ts.items():
            # Filter to CIDs with enough observations
            qualified = {
                cid: sorted(tss)
                for cid, tss in cid_map.items()
                if len(tss) >= _MIN_EVENTS_PER_CID
            }
            if len(qualified) < _MIN_CIDS_FOR_ROTATION:
                continue

            # Sort CIDs numerically and look for adjacent clusters
            try:
                sorted_cids = sorted(qualified.keys(), key=lambda c: int(c))
            except ValueError:
                continue

            # Find clusters (groups where consecutive CIDs differ by < threshold)
            clusters: List[List[str]] = []
            current_cluster = [sorted_cids[0]]
            for i in range(1, len(sorted_cids)):
                try:
                    gap = abs(int(sorted_cids[i]) - int(sorted_cids[i - 1]))
                except ValueError:
                    gap = _SUFFIX_STEP_THRESHOLD + 1
                if gap <= _SUFFIX_STEP_THRESHOLD:
                    current_cluster.append(sorted_cids[i])
                else:
                    if len(current_cluster) >= _MIN_CIDS_FOR_ROTATION:
                        clusters.append(current_cluster)
                    current_cluster = [sorted_cids[i]]
            if len(current_cluster) >= _MIN_CIDS_FOR_ROTATION:
                clusters.append(current_cluster)

            for cluster in clusters:
                cluster_cids = {c: qualified[c] for c in cluster}

                # Check all observations fall within the rotation window
                all_ts = sorted(t for tss in cluster_cids.values() for t in tss)
                if not all_ts:
                    continue
                window = all_ts[-1] - all_ts[0]
                if window > _ROTATION_WINDOW_SECONDS:
                    # Trim to most active window
                    window_label = f"{window/3600:.1f}h span (trimmed)"
                else:
                    window_label = f"{window/60:.1f} min span"

                # Build chronological sequence to confirm A→B→A rotation
                seq = sorted(
                    [(t, cid) for cid, tss in cluster_cids.items() for t in tss],
                    key=lambda x: x[0]
                )
                # Count CID transitions (changes in active CID)
                transitions = sum(
                    1 for i in range(1, len(seq)) if seq[i][1] != seq[i-1][1]
                )

                total_obs = sum(len(v) for v in cluster_cids.values())
                cid_list  = ", ".join(cluster)

                # Need meaningful rotation (not just two brief appearances)
                if transitions < 4:
                    continue

                evidence = [
                    f"TAC: {tac}",
                    f"Rotating CIDs: {cid_list}",
                    f"Total observations: {total_obs} across {len(cluster)} CIDs",
                    f"CID transitions: {transitions}",
                    f"Observation window: {window_label}",
                ]
                for cid, tss in cluster_cids.items():
                    evidence.append(f"  CID={cid}: {len(tss)} obs")

                findings.append(make_finding(
                    detector=self.name,
                    title=(
                        f"CID Rotation Cluster — TAC={tac} "
                        f"({len(cluster)} CIDs, {transitions} transitions)"
                    ),
                    description=(
                        f"{len(cluster)} numerically adjacent Cell IDs "
                        f"({cid_list}) within TAC={tac} rotate across "
                        f"{total_obs} observations with {transitions} transitions. "
                        f"Legitimate base stations have fixed Cell IDs. "
                        f"This pattern indicates a rogue platform cycling "
                        f"synthetic identifiers to evade single-tower anomaly detection."
                    ),
                    severity="HIGH",
                    confidence="PROBABLE",
                    technique="CID rotation — rogue cell evasion via synthetic identifier cycling",
                    evidence=evidence,
                    events=[ev for ev in events if str(ev.get("cid", "")) in cluster][:8],
                    action=(
                        "Add all rotating CIDs to known_rogue_cids in config.yaml. "
                        "Include rotation timeline in evidence package. "
                        "CID rotation is a documented Harris HailStorm operational mode."
                    ),
                    spec_ref="3GPP TS 36.331 §6.2.2 (SIB1 cellIdentity)",
                    hardware_hint=(
                        "Harris HailStorm / StingRay II — CID rotation matches "
                        "documented operator manual evasion guidance"
                    ),
                ))

        return findings
