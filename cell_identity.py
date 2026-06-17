"""
cell_identity.py  —  baseline-aware LTE Cell Identity logic for rayhunter-threat-analyzer
Drop-in replacement for the Novel-CID and CID-rotation detectors.

WHY THIS EXISTS
---------------
An LTE E-UTRAN Cell Identity (ECI) is 28 bits = (eNodeB-ID << 8) | sector_id.
The previous detectors treated numerically-adjacent ECIs as a rogue platform
"cycling synthetic identifiers". But adjacent ECIs that share the high 20 bits
are simply DIFFERENT SECTORS OF THE SAME PHYSICAL TOWER. Every macro eNodeB
broadcasts 3-6 sector CIDs differing only in the low byte. Flagging that as
evasion produced false positives on ordinary Telstra/Vodafone/Optus macro sites.

This module makes three corrections, all keyed off the triple-confirmation rule:
  1. Decompose ECI -> eNB-ID + sector. "Rotation" is only suspicious ACROSS
     distinct eNB-IDs, never across sectors of one eNB.
  2. Per-PLMN baseline allowlist. A CID is only "novel" relative to the SAME
     carrier's history. A first-ever Optus CID is not novel evidence when you've
     simply never run an Optus SIM before.
  3. Minimum-observation + minimum-distinct-eNB gates so a handful of SIB1 reads
     from one tower can never reach a positive verdict on their own.
"""

from collections import defaultdict, Counter
from dataclasses import dataclass, field
import json, os


def decompose_eci(cid: int):
    """LTE ECI -> (enb_id, sector_id). 28-bit ECI, low 8 bits = sector."""
    return (cid >> 8), (cid & 0xFF)


@dataclass
class CellBaseline:
    """Per-(PLMN,TAC) record of CIDs this device has legitimately seen before."""
    seen_cids: dict = field(default_factory=lambda: defaultdict(int))  # cid -> count

    def add(self, cid, n=1):
        self.seen_cids[cid] += n

    def known(self, cid):
        return cid in self.seen_cids


class BaselineStore:
    """
    Persisted JSON of {plmn: {tac: {cid: count}}}.
    Call observe() during every clean run; the file becomes the allowlist.
    """
    def __init__(self, path="intelligence/db/cell_baseline.json"):
        self.path = path
        self.data = defaultdict(lambda: defaultdict(CellBaseline))
        if os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            for plmn, tacs in raw.items():
                for tac, cids in tacs.items():
                    cb = self.data[plmn][tac]
                    for cid, cnt in cids.items():
                        cb.add(int(cid), cnt)

    def observe(self, plmn, tac, cid, n=1):
        self.data[str(plmn)][str(tac)].add(int(cid), n)

    def is_known(self, plmn, tac, cid):
        return self.data[str(plmn)][str(tac)].known(int(cid))

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        out = {p: {t: dict(cb.seen_cids) for t, cb in tacs.items()}
               for p, tacs in self.data.items()}
        with open(self.path, "w") as f:
            json.dump(out, f, indent=2)


# ----------------------------------------------------------------------------- 
# Detector 1: Novel CID  (baseline-aware)
# -----------------------------------------------------------------------------
def detect_novel_cid(observations, baseline: BaselineStore,
                     min_obs=2, require_unknown_enb=True):
    """
    observations: list of dicts {plmn, tac, cid, timestamp}
    Returns findings ONLY for CIDs that are:
      - not in the per-PLMN baseline, AND
      - (if require_unknown_enb) whose eNB-ID is also unseen for that PLMN/TAC,
        so a new sector of a known tower does NOT count as novel, AND
      - observed at least min_obs times.
    """
    by_cid = defaultdict(list)
    for o in observations:
        by_cid[(str(o["plmn"]), str(o["tac"]), int(o["cid"]))].append(o)

    # build set of known eNB-IDs per (plmn,tac) from baseline
    known_enbs = defaultdict(set)
    for plmn, tacs in baseline.data.items():
        for tac, cb in tacs.items():
            for cid in cb.seen_cids:
                known_enbs[(plmn, tac)].add(decompose_eci(cid)[0])

    findings = []
    for (plmn, tac, cid), obs in by_cid.items():
        if baseline.is_known(plmn, tac, cid):
            continue
        enb, sector = decompose_eci(cid)
        enb_is_known = enb in known_enbs[(plmn, tac)]
        if require_unknown_enb and enb_is_known:
            # new sector of an already-known tower -> NOT novel
            continue
        if len(obs) < min_obs:
            continue
        findings.append({
            "severity": "INFO",            # never auto-CRITICAL on novelty alone
            "status": "SUSPECTED",
            "cid": cid, "enb_id": enb, "sector": sector,
            "plmn": plmn, "tac": tac,
            "observations": len(obs),
            "note": ("CID not in this carrier's baseline. "
                     "REQUIRES OpenCelliD/ACMA register check before any "
                     "rogue classification. New-carrier first-contact is the "
                     "most common benign cause."),
        })
    return findings


# -----------------------------------------------------------------------------
# Detector 2: CID Rotation  (eNB-aware)
# -----------------------------------------------------------------------------
def detect_cid_rotation(observations, min_distinct_enbs=2, min_transitions=8):
    """
    True CID rotation (evasion) means hopping across DIFFERENT eNodeB-IDs.
    Cycling sectors within ONE eNB-ID is normal macro behaviour and is ignored.

    Returns a finding only when, within a (plmn,tac):
      - >= min_distinct_enbs distinct eNB-IDs are involved, AND
      - >= min_transitions eNB-to-eNB (not sector) transitions occur.
    """
    seq = sorted(observations, key=lambda o: o["timestamp"])
    by_tac = defaultdict(list)
    for o in seq:
        by_tac[(str(o["plmn"]), str(o["tac"]))].append(o)

    findings = []
    for (plmn, tac), obs in by_tac.items():
        enb_seq = [decompose_eci(int(o["cid"]))[0] for o in obs]
        distinct_enbs = sorted(set(enb_seq))
        # count transitions between DIFFERENT eNBs only
        enb_transitions = sum(1 for a, b in zip(enb_seq, enb_seq[1:]) if a != b)
        sector_only = (len(distinct_enbs) == 1)

        if sector_only:
            findings.append({
                "severity": "INFO", "status": "BENIGN",
                "plmn": plmn, "tac": tac,
                "enb_id": distinct_enbs[0],
                "sectors": sorted({decompose_eci(int(o["cid"]))[1] for o in obs}),
                "note": ("Single eNodeB, multiple sectors — normal macro cell. "
                         "NOT rotation. (Previous detector mis-flagged this.)"),
            })
            continue

        if len(distinct_enbs) >= min_distinct_enbs and enb_transitions >= min_transitions:
            findings.append({
                "severity": "MEDIUM", "status": "SUSPECTED",
                "plmn": plmn, "tac": tac,
                "distinct_enbs": distinct_enbs,
                "enb_transitions": enb_transitions,
                "note": ("Genuine multi-eNB cycling within one TAC. Verify each "
                         "eNB-ID against carrier register before classifying."),
            })
    return findings
