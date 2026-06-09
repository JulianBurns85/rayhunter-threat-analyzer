"""
NovelCidDetector
================
Flags Cell IDs that:
  1. Have never been seen in prior sessions loaded into the run, AND
  2. Appear ≤3 times total, AND
  3. Disappear within 10 seconds of first appearance

Matches the signature of post-ACMA-visit zero-observation CIDs
(8666381, 8666391, 8666411) and CID 135836191 on 2026-05-20.

Reads from normalised event fields: cell_id, tac, plmn, timestamp, source_file
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List

from .base import BaseDetector, make_finding


# CIDs confirmed across prior sessions — keep in sync with config.yaml
_KNOWN_CIDS: set = {
    # Vodafone AU TAC=30336
    "8409357", "8409367", "8409387", "8409397",
    # Telstra TAC=12385
    "137713155", "137713165", "137713175", "137713195",
    # Post-ACMA zero-observation CIDs (confirmed rogue)
    "8666381", "8666391", "8666411",
}


def _parse_ts(ts_str) -> float:
    if not ts_str or str(ts_str) == "None":
        return 0.0
    ts_str = str(ts_str).rstrip("Z")
    try:
        dt = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


class NovelCidDetector(BaseDetector):
    name = "NovelCidDetector"
    description = (
        "Detects Cell IDs that are new (not previously observed), "
        "appear ≤3 times, and disappear within 10 seconds."
    )

    MAX_OBS_FOR_NOVEL = 3
    MAX_WINDOW_SECS   = 10.0

    def analyze(self, events: List[Dict]) -> List[Dict]:
        # ── 1. Load known CIDs from config + hardcoded set ────────────
        cfg_known = set()
        for entry in self.cfg.get("known_rogue_cells", []):
            cid_val = str(entry.get("cid", "")) if isinstance(entry, dict) else str(entry)
            if cid_val:
                cfg_known.add(cid_val)
        all_known = _KNOWN_CIDS | cfg_known

        # ── 2. Collect CID observations from normalised events ────────
        # cid_obs: cid_str → [(epoch, source_file, tac, plmn)]
        cid_obs: Dict[str, list] = defaultdict(list)

        for evt in events:
            cid = str(evt.get("cell_id", "") or "")
            if not cid or cid == "None":
                continue

            epoch = _parse_ts(evt.get("timestamp"))
            if epoch == 0.0:
                continue

            source = str(evt.get("source_file", "unknown"))
            tac    = str(evt.get("tac", "") or "")
            plmn   = str(evt.get("plmn", "") or "")

            cid_obs[cid].append((epoch, source, tac, plmn))

        # ── 3. Evaluate each CID ─────────────────────────────────────
        findings: List[Dict] = []

        for cid, obs in cid_obs.items():
            if cid in all_known:
                continue

            obs_sorted = sorted(obs, key=lambda x: x[0])
            n = len(obs_sorted)
            first_epoch = obs_sorted[0][0]
            last_epoch  = obs_sorted[-1][0]
            window_secs = last_epoch - first_epoch

            if n > self.MAX_OBS_FOR_NOVEL:
                continue
            if window_secs > self.MAX_WINDOW_SECS:
                continue

            # Build evidence
            evidence = []
            for epoch, src, tac, plmn in obs_sorted:
                dt_str = datetime.fromtimestamp(
                    epoch, tz=timezone.utc
                ).isoformat()
                evidence.append(
                    f"[{dt_str}] CID={cid} TAC={tac} PLMN={plmn} ({src})"
                )

            tac_val  = obs_sorted[0][2] or "unknown"
            plmn_val = obs_sorted[0][3] or "unknown"
            window_str = f"{window_secs:.3f}s"
            mnc_guess  = "01" if tac_val == "12385" else "03"

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Novel Cell ID — CID={cid} "
                    f"({n} obs, {window_str} window)"
                ),
                description=(
                    f"CID {cid} (TAC={tac_val}, PLMN={plmn_val}) has "
                    f"never been observed in prior sessions. It appeared "
                    f"{n} time(s) within a {window_str} window then "
                    f"vanished. This transient signature matches confirmed "
                    f"zero-observation rogue CIDs (8666381, 8666391, "
                    f"8666411) from the post-ACMA-visit dataset. "
                    f"Recommend OpenCelliD lookup and addition to "
                    f"known_rogue_cells if unregistered."
                ),
                severity="HIGH",
                confidence="PROBABLE",
                technique=(
                    "Transient CID sweep — rogue cell brief activation"
                ),
                evidence=evidence,
                hardware_hint=(
                    "Unknown — consistent with Harris HailStorm / "
                    "srsRAN sweep mode"
                ),
                action=(
                    f"1. Run OpenCelliD lookup: https://opencellid.org/"
                    f"cell/get?mcc=505&mnc={mnc_guess}&lac={tac_val}"
                    f"&cellid={cid}&format=json\n"
                    f"2. If zero global observations, add CID={cid} "
                    f"to known_rogue_cells in config.yaml.\n"
                    f"3. Document in evidence log with timestamps.\n"
                    f"4. Include in USB evidence package."
                ),
                spec_ref="3GPP TS 36.331 §6.2.2 (SIB1 cellIdentity)",
            ))

        return findings
