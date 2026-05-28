#!/usr/bin/env python3
"""
FlashCatchDetector — Detects FlashCatch sub-second IMSI capture attacks.

Reference: Paci et al. "FlashCatch: Minimizing Disruption in IMSI Catcher
Operations" ACM WiSec 2025, DOI: 10.1145/3734477.3734705

Refactored from extended_detectors.py to use BaseDetector + make_finding().
Place in: detectors/flash_catch.py
"""

from typing import List, Dict
from collections import defaultdict

from .base import BaseDetector, make_finding

FLASH_DURATION_THRESHOLD = 2.0   # seconds — sub-second CID flash
MIN_OBSERVATIONS          = 2
AUTH_REJECT_WINDOW        = 60.0  # seconds around flash


class FlashCatchDetector(BaseDetector):
    """
    Detects FlashCatch-style sub-second IMSI capture.

    Phase 1: Sub-second CID appearance → immediate Identity Request
    Phase 2: Auth Reject → cell barring → UE reattaches to legitimate cell

    Indicators scored:
      +1  sub-2s CID flash duration
      +1  different eNB from home cells
      +1  same frequency band as home cell (frequency displacement)
      +1  Auth Reject within 60s of flash
    Threshold: score >= 2 to fire, >= 3 for CONFIRMED
    """

    name        = "FlashCatchDetector"
    description = "Detects FlashCatch sub-second IMSI capture (Paci et al. WiSec 2025)"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        # Build CID timeline
        cid_obs: Dict[str, List[float]] = defaultdict(list)
        cid_meta: Dict[str, Dict]       = {}

        for ev in events:
            cid = str(ev.get("cid") or ev.get("cell_id") or "")
            if not cid or cid == "0":
                continue
            ts  = self.parse_timestamp(ev)
            if ts <= 0:
                continue
            cid_obs[cid].append(ts)
            if cid not in cid_meta:
                cid_meta[cid] = {
                    "enb":  str(ev.get("enb_id") or ev.get("enb") or ""),
                    "band": str(ev.get("earfcn") or ev.get("band") or ""),
                    "tac":  str(ev.get("tac") or ""),
                }

        if not cid_obs:
            return findings

        # Identify home cells (most observed CIDs)
        obs_counts   = {c: len(v) for c, v in cid_obs.items()}
        sorted_cids  = sorted(obs_counts, key=obs_counts.get, reverse=True)
        home_cids    = sorted_cids[:3]  # top 3 by observation count
        home_enbs    = {cid_meta[c]["enb"] for c in home_cids if cid_meta[c]["enb"]}
        home_bands   = {cid_meta[c]["band"] for c in home_cids if cid_meta[c]["band"]}

        # Auth reject events
        auth_rejects = [
            self.parse_timestamp(e) for e in events
            if "reject" in str(e.get("msg_type", "")).lower()
            and self.parse_timestamp(e) > 0
        ]

        # Check each CID for flash signature
        for cid, timestamps in cid_obs.items():
            if cid in home_cids:
                continue
            timestamps.sort()
            duration = timestamps[-1] - timestamps[0]

            if duration >= FLASH_DURATION_THRESHOLD:
                continue
            if len(timestamps) < MIN_OBSERVATIONS:
                continue

            meta             = cid_meta.get(cid, {})
            enb              = meta.get("enb", "")
            band             = meta.get("band", "")
            is_diff_enb      = bool(enb) and enb not in home_enbs
            is_same_band     = bool(band) and band in home_bands
            flash_time       = timestamps[0]
            nearby_rejects   = [
                t for t in auth_rejects
                if abs(t - flash_time) < AUTH_REJECT_WINDOW
            ]

            score = sum([
                True,                          # flash itself always scores
                is_diff_enb,
                is_same_band,
                bool(nearby_rejects),
            ])

            if score < 2:
                continue

            severity   = "CRITICAL" if score >= 3 else "HIGH"
            confidence = "CONFIRMED" if score >= 3 else "PROBABLE"

            indicators = []
            indicators.append(f"Sub-{FLASH_DURATION_THRESHOLD}s CID flash ({duration:.3f}s)")
            if is_diff_enb:   indicators.append(f"Different eNB ({enb}) from home")
            if is_same_band:  indicators.append(f"Same band {band} as home — frequency displacement")
            if nearby_rejects:indicators.append(f"Auth Reject within 60s ({len(nearby_rejects)} events)")

            findings.append(make_finding(
                detector=self.name,
                title=f"FlashCatch Signature — CID={cid} ({duration:.3f}s flash, score={score}/4)",
                description=(
                    f"CID {cid} appeared for {duration:.3f}s with {len(timestamps)} "
                    f"observations, then vanished. Indicators: {'; '.join(indicators)}. "
                    f"Matches FlashCatch technique (Paci et al., WiSec 2025): "
                    f"Phase 1 sub-second IMSI capture via unrecognised GUTI attach, "
                    f"Phase 2 auth failure causes cell barring forcing reattach to "
                    f"legitimate cell — minimising user disruption."
                ),
                severity=severity,
                confidence=confidence,
                technique="FlashCatch sub-second IMSI capture (Phase 1 + Phase 2)",
                evidence=[
                    f"CID: {cid} | eNB: {enb} | Band: {band}",
                    f"Flash duration: {duration:.4f}s ({len(timestamps)} obs)",
                    f"Score: {score}/4 — {'; '.join(indicators)}",
                    f"Nearby Auth Rejects: {len(nearby_rejects)}",
                ],
                events=[e for e in events if str(e.get("cid","")) == cid][:6],
                action=(
                    f"Verify CID {cid} on OpenCelliD — zero observations confirms rogue. "
                    f"Check RFNSA.com.au for eNB {enb} registration. "
                    "Include in USB evidence package with timestamp documentation."
                ),
                spec_ref="3GPP TS 24.301 §5.4.4, §5.4.3.2; Paci et al. WiSec 2025",
                hardware_hint="Harris HailStorm / StingRay II active IMSI capture",
            ))

        return findings
