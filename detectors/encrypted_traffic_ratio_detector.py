"""
EncryptedTrafficRatioDetector
=============================
Flags sessions where the proportion of EncryptedNASMessage entries
exceeds a configurable threshold.

Reads from normalised event fields: source_file, timestamp, raw
(skipped_message_reason is inside the 'raw' field as a string).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .base import BaseDetector, make_finding


class EncryptedTrafficRatioDetector(BaseDetector):
    name = "EncryptedTrafficRatioDetector"
    description = (
        "Flags sessions where NAS-layer encryption rate exceeds normal "
        "baselines, indicating possible MitM cipher maintenance."
    )

    MIN_ENTRIES      = 20
    WARN_THRESHOLD   = 0.70
    HIGH_THRESHOLD   = 0.85

    def analyze(self, events: List[Dict]) -> List[Dict]:
        # ── 1. Group by source file (= session) ──────────────────────
        session_totals:    Dict[str, int] = defaultdict(int)
        session_encrypted: Dict[str, int] = defaultdict(int)
        session_ts_first:  Dict[str, str] = {}
        session_ts_last:   Dict[str, str] = {}

        for evt in events:
            sid = str(evt.get("source_file", "") or "unknown")
            ts  = str(evt.get("timestamp", "") or "")

            session_totals[sid] += 1

            # skipped_message_reason lives inside the 'raw' field
            # as a string repr of the original dict
            raw = str(evt.get("raw", "") or "")
            if "EncryptedNASMessage" in raw:
                session_encrypted[sid] += 1

            if ts and (sid not in session_ts_first
                       or ts < session_ts_first[sid]):
                session_ts_first[sid] = ts
            if ts and (sid not in session_ts_last
                       or ts > session_ts_last[sid]):
                session_ts_last[sid] = ts

        # ── 2. Evaluate each session ─────────────────────────────────
        findings: List[Dict] = []

        for sid, total in session_totals.items():
            if total < self.MIN_ENTRIES:
                continue

            enc   = session_encrypted.get(sid, 0)
            if enc == 0:
                continue

            ratio = enc / total

            if ratio < self.WARN_THRESHOLD:
                continue

            if ratio >= self.HIGH_THRESHOLD:
                severity  = "HIGH"
                level_str = "HIGH (≥85%)"
            else:
                severity  = "LOW"
                level_str = "WARN (≥70%)"

            pct     = f"{ratio * 100:.1f}%"
            t_first = session_ts_first.get(sid, "unknown")
            t_last  = session_ts_last.get(sid, "unknown")

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Anomalous NAS Encryption Rate — {sid} "
                    f"({pct} encrypted, {enc}/{total})"
                ),
                description=(
                    f"Session {sid} ({t_first} → {t_last}) shows a "
                    f"{pct} NAS-layer encryption rate ({enc} of {total} "
                    f"messages). Normal LTE attach/auth phases produce "
                    f"cleartext NAS messages; a rate this high suggests "
                    f"a MitM device maintaining an active cipher across "
                    f"the entire session, suppressing rayhunter NAS-layer "
                    f"visibility. Alert level: {level_str}."
                ),
                severity=severity,
                confidence="SUSPECTED",
                technique=(
                    "NAS cipher maintenance — "
                    "MitM active tunnel suppression"
                ),
                evidence=[
                    f"Session:        {sid}",
                    f"Window:         {t_first} → {t_last}",
                    f"Total entries:  {total}",
                    f"Encrypted:      {enc} ({pct})",
                    f"Threshold:      {level_str}",
                ],
                hardware_hint=(
                    "Consistent with Harris StingRay II / HailStorm in "
                    "transparent-proxy MitM mode"
                ),
                action=(
                    "1. Cross-reference timestamps with Identity Request "
                    "and Security Mode Command events.\n"
                    "2. Use SCAT/tshark on corresponding QMDL to extract "
                    "NAS-layer cipher type (EEA0/1/2).\n"
                    "3. If EEA0 confirmed, upgrade to CRITICAL.\n"
                    "4. Include in USB evidence package."
                ),
                spec_ref="3GPP TS 33.401 §8.2, TS 24.301 §5.4.3",
            ))

        return findings
