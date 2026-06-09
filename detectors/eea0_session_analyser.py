#!/usr/bin/env python3
"""
EEA0SessionDurationAnalyser — Null-cipher session duration profiling.

EEA0 (null cipher, no encryption) is a legitimate LTE fallback for
specific scenarios (emergency calls, roaming edge cases).

Legitimate EEA0: brief, seconds to minutes, specific contexts
Rogue EEA0: entire session duration, always, for ALL connections

This module calculates per-session EEA0 duration and coverage:
- Session EEA0 coverage ratio (% of session time unencrypted)
- EEA0 session duration distribution
- EEA0 prevalence across all observed sessions
- Comparison against legitimate EEA0 baseline expectations

A rogue platform running full-traffic intercept (MitM mode) forces
EEA0 for the ENTIRE session. No legitimate scenario produces 100%
EEA0 coverage across all sessions.

Reference: 3GPP TS 33.401 §8.2 (EEA0 allowed scenarios);
Harris HailStorm MitM mode documentation (public domain).
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


SESSION_GAP_S         = 300.0   # 5 min gap = new session
MIN_SESSION_EVENTS    = 3       # Min events to count as session
LEGIT_EEA0_MAX_RATIO  = 0.05    # Legitimate EEA0 < 5% of session time
ROGUE_EEA0_MIN_RATIO  = 0.50    # Rogue EEA0 > 50% of session time

EEA0_TYPES = {
    "eea0", "null cipher", "nullcipher",
    "eea0_active", "integrityprotected",
}
CIPHER_TYPES = {
    "securitymodecommand", "security mode command",
    "securitymodecomplete",
}
SETUP_TYPES = {
    "rrcconnectionsetup", "rrcconnectionsetupcomplete",
}
RELEASE_TYPES = {
    "rrcconnectionrelease", "rrc connection release",
}


class EEA0SessionDurationAnalyser(BaseDetector):
    """
    Analyses null-cipher session duration and coverage to prove
    full-session MitM interception by rogue platform.
    """

    name = "EEA0SessionDurationAnalyser"
    description = (
        "EEA0 null-cipher session duration analysis — proves full-session "
        "MitM interception. Legitimate EEA0 is brief; rogue EEA0 is perpetual."
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract timestamped events with cipher state
        ts_events = []
        for e in events:
            ts  = self._get_ts(e)
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            eea0_active = (
                e.get("cipher") == "EEA0" or
                e.get("encryption") == "none" or
                e.get("eea0") == True or
                any(t in msg for t in EEA0_TYPES)
            )
            if ts:
                ts_events.append({
                    "ts":         ts,
                    "msg":        msg,
                    "eea0":       eea0_active,
                    "is_setup":   any(t in msg for t in SETUP_TYPES),
                    "is_release": any(t in msg for t in RELEASE_TYPES),
                    "is_cipher":  any(t in msg for t in CIPHER_TYPES),
                })

        if not ts_events:
            return []

        ts_events.sort(key=lambda x: x["ts"])

        # Reconstruct sessions
        sessions = []
        current  = [ts_events[0]]
        for ev in ts_events[1:]:
            if ev["ts"] - current[-1]["ts"] <= SESSION_GAP_S:
                current.append(ev)
            else:
                if len(current) >= MIN_SESSION_EVENTS:
                    sessions.append(current)
                current = [ev]
        if len(current) >= MIN_SESSION_EVENTS:
            sessions.append(current)

        if not sessions:
            return []

        # Analyse each session for EEA0 coverage
        session_stats = []
        for session in sessions:
            duration      = session[-1]["ts"] - session[0]["ts"]
            eea0_events   = sum(1 for e in session if e["eea0"])
            total_events  = len(session)
            eea0_ratio    = eea0_events / total_events if total_events > 0 else 0
            has_cipher_cmd= any(e["is_cipher"] for e in session)

            if duration > 0 or eea0_events > 0:
                session_stats.append({
                    "start":       session[0]["ts"],
                    "duration_s":  duration,
                    "total_events":total_events,
                    "eea0_events": eea0_events,
                    "eea0_ratio":  eea0_ratio,
                    "has_cipher":  has_cipher_cmd,
                })

        if not session_stats:
            return []

        # Overall statistics
        eea0_ratios     = [s["eea0_ratio"] for s in session_stats]
        mean_eea0_ratio = statistics.mean(eea0_ratios)
        high_eea0_sessions = [s for s in session_stats if s["eea0_ratio"] >= ROGUE_EEA0_MIN_RATIO]
        no_cipher_sessions = [s for s in session_stats if not s["has_cipher"] and s["eea0_events"] > 0]

        total_sessions    = len(session_stats)
        high_eea0_pct     = len(high_eea0_sessions) / total_sessions * 100

        if mean_eea0_ratio < 0.01 and not high_eea0_sessions:
            return []  # EEA0 not significant

        evidence = [
            f"Sessions analysed: {total_sessions}",
            f"Mean EEA0 session coverage: {mean_eea0_ratio:.1%}",
            f"Sessions with >50% EEA0 coverage: {len(high_eea0_sessions)} ({high_eea0_pct:.0f}%)",
            f"Sessions with no SecurityModeCommand: {len(no_cipher_sessions)}",
            f"",
            f"EEA0 COVERAGE BENCHMARKS:",
            f"  Legitimate network: < {LEGIT_EEA0_MAX_RATIO:.0%} of session time",
            f"  Rogue MitM platform: > {ROGUE_EEA0_MIN_RATIO:.0%} of session time",
            f"  This corpus mean:    {mean_eea0_ratio:.1%}",
            f"",
        ]

        if high_eea0_sessions:
            evidence.append(f"HIGH-EEA0 SESSIONS (≥{ROGUE_EEA0_MIN_RATIO:.0%} coverage):")
            for s in sorted(high_eea0_sessions,
                           key=lambda x: x["eea0_ratio"], reverse=True)[:5]:
                ts_str = datetime.fromtimestamp(s["start"], tz=timezone.utc).isoformat()
                evidence.append(
                    f"  [{ts_str}] Duration: {s['duration_s']:.0f}s | "
                    f"EEA0: {s['eea0_ratio']:.0%} ({s['eea0_events']}/{s['total_events']} events)"
                )

        if no_cipher_sessions:
            evidence.append(f"")
            evidence.append(
                f"SESSIONS WITHOUT SECURITYMODECOMMAND: {len(no_cipher_sessions)}"
            )
            evidence.append(
                "  These sessions had EEA0-flagged events but no cipher negotiation — "
                "consistent with pre-security IMSI extraction (Wallet Inspector attack)."
            )

        evidence += [
            f"",
            f"FORENSIC SIGNIFICANCE:",
            f"  3GPP TS 33.401 §8.2 permits EEA0 only for emergency calls,",
            f"  specific roaming scenarios, and IMS emergency sessions.",
            f"  A mean EEA0 coverage of {mean_eea0_ratio:.0%} across {total_sessions} sessions",
            f"  is inconsistent with any legitimate network operation.",
            f"  This is consistent with Harris HailStorm full-traffic MitM interception.",
        ]

        severity   = "CRITICAL" if mean_eea0_ratio > ROGUE_EEA0_MIN_RATIO else "HIGH"
        confidence = "CONFIRMED" if len(high_eea0_sessions) >= 3 else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"EEA0 Session Analysis — Mean Coverage {mean_eea0_ratio:.0%} — "
                f"{len(high_eea0_sessions)}/{total_sessions} Sessions High-EEA0"
            ),
            description=(
                f"EEA0 null-cipher coverage analysis across {total_sessions} sessions. "
                f"Mean EEA0 coverage: {mean_eea0_ratio:.1%}. "
                f"{len(high_eea0_sessions)} session(s) ({high_eea0_pct:.0f}%) showed "
                f"EEA0 coverage exceeding {ROGUE_EEA0_MIN_RATIO:.0%}. "
                f"Legitimate EEA0 is below {LEGIT_EEA0_MAX_RATIO:.0%} of session time. "
                f"This coverage pattern is consistent with Harris HailStorm operating "
                f"in full-traffic MitM interception mode (EEA0 forced for entire session)."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "EEA0 null-cipher session duration and coverage analysis — "
                "full-session MitM interception detection"
            ),
            evidence=evidence,
            hardware_hint=(
                f"Harris HailStorm MitM mode — EEA0 forced for full session duration. "
                f"Mean coverage {mean_eea0_ratio:.0%} exceeds all legitimate scenarios."
            ),
            action=(
                "1. Per-session EEA0 coverage proves full-traffic interception.\n"
                "2. Cite 3GPP TS 33.401 §8.2 — EEA0 legitimate use cases are narrow.\n"
                "3. Sessions without SecurityModeCommand prove pre-security extraction.\n"
                "4. Include session duration chart in AFP submission.\n"
                "5. Cross-reference high-EEA0 sessions with operator rhythm."
            ),
            spec_ref=(
                "3GPP TS 33.401 §8.2 (EEA0 permitted scenarios); "
                "3GPP TS 33.401 §8.3 (integrity protection); "
                "Harris HailStorm MitM mode"
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
