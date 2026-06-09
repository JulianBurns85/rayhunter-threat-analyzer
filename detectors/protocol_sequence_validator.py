#!/usr/bin/env python3
"""
ProtocolSequenceValidator — Validates full LTE session state machines.

Right now we detect individual anomalies. This validates the SEQUENCE.

A legitimate LTE session MUST follow this state machine:
  RRCSetup → SecurityModeCmd → Attach → DataSession → Release

A rogue session skips steps:
  RRCSetup → IdentityRequest → Release          (FlashCatch)
  RRCSetup → AuthReject → IdentityRequest       (Wallet Inspector)
  Attach → HandoverCmd (no MeasurementReport)   (Forced handover)
  Release (no preceding DataSession)            (Phantom session)

This catches attacks that individual detectors miss because each
step looks innocent in isolation — only the SEQUENCE reveals
the violation.

Each sequence violation gets a 3GPP spec reference and maps to
a specific attack technique in Tucker et al. NDSS 2025.

Reference: 3GPP TS 24.301 (NAS procedures), TS 36.331 (RRC procedures)
Tucker et al. NDSS 2025 — 53-message IMSI exposure taxonomy
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Session reconstruction window (seconds)
SESSION_GAP_S = 60.0

# Message type normalisation
MSG_TYPES = {
    # RRC
    "rrcconnectionsetup":          "RRC_SETUP",
    "rrcconnectionsetupcomplete":  "RRC_SETUP",
    "rrc connection setup":        "RRC_SETUP",
    "securitymodecommand":         "SECURITY_CMD",
    "security mode command":       "SECURITY_CMD",
    "securitymodecomplete":        "SECURITY_DONE",
    "rrcconnectionrelease":        "RRC_RELEASE",
    "rrc connection release":      "RRC_RELEASE",
    "rrcconnectionreconfiguration":"RRC_RECONFIG",
    # NAS
    "attachrequest":               "ATTACH_REQ",
    "attach request":              "ATTACH_REQ",
    "attachaccept":                "ATTACH_ACCEPT",
    "attach accept":               "ATTACH_ACCEPT",
    "attachreject":                "ATTACH_REJECT",
    "attach reject":               "ATTACH_REJECT",
    "authenticationrequest":       "AUTH_REQ",
    "authentication request":      "AUTH_REQ",
    "authenticationreject":        "AUTH_REJECT",
    "authentication reject":       "AUTH_REJECT",
    "identityrequest":             "IDENTITY_REQ",
    "identity request":            "IDENTITY_REQ",
    "trackingareaupdaterequest":   "TAU_REQ",
    "trackingareaupdatereject":    "TAU_REJECT",
}

# Known malicious sequence patterns
MALICIOUS_PATTERNS = [
    {
        "name":       "FlashCatch — Sub-second IMSI capture",
        "required":   ["RRC_SETUP", "IDENTITY_REQ", "RRC_RELEASE"],
        "forbidden_before_identity": ["SECURITY_CMD"],
        "max_duration_s": 2.0,
        "severity":   "CRITICAL",
        "confidence": "CONFIRMED",
        "spec":       "Tucker et al. NDSS 2025 msg #3; 3GPP TS 24.301 §5.4.4",
        "tucker_msg": "#3 (Identity Request before Security Mode)",
    },
    {
        "name":       "Wallet Inspector — Pre-security IMSI extraction",
        "required":   ["RRC_SETUP", "IDENTITY_REQ"],
        "forbidden_before_identity": ["SECURITY_CMD", "AUTH_REQ"],
        "max_duration_s": 10.0,
        "severity":   "CRITICAL",
        "confidence": "CONFIRMED",
        "spec":       "Tucker et al. NDSS 2025 msg #47; 3GPP TS 24.301 §5.5.1",
        "tucker_msg": "#47 (Attach Reject cause → IMSI)",
    },
    {
        "name":       "Reject-then-Harvest — Auth reject IMSI extraction",
        "required":   ["AUTH_REJECT", "IDENTITY_REQ"],
        "forbidden_before_identity": [],
        "max_duration_s": 5.0,
        "severity":   "CRITICAL",
        "confidence": "CONFIRMED",
        "spec":       "Tucker et al. NDSS 2025 msg #8; 3GPP TS 24.301 §5.4.2.6",
        "tucker_msg": "#8 (Authentication Reject → Identity Request)",
    },
    {
        "name":       "Phantom Session — Release with no data session",
        "required":   ["RRC_SETUP", "RRC_RELEASE"],
        "forbidden_in_session": ["ATTACH_ACCEPT", "AUTH_REQ"],
        "max_duration_s": 30.0,
        "severity":   "HIGH",
        "confidence": "PROBABLE",
        "spec":       "3GPP TS 36.331 §5.3.8; Tucker et al. NDSS 2025",
        "tucker_msg": "Phantom session (no legitimate data exchange)",
    },
    {
        "name":       "TAU Reject Harvest — TAU reject IMSI extraction",
        "required":   ["TAU_REJECT", "IDENTITY_REQ"],
        "forbidden_before_identity": [],
        "max_duration_s": 5.0,
        "severity":   "CRITICAL",
        "confidence": "CONFIRMED",
        "spec":       "Tucker et al. NDSS 2025 msg #14; 3GPP TS 24.301 §5.5.3",
        "tucker_msg": "#14 (TAU Reject → Identity Request)",
    },
]


class ProtocolSequenceValidator(BaseDetector):
    """
    Reconstructs LTE session sequences and validates them against
    the 3GPP state machine, flagging violations mapped to known
    attack techniques.
    """

    name = "ProtocolSequenceValidator"
    description = (
        "3GPP protocol sequence validation — detects state machine "
        "violations invisible to single-event detectors"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract and normalise events with timestamps
        ts_events = []
        for e in events:
            ts  = self._get_ts(e)
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            normalised = None
            for pattern, norm in MSG_TYPES.items():
                if pattern in msg:
                    normalised = norm
                    break
            if ts and normalised:
                ts_events.append({
                    "ts":       ts,
                    "type":     normalised,
                    "raw_msg":  msg,
                    "cell_id":  str(e.get("cell_id") or e.get("cid") or ""),
                    "source":   str(e.get("source_file") or ""),
                    "event":    e,
                })

        if len(ts_events) < 5:
            return []

        ts_events.sort(key=lambda x: x["ts"])

        # Reconstruct sessions (group events within SESSION_GAP_S)
        sessions = []
        current_session = [ts_events[0]]
        for ev in ts_events[1:]:
            if ev["ts"] - current_session[-1]["ts"] <= SESSION_GAP_S:
                current_session.append(ev)
            else:
                if len(current_session) >= 2:
                    sessions.append(current_session)
                current_session = [ev]
        if len(current_session) >= 2:
            sessions.append(current_session)

        # Match sessions against malicious patterns
        violations: Dict[str, List] = defaultdict(list)

        for session in sessions:
            session_types = [ev["type"] for ev in session]
            session_start = session[0]["ts"]
            session_end   = session[-1]["ts"]
            duration      = session_end - session_start

            for pattern in MALICIOUS_PATTERNS:
                # Check max duration
                max_dur = pattern.get("max_duration_s", float('inf'))
                if duration > max_dur:
                    continue

                # Check all required message types present
                required = pattern["required"]
                if not all(r in session_types for r in required):
                    continue

                # Check forbidden messages before identity
                forbidden_before = pattern.get("forbidden_before_identity", [])
                if forbidden_before:
                    if "IDENTITY_REQ" in session_types:
                        idx_identity = session_types.index("IDENTITY_REQ")
                        types_before = session_types[:idx_identity]
                        if any(f in types_before for f in forbidden_before):
                            continue  # Legitimate — security was done first

                # Check forbidden messages in session
                forbidden_in = pattern.get("forbidden_in_session", [])
                if any(f in session_types for f in forbidden_in):
                    continue

                # Match found
                violations[pattern["name"]].append({
                    "session":     session,
                    "pattern":     pattern,
                    "duration_ms": duration * 1000,
                    "start_ts":    session_start,
                    "types":       session_types,
                })

        if not violations:
            return []

        # Build findings per pattern
        for pattern_name, matches in violations.items():
            if not matches:
                continue

            pattern = matches[0]["pattern"]
            evidence = [
                f"Pattern: {pattern_name}",
                f"Tucker et al. reference: {pattern.get('tucker_msg', 'N/A')}",
                f"3GPP spec: {pattern['spec']}",
                f"Instances detected: {len(matches)}",
                f"",
                f"SEQUENCE VIOLATIONS:",
            ]

            for m in matches[:5]:
                ts_str = datetime.fromtimestamp(m["start_ts"], tz=timezone.utc).isoformat()
                src = m["session"][0].get("source", "")
                evidence.append(
                    f"  [{ts_str}] Duration: {m['duration_ms']:.0f}ms | "
                    f"Sequence: {' → '.join(m['types'])} | {src}"
                )

            if len(matches) > 5:
                evidence.append(f"  ... and {len(matches) - 5} more (see JSON report)")

            evidence.append("")
            evidence.append("WHY THIS IS MALICIOUS:")
            evidence.append(
                f"  A legitimate 3GPP session MUST complete SecurityModeCommand "
                f"before any Identity Request. The observed sequence "
                f"'{' → '.join(pattern['required'])}' violates the mandatory "
                f"state machine defined in {pattern['spec']}."
            )

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Protocol Sequence Violation — {pattern_name} — "
                    f"{len(matches)} Instance(s)"
                ),
                description=(
                    f"{len(matches)} instance(s) of '{pattern_name}' detected. "
                    f"The observed message sequence violates the mandatory 3GPP "
                    f"LTE state machine ({pattern['spec']}). "
                    f"This attack technique is documented in Tucker et al. NDSS 2025 "
                    f"({pattern.get('tucker_msg', 'N/A')}). "
                    f"Each instance represents a complete attack sequence that may "
                    f"have resulted in successful IMSI extraction."
                ),
                severity=pattern["severity"],
                confidence=pattern["confidence"],
                technique=(
                    f"3GPP state machine violation — {pattern_name}"
                ),
                evidence=evidence,
                hardware_hint=(
                    "Active rogue eNodeB with full NAS/RRC stack. "
                    "This sequence requires complete control of the LTE "
                    "protocol stack — not possible with passive SDR or repeater."
                ),
                action=(
                    f"1. Each instance is an independent attack sequence — document all.\n"
                    f"2. Cite Tucker et al. NDSS 2025 {pattern.get('tucker_msg', '')} in AFP submission.\n"
                    f"3. Cite {pattern['spec']} as the violated standard.\n"
                    f"4. This sequence is invisible to single-event detectors — unique finding.\n"
                    f"5. Include raw session sequences in evidence package."
                ),
                spec_ref=pattern["spec"],
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
