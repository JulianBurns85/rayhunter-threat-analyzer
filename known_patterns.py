#!/usr/bin/env python3
"""
Known Attack Pattern Signatures
================================
Reference database of known IMSI catcher / rogue tower attack sequences.
Used for pattern-matching across correlated event chains.

Each signature defines:
  - A sequence of event types (in order)
  - Timing constraints between steps
  - Confidence and severity if matched
"""

from typing import List, Dict, Optional


ATTACK_SIGNATURES = [
    {
        "id": "IMSI_CATCHER_CLASSIC",
        "name": "Classic IMSI Catcher Cycle",
        "description": (
            "The canonical IMSI catcher attack sequence: device connects to "
            "rogue cell, attacker requests IMSI in plaintext, negotiates null "
            "cipher to intercept traffic."
        ),
        "sequence": [
            {"type": "Identity Request", "identity_type": "IMSI"},
            {"type": "Security Mode Command", "cipher_alg": "EEA0"},
        ],
        "max_gap_seconds": 30,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 24.301 §5.4.4, §5.4.3",
        "hardware_hint": "Active IMSI catcher (StingRay/Cobham/Septier or SDR-based)",
    },
    {
        "id": "AUTH_REJECT_IMSI_EXTRACT",
        "name": "Authentication Reject → IMSI Extraction",
        "description": (
            "Rogue device rejects authentication to force device to reveal "
            "IMSI in plaintext Identity Response."
        ),
        "sequence": [
            {"type": "Authentication Reject"},
            {"type": "Identity Request", "identity_type": "IMSI"},
            {"type": "Identity Response"},
        ],
        "max_gap_seconds": 15,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 24.301 §5.4.3.2",
        "hardware_hint": "Active IMSI catcher with authentication bypass",
    },
    {
        "id": "LTE_TO_2G_DOWNGRADE",
        "name": "LTE → 2G Forced Downgrade Chain",
        "description": (
            "Rogue LTE cell forces 2G redirect, then GSM interceptor captures "
            "traffic using A5/0 (no cipher) or weak A5/1."
        ),
        "sequence": [
            {"type": "RRC Connection Release", "has_geran_redirect": True},
            {"type": "GSM RR Signaling"},
        ],
        "max_gap_seconds": 60,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 36.331 §5.3.12",
        "hardware_hint": "Dual-layer attack: LTE rogue eNodeB + GSM IMSI catcher",
    },
    {
        "id": "IMSI_PAGE_CONFIRM",
        "name": "IMSI Harvest → Location Confirmation Paging",
        "description": (
            "After harvesting IMSI, attacker sends IMSI-targeted page to "
            "confirm device is still in range (location tracking)."
        ),
        "sequence": [
            {"type": "Identity Request", "identity_type": "IMSI"},
            {"type": "Paging", "paging_type": "IMSI"},
        ],
        "max_gap_seconds": 120,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 24.301 §5.6.2",
        "hardware_hint": "IMSI catcher in persistent location-tracking mode",
    },
    {
        "id": "INJECTED_HANDOVER_NULL_CIPHER",
        "name": "Injected Handover → Null Cipher Setup",
        "description": (
            "Rogue eNodeB forces handover to attacker-controlled cell, "
            "then negotiates null cipher for full traffic interception."
        ),
        "sequence": [
            {"has_mobility_control": True},
            {"type": "Security Mode Command", "cipher_alg": "EEA0"},
        ],
        "max_gap_seconds": 20,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 36.331 §5.3.5, TS 33.401 §8.3",
        "hardware_hint": "Advanced rogue eNodeB with handover injection capability",
    },
    {
        "id": "FULL_INTERCEPTION_CHAIN",
        "name": "Complete Interception Chain",
        "description": (
            "Full multi-stage attack: IMSI harvest → forced handover → "
            "null cipher → traffic interception. The most complete attack chain."
        ),
        "sequence": [
            {"type": "Identity Request", "identity_type": "IMSI"},
            {"has_mobility_control": True},
            {"type": "Security Mode Command", "cipher_alg": "EEA0"},
        ],
        "max_gap_seconds": 60,
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "spec_ref": "3GPP TS 33.401, TS 36.331",
        "hardware_hint": (
            "Sophisticated rogue eNodeB infrastructure. "
            "Likely commercial-grade IMSI catcher (StingRay-class or better)."
        ),
    },
]


def match_signatures(events: List[Dict]) -> List[Dict]:
    """
    Scan a list of normalised events for known attack signature sequences.
    Returns list of matched signature dicts with supporting evidence.
    """
    matches = []

    for sig in ATTACK_SIGNATURES:
        match = _try_match_sequence(events, sig)
        if match:
            matches.append({
                "signature_id": sig["id"],
                "name": sig["name"],
                "description": sig["description"],
                "severity": sig["severity"],
                "confidence": sig["confidence"],
                "hardware_hint": sig.get("hardware_hint", ""),
                "spec_ref": sig.get("spec_ref", ""),
                "matched_events": match,
            })

    return matches


def _try_match_sequence(events: List[Dict], sig: Dict) -> Optional[List[Dict]]:
    """
    Attempt to match a signature's event sequence in the event list.
    Returns matched events if found, None otherwise.
    """
    sequence = sig["sequence"]
    max_gap = sig.get("max_gap_seconds", 60)

    if not sequence:
        return None

    # Slide a window through events looking for the sequence
    matched_so_far = []
    last_ts = None

    for ev in events:
        expected = sequence[len(matched_so_far)]
        if _event_matches_step(ev, expected):
            ev_ts = _get_ts(ev)
            if last_ts is None or (ev_ts == 0) or (ev_ts - last_ts <= max_gap):
                matched_so_far.append(ev)
                last_ts = ev_ts if ev_ts > 0 else last_ts
                if len(matched_so_far) == len(sequence):
                    return matched_so_far

    return None


def _event_matches_step(ev: Dict, step: Dict) -> bool:
    """Check if an event matches a signature step's criteria."""
    for key, expected_val in step.items():
        ev_val = ev.get(key)
        if expected_val is True:
            if not ev_val:
                return False
        elif expected_val is False:
            if ev_val:
                return False
        elif ev_val is None:
            return False
        elif isinstance(expected_val, str) and isinstance(ev_val, str):
            if expected_val.lower() not in ev_val.lower():
                return False
        elif ev_val != expected_val:
            return False
    return True


def _get_ts(ev: Dict) -> float:
    """Get event timestamp as float."""
    ts = ev.get("timestamp")
    if not ts:
        return 0.0
    try:
        from dateutil import parser as dtparser
        return dtparser.parse(str(ts)).timestamp()
    except Exception:
        try:
            return float(str(ts))
        except (ValueError, TypeError):
            return 0.0
