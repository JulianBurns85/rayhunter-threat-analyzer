#!/usr/bin/env python3
"""
flag_provenance.py — IE-flag provenance helper
==============================================
The NDJSON parser sets boolean IE-presence flags (has_mobility_control,
has_prose, has_geran_redirect). Some are set from AUTHORITATIVE evidence
(a decoded protocol IE, or a Rayhunter analyzer that actually fired); others
are set from an incidental keyword in free-text log content and are recorded
in the event's `keyword_derived_flags` list.

A keyword in a log line ("...ML1 Handover...") is NOT a decoded
mobilityControlInfo IE. Detectors that treat these flags as confirmed-attack
evidence must verify provenance first. This is the single seam where
"the log mentioned the concept" was being conflated with "the IE was present".

Adoption is one line per detector:

    from flag_provenance import flag_is_verified
    # before:  if e.get("has_prose"):
    # after:   if flag_is_verified(e, "has_prose"):
"""
from typing import Dict, List


def flag_is_verified(ev: Dict, flag_name: str) -> bool:
    """
    True only if `flag_name` is set AND was not derived from a bare keyword
    match. Returns False for unset flags and for keyword-derived ones.
    """
    if not ev.get(flag_name):
        return False
    return flag_name not in (ev.get("keyword_derived_flags") or [])


def keyword_only_flags(ev: Dict) -> List[str]:
    """Return the list of IE flags on this event that are keyword-derived."""
    return list(ev.get("keyword_derived_flags") or [])


def verified_events(events: List[Dict], flag_name: str) -> List[Dict]:
    """Filter to events whose `flag_name` is set from authoritative evidence."""
    return [e for e in events if flag_is_verified(e, flag_name)]
