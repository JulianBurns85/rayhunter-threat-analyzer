"""
cross_carrier_timestamp_patch.py
=================================
Patch / drop-in replacement for the evidence output section of the
existing cross_carrier_release detector (RogueTowerDetector or
whichever module currently handles the P10_cross_carrier_release
YAICD parameter).

PROBLEM
-------
The existing detector confirms the cross-carrier simultaneous release
heuristic and adds it to the YAICD score, but only outputs:

    "CROSS_CARRIER: Simultaneous multi-carrier sync → ..."

It does not output the specific timestamp pairs that triggered the
detection. For the USB evidence package, VicPol and ACMA need exact
timestamps, not just a confirmation flag.

SOLUTION
--------
This module provides `CrossCarrierEvidencePatcher` — a post-processing
class that accepts the flat event list and the list of sessions already
identified as parallel by SessionOverlapCorrelator, then generates a
rich evidence block with pinned timestamp pairs for insertion into any
Finding that already references P10_cross_carrier_release.

INTEGRATION
-----------
In reporter.py (or wherever findings are finalised before output),
after the main detector phase:

    from cross_carrier_timestamp_patch import CrossCarrierEvidencePatcher

    patcher = CrossCarrierEvidencePatcher(
        all_events=flat_events,
        parallel_pairs=correlator.parallel_pairs,   # from SessionOverlapCorrelator
        session_meta=correlator.session_meta,
        gap_seconds=5.0,   # tighter window than correlator's 30s default
    )
    patcher.apply(findings)   # mutates matching Finding objects in-place

The patcher finds any Finding whose title or technique references
"cross_carrier" (case-insensitive) and appends the pinned timestamp
pairs to its evidence list, replacing the generic confirmation string.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

_CID_RE = re.compile(r"CID:\s*(\d+),\s*TAC:\s*(\d+),\s*PLMN:\s*(\S+)")


def _parse_ts(ts_str: str) -> float | None:
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str.rstrip("Z")).replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class CrossCarrierEvidencePatcher:
    """
    Post-processing class that enriches cross-carrier findings with
    pinned timestamp pairs.

    Parameters
    ----------
    all_events     : flat list of normalised event dicts from all sessions
    parallel_pairs : list of (sid_a, sid_b) tuples from SessionOverlapCorrelator
    session_meta   : dict of sid → {carrier, first_epoch, last_epoch, ...}
    gap_seconds    : max gap (seconds) to count as simultaneous (default 5.0)
    """

    # Tight window for definitive simultaneous events
    DEFAULT_GAP = 5.0

    def __init__(
        self,
        all_events: list[dict[str, Any]],
        parallel_pairs: list[tuple[str, str]],
        session_meta: dict[str, dict],
        gap_seconds: float = DEFAULT_GAP,
    ) -> None:
        self.all_events     = all_events
        self.parallel_pairs = parallel_pairs
        self.session_meta   = session_meta
        self.gap_seconds    = gap_seconds
        self._pairs: list[dict] = []

    def compute(self) -> list[dict]:
        """
        Compute and return the list of cross-carrier timestamp pair dicts.
        Called automatically by apply() if not already called.
        """
        if self._pairs:
            return self._pairs

        # Group events by session
        session_events: dict[str, list] = defaultdict(list)
        for evt in self.all_events:
            sid = evt.get("session_id") or evt.get("source", "")
            session_events[sid].append(evt)

        seen: set[tuple] = set()

        for sid_a, sid_b in self.parallel_pairs:
            carrier_a = self.session_meta.get(sid_a, {}).get("carrier", "?")
            carrier_b = self.session_meta.get(sid_b, {}).get("carrier", "?")

            cid_events_a = self._extract_cid_events(session_events[sid_a], carrier_a, sid_a)
            cid_events_b = self._extract_cid_events(session_events[sid_b], carrier_b, sid_b)

            for ea in cid_events_a:
                for eb in cid_events_b:
                    gap = abs(ea["epoch"] - eb["epoch"])
                    if gap > self.gap_seconds:
                        continue
                    key = (round(ea["epoch"]), round(eb["epoch"]), ea["cid"], eb["cid"])
                    if key in seen:
                        continue
                    seen.add(key)
                    self._pairs.append({
                        "ts_a":      ea["ts_iso"],
                        "session_a": ea["session"],
                        "carrier_a": ea["carrier"],
                        "cid_a":     ea["cid"],
                        "tac_a":     ea["tac"],
                        "ts_b":      eb["ts_iso"],
                        "session_b": eb["session"],
                        "carrier_b": eb["carrier"],
                        "cid_b":     eb["cid"],
                        "tac_b":     eb["tac"],
                        "gap_seconds": round(gap, 3),
                    })

        self._pairs.sort(key=lambda x: x["ts_a"])
        return self._pairs

    def apply(self, findings: list) -> None:
        """
        Mutate cross-carrier Finding objects in-place, appending
        pinned timestamp pairs to their evidence lists.

        Parameters
        ----------
        findings : list of Finding objects (must have .evidence attribute
                   which is a list of strings, and .title / .technique)
        """
        pairs = self.compute()
        if not pairs:
            return

        for finding in findings:
            title     = getattr(finding, "title", "").lower()
            technique = getattr(finding, "technique", "").lower()
            if "cross_carrier" not in title and "cross_carrier" not in technique \
               and "cross carrier" not in title and "cross carrier" not in technique:
                continue

            # Append pinned pairs to evidence
            evidence = getattr(finding, "evidence", [])

            # Remove old generic confirmation line if present
            evidence = [
                e for e in evidence
                if "simultaneous multi-carrier" not in str(e).lower()
            ]

            evidence.append(
                f"--- Cross-carrier timestamp pairs "
                f"(gap ≤ {self.gap_seconds}s): {len(pairs)} event(s) ---"
            )
            for p in pairs:
                evidence.append(
                    f"  [{p['carrier_a']}] {p['ts_a']}  "
                    f"CID={p['cid_a']} TAC={p['tac_a']}  [{p['session_a']}]"
                )
                evidence.append(
                    f"  [{p['carrier_b']}] {p['ts_b']}  "
                    f"CID={p['cid_b']} TAC={p['tac_b']}  [{p['session_b']}]"
                    f"  gap={p['gap_seconds']}s"
                )
                evidence.append("")

            finding.evidence = evidence

            # Also patch action list if it exists
            action = getattr(finding, "action", [])
            action.append(
                f"Cross-carrier pairs ({len(pairs)} event(s) ≤{self.gap_seconds}s) "
                f"are now pinned in evidence. Include these timestamp pairs "
                f"verbatim in the USB evidence package forensic report."
            )
            finding.action = action

    # ── Internal ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_cid_events(
        events: list[dict],
        carrier: str,
        session_id: str,
    ) -> list[dict]:
        result = []
        for evt in events:
            ts  = evt.get("timestamp") or evt.get("packet_timestamp") or ""
            ep  = _parse_ts(ts)
            if ep is None:
                continue
            # Check direct message
            for evt_inner in evt.get("events", [evt]):
                if evt_inner is None:
                    continue
                msg = evt_inner.get("message", "") if isinstance(evt_inner, dict) else ""
                m = _CID_RE.search(msg)
                if m:
                    result.append({
                        "epoch":   ep,
                        "ts_iso":  _epoch_to_iso(ep),
                        "cid":     m.group(1),
                        "tac":     m.group(2),
                        "carrier": carrier,
                        "session": session_id,
                    })
        return result
