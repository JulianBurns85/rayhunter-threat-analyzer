"""
SessionOverlapCorrelator
========================
Two functions in one module:

1.  identify_parallel_sessions()
    Finds sessions with overlapping time windows and different carriers
    (i.e. the dual-device Vodafone+Telstra capture configuration).
    Outputs a human-readable section for the report noting which sessions
    are confirmed simultaneous captures.

2.  cross_carrier_timestamp_pairs()
    For any two parallel sessions on different carriers, finds CID
    observation events that occur within a configurable gap window
    (default 30 seconds) and returns them as pinned timestamp pairs.
    This is the primary evidence unit for the USB package.

Rationale
---------
Sessions 1655238 (Vodafone) and 1656131 (Telstra) ran in parallel from
2026-05-20T02:26Z to 2026-05-21T18:05Z. The analyzer confirmed
cross-carrier simultaneous events but did not output the specific
timestamp pairs. This module surfaces those pairs explicitly.

Integration
-----------
Import and call from reporter.py after the main detection phase.
Results feed into the JSON report under a new 'session_correlation'
top-level key and into the PRIORITY ACTIONS section.

Usage
-----
    from session_overlap_correlator import SessionOverlapCorrelator

    corr = SessionOverlapCorrelator(sessions, gap_seconds=30)
    corr.analyze()
    report_section = corr.render_text()
    json_data      = corr.to_dict()
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# Regex matching rayhunter SIB1 event messages
_CID_RE = re.compile(r"CID:\s*(\d+),\s*TAC:\s*(\d+),\s*PLMN:\s*(\S+)")

# Known carrier attribution by MNC
_MNC_CARRIER = {
    "01": "Telstra",
    "001": "Telstra",
    "03": "Vodafone AU",
    "003": "Vodafone AU",
}


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


class SessionOverlapCorrelator:
    """
    Accepts a dict of session_id → list[event_dict] and finds:
      - Overlapping session pairs (different carriers, same time window)
      - Cross-carrier CID events within `gap_seconds` of each other

    Parameters
    ----------
    sessions   : dict mapping session_id (str) to flat list of event dicts
    gap_seconds: max seconds between events on different carriers to count
                 as a simultaneous cross-carrier event (default 30)
    """

    def __init__(
        self,
        sessions: dict[str, list[dict[str, Any]]],
        gap_seconds: float = 30.0,
    ) -> None:
        self.sessions    = sessions
        self.gap_seconds = gap_seconds

        # Populated by analyze()
        self.session_meta:    dict[str, dict] = {}
        self.parallel_pairs:  list[tuple[str, str]] = []
        self.timestamp_pairs: list[dict]  = []

    # ── Public API ─────────────────────────────────────────────────────

    def analyze(self) -> None:
        """Run full correlation. Call before render_text() or to_dict()."""
        self._build_session_meta()
        self._find_parallel_pairs()
        self._find_timestamp_pairs()

    def render_text(self) -> str:
        """Return a plain-text report section for insertion into the CLI output."""
        lines = [
            "",
            "=" * 64,
            "SESSION OVERLAP CORRELATION",
            "=" * 64,
        ]

        if not self.parallel_pairs:
            lines.append("  No parallel dual-carrier sessions detected.")
            return "\n".join(lines)

        for sid_a, sid_b in self.parallel_pairs:
            meta_a = self.session_meta[sid_a]
            meta_b = self.session_meta[sid_b]
            overlap_start = max(meta_a["first_epoch"], meta_b["first_epoch"])
            overlap_end   = min(meta_a["last_epoch"],  meta_b["last_epoch"])
            overlap_dur   = overlap_end - overlap_start

            lines += [
                "",
                f"  Parallel pair: {sid_a} ({meta_a['carrier']}) "
                f"+ {sid_b} ({meta_b['carrier']})",
                f"  Overlap window: {_epoch_to_iso(overlap_start)} "
                f"→ {_epoch_to_iso(overlap_end)}",
                f"  Overlap duration: {overlap_dur / 3600:.2f} hours",
                f"  Note: Cross-carrier events in this window have "
                f"dual-session confirmation.",
            ]

        # Pinned timestamp pairs
        if self.timestamp_pairs:
            lines += [
                "",
                f"  Cross-carrier simultaneous events "
                f"(gap ≤ {self.gap_seconds}s): "
                f"{len(self.timestamp_pairs)} pair(s)",
                "",
            ]
            for pair in self.timestamp_pairs:
                gap_str = f"{pair['gap_seconds']:.3f}s"
                lines += [
                    f"  ┌─ Event pair (gap={gap_str})",
                    f"  │  [{pair['carrier_a']}] {pair['ts_a']}",
                    f"  │  CID={pair['cid_a']} TAC={pair['tac_a']} "
                    f"session={pair['session_a']}",
                    f"  │  [{pair['carrier_b']}] {pair['ts_b']}",
                    f"  │  CID={pair['cid_b']} TAC={pair['tac_b']} "
                    f"session={pair['session_b']}",
                    f"  └─",
                    "",
                ]
        else:
            lines.append(
                f"  No cross-carrier events found within "
                f"{self.gap_seconds}s gap window."
            )

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return structured data for JSON report under 'session_correlation' key."""
        return {
            "parallel_session_pairs": [
                {
                    "session_a": a,
                    "carrier_a": self.session_meta[a]["carrier"],
                    "session_b": b,
                    "carrier_b": self.session_meta[b]["carrier"],
                    "overlap_start": _epoch_to_iso(
                        max(
                            self.session_meta[a]["first_epoch"],
                            self.session_meta[b]["first_epoch"],
                        )
                    ),
                    "overlap_end": _epoch_to_iso(
                        min(
                            self.session_meta[a]["last_epoch"],
                            self.session_meta[b]["last_epoch"],
                        )
                    ),
                }
                for a, b in self.parallel_pairs
            ],
            "cross_carrier_timestamp_pairs": self.timestamp_pairs,
            "gap_threshold_seconds": self.gap_seconds,
        }

    # ── Internal helpers ───────────────────────────────────────────────

    def _build_session_meta(self) -> None:
        """Compute per-session time range and carrier from events."""
        for sid, events in self.sessions.items():
            epochs   = []
            carriers = set()

            for evt in events:
                ts = evt.get("timestamp") or evt.get("packet_timestamp") or ""
                ep = _parse_ts(ts)
                if ep:
                    epochs.append(ep)

                msg = evt.get("message", "") or ""
                m = _CID_RE.search(msg)
                if m:
                    plmn  = m.group(3)
                    mnc   = plmn.split("-")[1] if "-" in plmn else ""
                    carrier = _MNC_CARRIER.get(mnc, f"MNC={mnc}")
                    carriers.add(carrier)

            if not epochs:
                continue

            self.session_meta[sid] = {
                "first_epoch": min(epochs),
                "last_epoch":  max(epochs),
                "carrier":     ", ".join(sorted(carriers)) if carriers else "unknown",
                "event_count": len(events),
            }

    def _find_parallel_pairs(self) -> None:
        """Find pairs of sessions with overlapping windows on different carriers."""
        sids = list(self.session_meta.keys())
        for i in range(len(sids)):
            for j in range(i + 1, len(sids)):
                sid_a = sids[i]
                sid_b = sids[j]
                meta_a = self.session_meta[sid_a]
                meta_b = self.session_meta[sid_b]

                # Must be different carriers
                if meta_a["carrier"] == meta_b["carrier"]:
                    continue

                # Must have overlapping time windows
                overlap_start = max(meta_a["first_epoch"], meta_b["first_epoch"])
                overlap_end   = min(meta_a["last_epoch"],  meta_b["last_epoch"])
                if overlap_start >= overlap_end:
                    continue

                self.parallel_pairs.append((sid_a, sid_b))

    def _find_timestamp_pairs(self) -> None:
        """
        For each parallel pair, extract CID events and find those
        within gap_seconds of each other on different carriers.
        """
        # Build per-session CID event list: [(epoch, cid, tac, carrier, session)]
        session_cid_events: dict[str, list[tuple]] = defaultdict(list)

        for sid, events in self.sessions.items():
            if sid not in self.session_meta:
                continue
            carrier = self.session_meta[sid]["carrier"]
            for evt in events:
                ts  = evt.get("timestamp") or evt.get("packet_timestamp") or ""
                ep  = _parse_ts(ts)
                if ep is None:
                    continue
                msg = evt.get("message", "") or ""
                m   = _CID_RE.search(msg)
                if not m:
                    continue
                session_cid_events[sid].append(
                    (ep, m.group(1), m.group(2), carrier)
                )

        seen_pairs: set[tuple] = set()

        for sid_a, sid_b in self.parallel_pairs:
            events_a = session_cid_events.get(sid_a, [])
            events_b = session_cid_events.get(sid_b, [])

            for ep_a, cid_a, tac_a, car_a in events_a:
                for ep_b, cid_b, tac_b, car_b in events_b:
                    gap = abs(ep_a - ep_b)
                    if gap > self.gap_seconds:
                        continue

                    # Deduplicate (same pair within 1 second)
                    pair_key = (
                        round(ep_a),
                        round(ep_b),
                        cid_a,
                        cid_b,
                    )
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    self.timestamp_pairs.append({
                        "ts_a":      _epoch_to_iso(ep_a),
                        "session_a": sid_a,
                        "carrier_a": car_a,
                        "cid_a":     cid_a,
                        "tac_a":     tac_a,
                        "ts_b":      _epoch_to_iso(ep_b),
                        "session_b": sid_b,
                        "carrier_b": car_b,
                        "cid_b":     cid_b,
                        "tac_b":     tac_b,
                        "gap_seconds": round(gap, 3),
                    })

        # Sort by timestamp of first event in pair
        self.timestamp_pairs.sort(key=lambda x: x["ts_a"])
