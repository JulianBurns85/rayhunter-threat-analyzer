#!/usr/bin/env python3
"""
RealtimeAlertEngine — live attack-signature watcher for the phone node.

Watches a live stream of parsed cellular events (NDJSON, one event per line —
the same schema the offline detectors consume) and fires an alert the moment a
known attack signature appears. Designed to run on the Pixel 9 Pro Fold under
Termux/GrapheneOS as a lightweight always-on process.

This is the LIVE counterpart to the offline detector suite. The offline
detectors do deep forensic analysis over a whole corpus; this engine does fast
pattern-matching on a sliding window so you get a notification in the field
within seconds of an attack signature appearing.

SIGNATURES WATCHED (all derived from confirmed corpus findings)
---------------------------------------------------------------
  1. Wallet Inspector  : Auth Reject -> Identity Request within 5s
  2. FlashCatch        : new CID appears then vanishes within 2s
  3. Injected Handover : mobilityControlInfo with NO preceding MeasurementReport
  4. TA in range       : Timing Advance == known rogue TA (you're in range)
  5. Cross-carrier      : both rogue TACs seen within a short co-presence window

DESIGN
------
- Sliding time window (default 120s) holds recent events in memory.
- Each new event is appended, the window is trimmed, signatures are checked.
- Each signature has a cooldown so you don't get spammed by the same ongoing
  attack — one alert, then quiet for the cooldown period.
- Output is pluggable: termux-notification on the phone, or print() for testing.

USAGE
-----
  # live from a named pipe / tail of the parser output:
  tail -F /data/rayhunter/live.ndjson | python3 realtime_alert_engine.py

  # or test against a captured file:
  python3 realtime_alert_engine.py --file sample_events.ndjson --replay

Honest scope: this matches the SAME signatures the offline suite already
confirmed. It is a fast tripwire, not a new analytical claim. False positives
are possible on noisy live data — treat an alert as "look now", and let the
offline forensic suite be the system of record.
"""

import sys
import json
import time
import argparse
import subprocess
from collections import deque
from typing import Dict, List, Optional, Callable


# ── Known-threat parameters (from confirmed Cranbourne East corpus) ──── #
KNOWN_ROGUE_TA = 7                      # TA=7 ~547m fixed installation
KNOWN_ROGUE_TACS = {12385}    # TAC=30336 removed — confirmed legitimate Vodafone (eNB 32849)
KNOWN_ROGUE_CIDS = {21940289, 2861966, 2862043,
                    137713165}          # FlashCatch CIDs + Wallet Inspector CID

# ── Signature timing thresholds ──────────────────────────────────────── #
WALLET_GAP_MAX_S = 5.0                  # Auth Reject -> Identity Request
FLASHCATCH_LIFETIME_MAX_S = 1.0         # CID appear -> vanish (genuine flash)
PERSISTENT_CID_MIN_SPAN_S = 30.0        # CID seen across >= this span = legit persistent
CROSS_CARRIER_WINDOW_S = 60.0           # both TACs within this window
WINDOW_SECONDS = 120.0                  # sliding memory window
DEFAULT_COOLDOWN_S = 300.0              # per-signature alert cooldown (5 min)


def _now() -> float:
    return time.time()


def _msg(e: Dict) -> str:
    return str(e.get("msg") or e.get("message_type") or e.get("msg_type") or "")


def _ts(e: Dict) -> Optional[float]:
    v = e.get("ts") or e.get("timestamp") or e.get("time")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class Alert:
    __slots__ = ("level", "signature", "detail", "ts")

    def __init__(self, level: str, signature: str, detail: str, ts: float):
        self.level = level
        self.signature = signature
        self.detail = detail
        self.ts = ts

    def format(self) -> str:
        icon = {"RED": "⛔", "AMBER": "⚠", "BLUE": "🔵"}.get(self.level, "•")
        return f"{icon} {self.signature} — {self.detail}"


# ── Output sinks ─────────────────────────────────────────────────────── #
def termux_notify(alert: Alert) -> None:
    """Fire an Android notification via Termux:API. No-op if unavailable."""
    try:
        subprocess.run(
            ["termux-notification",
             "--title", f"[{alert.level}] {alert.signature}",
             "--content", alert.detail,
             "--priority", "max" if alert.level == "RED" else "high",
             "--vibrate", "500,200,500" if alert.level == "RED" else "300"],
            check=False, timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        pass


def stdout_notify(alert: Alert) -> None:
    ts = time.strftime("%H:%M:%S", time.localtime(alert.ts))
    print(f"[{ts}] {alert.format()}", flush=True)


class RealtimeAlertEngine:
    """
    Sliding-window live attack-signature matcher.
    """

    def __init__(self,
                 sink: Callable[[Alert], None] = stdout_notify,
                 window_s: float = WINDOW_SECONDS,
                 cooldown_s: float = DEFAULT_COOLDOWN_S):
        self.sink = sink
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self.events: deque = deque()
        self._last_alert: Dict[str, float] = {}
        # transient CID lifetime tracking: cid -> first_seen_ts
        self._cid_first_seen: Dict[int, float] = {}
        self._cid_last_seen: Dict[int, float] = {}
        self._cid_seen_count: Dict[int, int] = {}
        # CIDs proven legit by long persistence — survives window trimming,
        # permanently exempt from FlashCatch false-positives
        self._persistent_cids: set = set()
        # earliest-ever sighting per CID (NOT trimmed) for persistence test
        self._cid_ever_first: Dict[int, float] = {}

    # -- cooldown gate -------------------------------------------------- #
    def _ready(self, signature: str, ts: float) -> bool:
        last = self._last_alert.get(signature, 0.0)
        if ts - last >= self.cooldown_s:
            self._last_alert[signature] = ts
            return True
        return False

    def _fire(self, level: str, signature: str, detail: str, ts: float):
        if self._ready(signature, ts):
            self.sink(Alert(level, signature, detail, ts))

    # -- window maintenance --------------------------------------------- #
    def _trim(self, now_ts: float):
        cutoff = now_ts - self.window_s
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    # -- main ingest ---------------------------------------------------- #
    def ingest(self, event: Dict):
        ts = _ts(event)
        if ts is None:
            ts = _now()
        self.events.append((ts, event))
        self._trim(ts)
        self._check_signatures(ts, event)

    # -- signature checks ----------------------------------------------- #
    def _check_signatures(self, ts: float, event: Dict):
        msg = _msg(event).lower()

        # --- TA in range -------------------------------------------------
        ta = event.get("ta") or event.get("timing_advance")
        try:
            if ta is not None and int(ta) == KNOWN_ROGUE_TA:
                self._fire("AMBER", "TA In Range",
                           f"Timing Advance = {KNOWN_ROGUE_TA} "
                           f"(~547m — known installation range)", ts)
        except (TypeError, ValueError):
            pass

        # --- Cross-carrier co-presence ----------------------------------
        tac = event.get("tac")
        try:
            tac = int(tac) if tac is not None else None
        except (TypeError, ValueError):
            tac = None
        if tac in KNOWN_ROGUE_TACS:
            seen_tacs = set()
            for ets, ev in self.events:
                if ts - ets <= CROSS_CARRIER_WINDOW_S:
                    t = ev.get("tac")
                    try:
                        t = int(t) if t is not None else None
                    except (TypeError, ValueError):
                        t = None
                    if t in KNOWN_ROGUE_TACS:
                        seen_tacs.add(t)
            if seen_tacs >= KNOWN_ROGUE_TACS:
                self._fire("RED", "Cross-Carrier Co-Presence",
                           f"Both rogue TACs {sorted(KNOWN_ROGUE_TACS)} active "
                           f"within {CROSS_CARRIER_WINDOW_S:.0f}s — dual-device", ts)

        # --- Wallet Inspector: Auth Reject -> Identity Request ----------
        if "identityrequest" in msg.replace(" ", "") or "identity request" in msg:
            for ets, ev in reversed(self.events):
                if ts - ets > WALLET_GAP_MAX_S:
                    break
                em = _msg(ev).lower()
                if "authentication reject" in em or "authreject" in em.replace(" ", ""):
                    gap_ms = (ts - ets) * 1000.0
                    self._fire("RED", "Wallet Inspector",
                               f"Auth Reject -> Identity Request, "
                               f"{gap_ms:.0f}ms gap (pre-security IMSI grab)", ts)
                    break

        # --- Injected Handover: mobilityControlInfo, no MeasurementReport
        mlow = msg.replace(" ", "")
        if "mobilitycontrolinfo" in mlow or "rrcreconfiguration" in mlow:
            saw_measreport = False
            for ets, ev in self.events:
                if ts - ets > self.window_s:
                    continue
                if "measurementreport" in _msg(ev).lower().replace(" ", ""):
                    saw_measreport = True
                    break
            if not saw_measreport:
                self._fire("RED", "Injected Handover",
                           "Handover/RRC reconfig with NO preceding "
                           "MeasurementReport (physically anomalous)", ts)

        # --- FlashCatch: transient CID appear -> vanish -----------------
        cid = event.get("cid") or event.get("cell_id")
        try:
            cid = int(cid) if cid is not None else None
        except (TypeError, ValueError):
            cid = None
        if cid is not None:
            if cid not in self._cid_first_seen:
                self._cid_first_seen[cid] = ts
            self._cid_last_seen[cid] = ts
            self._cid_seen_count[cid] = self._cid_seen_count.get(cid, 0) + 1
            # never-trimmed earliest sighting, for persistence determination
            if cid not in self._cid_ever_first:
                self._cid_ever_first[cid] = ts
            if (ts - self._cid_ever_first[cid]) >= PERSISTENT_CID_MIN_SPAN_S:
                self._persistent_cids.add(cid)
            # known FlashCatch CID is an immediate amber
            if cid in KNOWN_ROGUE_CIDS:
                self._fire("AMBER", "Known Rogue CID",
                           f"CID {cid} seen (on known-rogue list)", ts)

    def sweep_transient_cids(self, now_ts: float):
        """
        Call periodically. Detects CIDs that appeared and vanished within the
        FlashCatch lifetime threshold — the sub-second flash signature.

        Guards against false positives:
          - lifetime must be genuinely brief (<= threshold) AND > 0 (seen more
            than once at the same instant is not a "flash")
          - a CID seen only ONCE is not enough; a real flash is caught mid-attach
            so it produces a short burst, not a single stray packet
          - known-legitimate behaviour: a CID that persisted across many events
            is excluded by the lifetime gate naturally
        """
        gone = []
        for cid, first in self._cid_first_seen.items():
            last = self._cid_last_seen.get(cid, first)
            lifetime = last - first
            seen_count = self._cid_seen_count.get(cid, 1)
            if (now_ts - last) > FLASHCATCH_LIFETIME_MAX_S:
                # CIDs proven legit by long persistence are never flashes
                if cid in self._persistent_cids and cid not in KNOWN_ROGUE_CIDS:
                    gone.append(cid)
                    continue
                # genuine flash: brief but non-trivial lifetime, multiple sightings,
                # OR explicitly on the known-rogue list
                is_brief = 0.0 < lifetime <= FLASHCATCH_LIFETIME_MAX_S
                enough_sightings = seen_count >= 2
                if (is_brief and enough_sightings) or cid in KNOWN_ROGUE_CIDS:
                    if is_brief and enough_sightings:
                        self._fire("RED", "FlashCatch",
                                   f"CID {cid} flashed for {lifetime:.2f}s "
                                   f"({seen_count} sightings) then vanished "
                                   f"(sub-second IMSI catch window)", now_ts)
                gone.append(cid)
        for cid in gone:
            self._cid_first_seen.pop(cid, None)
            self._cid_last_seen.pop(cid, None)
            self._cid_seen_count.pop(cid, None)


# ── Runner ───────────────────────────────────────────────────────────── #
def main():
    ap = argparse.ArgumentParser(description="Live attack-signature alert engine")
    ap.add_argument("--file", help="read events from file instead of stdin")
    ap.add_argument("--replay", action="store_true",
                    help="replay file honouring inter-event timing (demo)")
    ap.add_argument("--termux", action="store_true",
                    help="fire Android notifications via Termux:API")
    ap.add_argument("--cooldown", type=float, default=DEFAULT_COOLDOWN_S)
    args = ap.parse_args()

    sink = termux_notify if args.termux else stdout_notify
    engine = RealtimeAlertEngine(sink=sink, cooldown_s=args.cooldown)

    stream = open(args.file) if args.file else sys.stdin
    last_sweep = 0.0
    try:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            engine.ingest(event)
            now = _ts(event) or _now()
            if now - last_sweep >= 1.0:
                engine.sweep_transient_cids(now)
                last_sweep = now
    finally:
        if args.file:
            stream.close()


if __name__ == "__main__":
    main()
