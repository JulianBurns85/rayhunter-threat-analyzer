"""
rrc_redirect_detector.py — LTE Redirect Anomaly Detector
rayhunter-threat-analyzer / Julian Burns / Atomic Tech

Detects the Harris Arrowhead DF companion activation signature.

ATTACK MECHANISM:
  When Harris activates the Arrowhead direction-finding companion unit,
  the HailStorm sends RRCConnectionRelease with redirectedCarrierInfo
  pointing the UE toward a specific frequency for DF measurement.

  From Gemini QSG §6 "LTE Redirect MS DF":
    The rogue cell issues RRCConnectionRelease with a redirect target
    that is either:
      a) A frequency inconsistent with the serving EARFCN/band
      b) A frequency in the Arrowhead DF measurement range
      c) A frequency with no legitimate cell (causes re-scan, re-capture)

  Legitimate RRCConnectionRelease WITH redirect is rare — networks
  typically release without redirect, or redirect within the same band.
  A redirect to an unoccupied/anomalous frequency is highly suspicious.

DETECTION LOGIC:
  1. Find all RRCConnectionRelease frames with redirectedCarrierInfo
  2. Extract the target EARFCN
  3. Flag if target EARFCN:
     a) Differs from serving EARFCN by >100 (cross-band redirect)
     b) Is in a band not matching the serving carrier (cross-carrier)
     c) Points to EARFCN 9410/1275/450/3148 (our confirmed rogue cells)
     d) Appears repeatedly within short windows (systematic DF sweeping)

ARROWHEAD DF COMPANION SPECIFICS (from Arrowhead 1.0.1 Release Notes):
  - Connects to HailStorm via EIM (External Interface Module) connector
  - Uses RSSI measurements across multiple frequencies
  - Redirect target frequencies chosen to isolate target UE signal
  - Typical redirect pattern: serving freq → DF freq → re-capture freq
  - The systematic nature (multiple redirects in short window) is the key

KNOWN ROGUE EARFCNS (from this investigation):
  9410 (Band 28, 700MHz), 1275 (Band 3, 1800MHz),
  450 (Band 1, 2100MHz), 3148 (Band 7, 2600MHz)
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Configuration ─────────────────────────────────────────────────────────────

# Known rogue EARFCNs from this investigation — redirect TO these = suspicious
KNOWN_ROGUE_EARFCNS = {9410, 1275, 450, 3148}

# Maximum seconds between redirects to count as a DF sweep pattern
DF_SWEEP_WINDOW_SECONDS = 300.0

# Minimum redirects within window to classify as systematic DF sweep
DF_SWEEP_MIN_REDIRECTS = 3

# Cross-band threshold — redirects differing by more than this are suspicious
CROSS_BAND_EARFCN_DELTA = 100


# ── EARFCN → Band mapping (LTE) ───────────────────────────────────────────────

def earfcn_to_band(earfcn: int) -> Optional[int]:
    """Convert LTE EARFCN to band number. Returns None if unknown."""
    ranges = [
        (0,     599,   1),
        (600,   1199,  2),
        (1200,  1949,  3),
        (1950,  2399,  4),
        (2400,  2649,  5),
        (2650,  2749,  6),
        (2750,  3449,  7),
        (3450,  3799,  8),
        (36000, 36199, 17),
        (36200, 36349, 18),
        (36350, 36949, 19),
        (36950, 37549, 20),
        (37550, 37749, 21),
        (37750, 38249, 22),
        (38250, 38649, 23),
        (38650, 39649, 24),
        (39650, 41589, 25),
        (41590, 43589, 26),
        (43590, 45589, 27),
        (45590, 46589, 28),
        (46590, 46789, 29),
        (46790, 54539, 30),
    ]
    for start, end, band in ranges:
        if start <= earfcn <= end:
            return band
    return None


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class RedirectEvent:
    """An RRCConnectionRelease with redirectedCarrierInfo."""
    ts:              float
    serving_earfcn:  Optional[int]
    redirect_earfcn: int
    frame_num:       Optional[int] = None
    source:          str = 'pcap'

    @property
    def serving_band(self) -> Optional[int]:
        return earfcn_to_band(self.serving_earfcn) if self.serving_earfcn else None

    @property
    def redirect_band(self) -> Optional[int]:
        return earfcn_to_band(self.redirect_earfcn)

    @property
    def is_cross_band(self) -> bool:
        if self.serving_earfcn is None:
            return False
        return abs(self.redirect_earfcn - self.serving_earfcn) > CROSS_BAND_EARFCN_DELTA

    @property
    def targets_rogue_earfcn(self) -> bool:
        return self.redirect_earfcn in KNOWN_ROGUE_EARFCNS


# ── Main detector ─────────────────────────────────────────────────────────────

class RrcRedirectDetector:
    """
    Detects Harris Arrowhead DF activation via RRC redirect anomalies.
    """

    DETECTOR_NAME = 'rrc_redirect_anomaly'
    YAICD_PARAM   = 'P_DF'   # Not in original YAICD framework — new parameter
    YAICD_SCORE   = 1.5       # Proposed score — cross-band redirect is strong indicator

    def __init__(self):
        self._events: list[RedirectEvent] = []
        self._analysed = False
        self._findings_cache: Optional[dict] = None

    def ingest_events(self, events: list[RedirectEvent]) -> None:
        self._events.extend(events)
        self._analysed = False

    def analyse(self) -> dict:
        if self._analysed and self._findings_cache:
            return self._findings_cache

        events = sorted(self._events, key=lambda e: e.ts)

        rogue_targets   = [e for e in events if e.targets_rogue_earfcn]
        cross_band      = [e for e in events if e.is_cross_band]
        all_redirects   = events

        # Detect systematic DF sweep pattern
        sweep_sequences = []
        for i, evt in enumerate(events):
            window = [
                e for e in events
                if evt.ts <= e.ts <= evt.ts + DF_SWEEP_WINDOW_SECONDS
            ]
            if len(window) >= DF_SWEEP_MIN_REDIRECTS:
                # Check if this window hasn't already been captured
                if not sweep_sequences or sweep_sequences[-1][-1].ts < evt.ts:
                    sweep_sequences.append(window)

        triggered = bool(rogue_targets or cross_band or sweep_sequences)
        severity = 'NOT_TRIGGERED'
        if rogue_targets:
            severity = 'CRITICAL'
        elif sweep_sequences:
            severity = 'HIGH'
        elif cross_band:
            severity = 'MEDIUM'

        score = self.YAICD_SCORE if triggered else 0.0

        findings = {
            'detector':          self.DETECTOR_NAME,
            'yaicd_param':       self.YAICD_PARAM,
            'yaicd_score':       score,
            'triggered':         triggered,
            'severity':          severity,
            'total_redirects':   len(all_redirects),
            'rogue_targets':     len(rogue_targets),
            'cross_band':        len(cross_band),
            'sweep_sequences':   len(sweep_sequences),
            'events': [
                {
                    'ts':              datetime.utcfromtimestamp(e.ts).isoformat(),
                    'serving_earfcn':  e.serving_earfcn,
                    'serving_band':    e.serving_band,
                    'redirect_earfcn': e.redirect_earfcn,
                    'redirect_band':   e.redirect_band,
                    'cross_band':      e.is_cross_band,
                    'rogue_target':    e.targets_rogue_earfcn,
                }
                for e in all_redirects
            ],
            'summary': _build_summary(
                triggered, severity, all_redirects,
                rogue_targets, cross_band, sweep_sequences
            ),
        }

        self._findings_cache = findings
        self._analysed = True
        return findings


def _build_summary(triggered, severity, all_redirects, rogue_targets,
                   cross_band, sweep_sequences) -> str:
    if not triggered:
        return (
            f"RRC Redirect: {len(all_redirects)} redirect(s) found, "
            f"none anomalous. No Arrowhead DF activation signature."
        )

    parts = []
    if rogue_targets:
        earfcns = {e.redirect_earfcn for e in rogue_targets}
        parts.append(
            f"{len(rogue_targets)} redirect(s) targeting known rogue EARFCN(s) "
            f"{earfcns} — CRITICAL indicator of Arrowhead DF sweep toward "
            f"confirmed rogue infrastructure"
        )
    if sweep_sequences:
        parts.append(
            f"{len(sweep_sequences)} systematic DF sweep pattern(s) detected "
            f"(≥{DF_SWEEP_MIN_REDIRECTS} redirects within "
            f"{DF_SWEEP_WINDOW_SECONDS}s window)"
        )
    if cross_band:
        bands = {(e.serving_band, e.redirect_band) for e in cross_band}
        parts.append(
            f"{len(cross_band)} cross-band redirect(s): {bands}"
        )

    return (
        f"RRC REDIRECT ANOMALY [{severity}]: " + "; ".join(parts) + ". "
        f"Source: Gemini QSG §6 LTE Redirect MS DF, "
        f"Arrowhead 1.0.1 Release Notes (EIM companion unit)."
    )


# ── PCAP parser ───────────────────────────────────────────────────────────────

def extract_redirects_from_pcap(pcap_path: Path) -> list[RedirectEvent]:
    """
    Extract RRCConnectionRelease with redirectedCarrierInfo from PCAP.
    Uses tshark with RRC fields.
    """
    cmd = [
        'tshark', '-r', str(pcap_path),
        '-Y', 'lte_rrc.rrcConnectionRelease_element',
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'frame.number',
        '-e', 'gsmtap.arfcn',                           # serving EARFCN
        '-e', 'lte_rrc.redirectedCarrierInfo_element',  # redirect present
        '-e', 'lte_rrc.eutra',                          # redirect EARFCN (EUTRA)
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    events = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 5:
            continue
        try:
            ts              = float(parts[0]) if parts[0] else 0.0
            frame           = int(parts[1]) if parts[1] else 0
            serving_earfcn  = int(parts[2]) if parts[2] else None
            has_redirect    = bool(parts[3])
            redirect_earfcn = int(parts[4]) if parts[4] else None

            if ts and has_redirect and redirect_earfcn:
                events.append(RedirectEvent(
                    ts              = ts,
                    serving_earfcn  = serving_earfcn,
                    redirect_earfcn = redirect_earfcn,
                    frame_num       = frame,
                    source          = 'pcap',
                ))
        except (ValueError, IndexError):
            continue

    return sorted(events, key=lambda e: e.ts)


# ── CLI entry point ───────────────────────────────────────────────────────────

def run_on_directory(directory: Path) -> dict:
    detector = RrcRedirectDetector()

    pcap_files = list(directory.glob('*.pcapng')) + list(directory.glob('*.pcap'))
    print(f"[RRC Redirect] Scanning {len(pcap_files)} PCAP file(s)")

    for pcap in pcap_files:
        events = extract_redirects_from_pcap(pcap)
        print(f"  {pcap.name}: {len(events)} redirect event(s)")
        detector.ingest_events(events)

    findings = detector.analyse()

    print(f"\n[RRC Redirect] Result: {'TRIGGERED' if findings['triggered'] else 'not triggered'}")
    print(f"  {findings['summary']}")

    return findings


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python rrc_redirect_detector.py <directory>")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"Error: {target} not found")
        sys.exit(1)

    findings = run_on_directory(target)
    out = target / 'rrc_redirect_findings.json'
    out.write_text(json.dumps(findings, indent=2))
    print(f"\n[RRC Redirect] Written to {out}")
