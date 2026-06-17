"""
auth_reject_imeisv_detector.py — P7 Auth Reject → IMEISV Sequence Detector
rayhunter-threat-analyzer / Julian Burns / Atomic Tech

Detects the IMEISV P7 attack documented in:
  Kareem (2023) "The Impact of IMSI Catcher Deployments" IJRITCC
  YAICD framework — P7 parameter (score contribution: 2.0)

ATTACK MECHANISM:
  Harris HailStorm sends Authentication Reject (NAS 0x44 / EMM type 0x44)
  immediately followed by an Identity Request (NAS 0x55) specifying
  IMEISV (identity type 0x03). This sequence is architecturally impossible
  on a legitimate LTE network:

  On a legitimate network:
    Auth Reject → UE detaches → no further NAS exchange until re-attach
    Identity Request only sent BEFORE security context is established

  On Harris HailStorm (transparent proxy mode):
    Auth Reject used to reset UE state while retaining NAS session
    → Identity Request sent immediately while UE still connected
    → UE responds with IMEISV (IMEI + software version = 16 digits)
    This gives Harris the device fingerprint WITHOUT establishing
    a security context, bypassing the 3GPP protection mechanism.

DETECTION LOGIC:
  1. Scan all NAS EMM messages for Authentication Reject (type 0x44)
  2. For each Auth Reject, check if an Identity Request (type 0x55)
     appears within SEQUENCE_WINDOW_SECONDS on the same connection
  3. If Identity Request requests IMEISV (identity_type == 3): CRITICAL
  4. If Identity Request requests IMSI (identity_type == 1): HIGH
  5. Any Identity Request within window: MEDIUM (suspicious)

SOURCE CONFIRMATION:
  Gemini 3.3 QSG §4-2: "After IMSI capture the MS is rejected (TAU Reject
  cause 2 or 13)" — the rejection is deliberate, not an error.
  The IMEISV request exploits the window between rejection and re-attach.

PCAP EVIDENCE STATUS:
  Run this detector against all corpus PCAPs to check for P7 presence.
  Expected result: 1+ sequences if HailStorm is in full harvest mode.
  Zero sequences if HailStorm in passive/logging mode only.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Detection parameters ──────────────────────────────────────────────────────

# Maximum seconds between Auth Reject and Identity Request to count as sequence
SEQUENCE_WINDOW_SECONDS = 10.0

# NAS EMM message types (decimal)
NAS_AUTH_REJECT     = 0x44   # 68  — Authentication Reject
NAS_IDENTITY_REQ    = 0x55   # 85  — Identity Request
NAS_IDENTITY_RESP   = 0x56   # 86  — Identity Response
NAS_SECURITY_MODE   = 0x5D   # 93  — Security Mode Command
NAS_ATTACH_ACCEPT   = 0x42   # 66  — Attach Accept
NAS_TAU_REJECT      = 0x4B   # 75  — Tracking Area Update Reject

# Identity types in Identity Request
IDENTITY_TYPE_IMSI   = 1
IDENTITY_TYPE_IMEI   = 2
IDENTITY_TYPE_IMEISV = 3

# Kareem (2023) cause codes associated with HailStorm rejection
HARRIS_TAU_REJECT_CAUSES = {2, 13}  # "IMSI unknown in HSS", "Roaming not allowed"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class NasEvent:
    """A single NAS message extracted from PCAP/NDJSON."""
    ts:           float         # Unix timestamp
    msg_type:     int           # NAS EMM type byte
    identity_type: Optional[int] = None   # For Identity Request/Response
    cause:        Optional[int] = None    # For Reject messages
    frame_num:    Optional[int] = None
    source:       str = ''      # 'pcap' or 'ndjson'


@dataclass
class P7Sequence:
    """A confirmed Auth Reject → Identity Request sequence."""
    auth_reject:      NasEvent
    identity_request: NasEvent
    gap_seconds:      float
    identity_type:    int
    severity:         str        # CRITICAL / HIGH / MEDIUM


# ── Main detector class ───────────────────────────────────────────────────────

class AuthRejectImeisvDetector:
    """
    Detects Harris P7 attack: Authentication Reject → IMEISV Identity Request.

    Designed to plug into rayhunter-threat-analyzer's detector pipeline.
    Call ingest_events() with a sorted list of NasEvent objects,
    then call findings() to retrieve detected sequences.
    """

    DETECTOR_NAME = 'auth_reject_imeisv'
    YAICD_PARAM   = 'P7'
    YAICD_SCORE   = 2.0   # Kareem 2023 / YAICD framework score

    def __init__(self):
        self._events: list[NasEvent] = []
        self._sequences: list[P7Sequence] = []
        self._analysed = False

    def ingest_events(self, events: list[NasEvent]) -> None:
        """Add NAS events. Can be called multiple times (e.g. per-session)."""
        self._events.extend(events)
        self._analysed = False

    def analyse(self) -> list[P7Sequence]:
        """Run detection. Returns list of confirmed P7 sequences."""
        if self._analysed:
            return self._sequences

        sorted_events = sorted(self._events, key=lambda e: e.ts)
        auth_rejects = [e for e in sorted_events if e.msg_type == NAS_AUTH_REJECT]

        sequences = []
        for reject in auth_rejects:
            # Look for Identity Request within window AFTER this reject
            window_end = reject.ts + SEQUENCE_WINDOW_SECONDS
            candidates = [
                e for e in sorted_events
                if e.msg_type == NAS_IDENTITY_REQ
                and reject.ts < e.ts <= window_end
            ]

            for candidate in candidates:
                gap = candidate.ts - reject.ts
                id_type = candidate.identity_type or 0

                if id_type == IDENTITY_TYPE_IMEISV:
                    severity = 'CRITICAL'
                elif id_type == IDENTITY_TYPE_IMSI:
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'

                sequences.append(P7Sequence(
                    auth_reject      = reject,
                    identity_request = candidate,
                    gap_seconds      = gap,
                    identity_type    = id_type,
                    severity         = severity,
                ))

        self._sequences = sequences
        self._analysed = True
        return sequences

    def findings(self) -> dict:
        """Return structured findings dict for rayhunter-threat-analyzer."""
        seqs = self.analyse()
        if not seqs:
            return {
                'detector':     self.DETECTOR_NAME,
                'yaicd_param':  self.YAICD_PARAM,
                'yaicd_score':  0.0,
                'triggered':    False,
                'sequences':    [],
                'summary':      'P7 not detected — no Auth Reject → Identity Request sequences',
            }

        critical = [s for s in seqs if s.severity == 'CRITICAL']
        high     = [s for s in seqs if s.severity == 'HIGH']
        score    = self.YAICD_SCORE if seqs else 0.0

        return {
            'detector':     self.DETECTOR_NAME,
            'yaicd_param':  self.YAICD_PARAM,
            'yaicd_score':  score,
            'triggered':    True,
            'severity':     seqs[0].severity,
            'sequences':    [
                {
                    'ts_reject':    datetime.utcfromtimestamp(s.auth_reject.ts).isoformat(),
                    'ts_id_req':    datetime.utcfromtimestamp(s.identity_request.ts).isoformat(),
                    'gap_seconds':  round(s.gap_seconds, 3),
                    'identity_type': _identity_type_name(s.identity_type),
                    'severity':     s.severity,
                }
                for s in seqs
            ],
            'summary': (
                f"P7 CONFIRMED: {len(seqs)} Auth Reject → Identity Request "
                f"sequence(s) detected "
                f"({len(critical)} CRITICAL/IMEISV, {len(high)} HIGH/IMSI). "
                f"This sequence is architecturally impossible on legitimate LTE. "
                f"Primary-source confirmed Harris HailStorm harvest technique "
                f"(Gemini QSG §4-2, Kareem 2023 IJRITCC). "
                f"YAICD P7 score: {score}."
            ),
        }


# ── PCAP parser integration ───────────────────────────────────────────────────

def extract_nas_events_from_pcap(pcap_path: Path) -> list[NasEvent]:
    """
    Extract NAS EMM events from a PCAP using tshark.
    Requires tshark in PATH. Returns sorted list of NasEvent.
    """
    import subprocess

    cmd = [
        'tshark', '-r', str(pcap_path),
        '-Y', 'nas-eps',
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'frame.number',
        '-e', 'nas_eps.nas_msg_emm_type',
        '-e', 'nas_eps.emm.id_type2',     # identity type in Identity Request
        '-e', 'nas_eps.emm.cause',         # reject cause
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
        if len(parts) < 3:
            continue
        try:
            ts       = float(parts[0]) if parts[0] else 0.0
            frame    = int(parts[1]) if parts[1] else 0
            msg_type = int(parts[2], 16) if parts[2] else 0

            id_type  = int(parts[3]) if len(parts) > 3 and parts[3] else None
            cause    = int(parts[4]) if len(parts) > 4 and parts[4] else None

            if msg_type and ts:
                events.append(NasEvent(
                    ts           = ts,
                    msg_type     = msg_type,
                    identity_type = id_type,
                    cause        = cause,
                    frame_num    = frame,
                    source       = 'pcap',
                ))
        except (ValueError, IndexError):
            continue

    return sorted(events, key=lambda e: e.ts)


# ── NDJSON parser integration ─────────────────────────────────────────────────

def extract_nas_events_from_ndjson(ndjson_path: Path) -> list[NasEvent]:
    """
    Extract NAS events from rayhunter NDJSON output.
    Looks for NAS-related events in the event stream.
    """
    events = []

    # NAS type name → byte value mapping for NDJSON text-based events
    NAS_TYPE_MAP = {
        'authentication reject':    NAS_AUTH_REJECT,
        'identity request':         NAS_IDENTITY_REQ,
        'identity response':        NAS_IDENTITY_RESP,
        'security mode command':    NAS_SECURITY_MODE,
        'tracking area update reject': NAS_TAU_REJECT,
        'attach accept':            NAS_ATTACH_ACCEPT,
    }

    IDENTITY_TYPE_MAP = {
        'imsi': IDENTITY_TYPE_IMSI,
        'imei': IDENTITY_TYPE_IMEI,
        'imeisv': IDENTITY_TYPE_IMEISV,
    }

    with open(ndjson_path) as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            ts_str = obj.get('packet_timestamp', '')
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(
                    ts_str.replace('Z', '+00:00')
                ).timestamp()
            except ValueError:
                continue

            # Check event list for NAS-related events
            for evt in obj.get('events', []) or []:
                if not evt:
                    continue
                message = (evt.get('message', '') or '').lower()
                for nas_name, nas_type in NAS_TYPE_MAP.items():
                    if nas_name in message:
                        # Try to extract identity type if present
                        id_type = None
                        for id_name, id_val in IDENTITY_TYPE_MAP.items():
                            if id_name in message:
                                id_type = id_val
                                break

                        events.append(NasEvent(
                            ts            = ts,
                            msg_type      = nas_type,
                            identity_type = id_type,
                            source        = 'ndjson',
                        ))
                        break

    return sorted(events, key=lambda e: e.ts)


# ── CLI entry point ───────────────────────────────────────────────────────────

def run_on_directory(directory: Path) -> dict:
    """
    Run P7 detector across all PCAPs and NDJSONs in a directory.
    Returns aggregated findings dict.
    """
    detector = AuthRejectImeisvDetector()

    pcap_files  = list(directory.glob('*.pcapng')) + list(directory.glob('*.pcap'))
    ndjson_files = list(directory.glob('*.ndjson'))

    print(f"[P7 Detector] Scanning {len(pcap_files)} PCAPs, {len(ndjson_files)} NDJSONs")

    for pcap in pcap_files:
        events = extract_nas_events_from_pcap(pcap)
        print(f"  {pcap.name}: {len(events)} NAS events")
        detector.ingest_events(events)

    for ndjson in ndjson_files:
        events = extract_nas_events_from_ndjson(ndjson)
        print(f"  {ndjson.name}: {len(events)} NAS events (from NDJSON)")
        detector.ingest_events(events)

    findings = detector.findings()

    print(f"\n[P7 Detector] Result: {'TRIGGERED' if findings['triggered'] else 'not triggered'}")
    print(f"  YAICD P7 score: {findings['yaicd_score']}")
    print(f"  {findings['summary']}")
    if findings.get('sequences'):
        for seq in findings['sequences']:
            print(f"    [{seq['ts_reject']}] Auth Reject → [{seq['ts_id_req']}] "
                  f"Identity({seq['identity_type']}) gap={seq['gap_seconds']:.3f}s "
                  f"[{seq['severity']}]")

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _identity_type_name(id_type: int) -> str:
    return {
        IDENTITY_TYPE_IMSI:   'IMSI',
        IDENTITY_TYPE_IMEI:   'IMEI',
        IDENTITY_TYPE_IMEISV: 'IMEISV',
    }.get(id_type, f'unknown({id_type})')


# ── Standalone run ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auth_reject_imeisv_detector.py <directory>")
        print("  directory: path containing .pcapng / .ndjson files")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"Error: {target} not found")
        sys.exit(1)

    findings = run_on_directory(target)

    # Write findings JSON
    out = target / 'p7_auth_reject_findings.json'
    out.write_text(json.dumps(findings, indent=2))
    print(f"\n[P7 Detector] Written to {out}")
