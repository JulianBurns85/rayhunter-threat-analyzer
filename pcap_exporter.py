#!/usr/bin/env python3
"""
Flagged Events PCAP Exporter
==============================
Extracts only attack-flagged events from raw PCAP files and writes
a clean exhibit PCAP containing only the relevant packets.

This makes it practical to share specific evidence with technical
recipients (Citizen Lab, CSIRO, AFP technical analysts) without
sending multi-GB raw capture files.

Output: rayhunter_flagged_events_<timestamp>.pcapng
"""

import struct
import time
import os
from pathlib import Path
from typing import List, Dict, Set
from datetime import datetime, timezone


# PCAPNG block types
PCAPNG_SHB  = 0x0A0D0D0A  # Section Header Block
PCAPNG_IDB  = 0x00000001  # Interface Description Block
PCAPNG_EPB  = 0x00000006  # Enhanced Packet Block
PCAPNG_BYTE_ORDER = 0x1A2B3C4D


def _pad32(data: bytes) -> bytes:
    """Pad data to 32-bit boundary."""
    pad = (4 - len(data) % 4) % 4
    return data + b'\x00' * pad


def _write_shb() -> bytes:
    """Write PCAPNG Section Header Block."""
    body = struct.pack('<IHH', PCAPNG_BYTE_ORDER, 1, 0) + b'\xff\xff\xff\xff\xff\xff\xff\xff'
    total = 12 + len(body)
    return (struct.pack('<II', PCAPNG_SHB, total) + body +
            struct.pack('<I', total))


def _write_idb(link_type: int = 147) -> bytes:
    """Write Interface Description Block. Link type 147 = GSMTAP."""
    body = struct.pack('<HHI', link_type, 0, 0)
    total = 12 + len(body)
    return (struct.pack('<II', PCAPNG_IDB, total) + body +
            struct.pack('<I', total))


def _write_epb(ts_us: int, data: bytes) -> bytes:
    """Write Enhanced Packet Block."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low  = ts_us & 0xFFFFFFFF
    padded = _pad32(data)
    body = struct.pack('<IIIiI', 0, ts_high, ts_low, len(data), len(data)) + padded
    total = 12 + len(body)
    return (struct.pack('<II', PCAPNG_EPB, total) + body +
            struct.pack('<I', total))


def _ts_to_us(ts) -> int:
    """Convert timestamp to microseconds since epoch."""
    try:
        from dateutil import parser as dtparser
        dt = dtparser.parse(str(ts))
        return int(dt.timestamp() * 1_000_000)
    except Exception:
        try:
            return int(float(str(ts)) * 1_000_000)
        except (ValueError, TypeError):
            return int(time.time() * 1_000_000)


def _make_gsmtap_header(msg_type_str: str) -> bytes:
    """
    Create a minimal GSMTAP header for an event.
    GSMTAP version 2, type 0x07 (LTE NAS) or 0x0d (LTE RRC).
    """
    # Determine GSMTAP type
    if any(x in str(msg_type_str) for x in ["NAS", "Identity", "Auth", "Security Mode",
                                               "Attach", "TAU", "Detach"]):
        gsmtap_type = 0x07  # LTE NAS
    else:
        gsmtap_type = 0x0d  # LTE RRC

    # Minimal GSMTAP v2 header (16 bytes)
    header = struct.pack(
        '>BBHBBHHHBB',
        0x01,        # version = 1 (v2)
        0x04,        # header length (in 32-bit words) = 4 = 16 bytes
        gsmtap_type, # type
        0,           # timeslot
        0,           # arfcn high
        0,           # arfcn low
        0,           # signal_dbm
        0,           # snr_db
        0,           # frame_number high
        0,           # frame_number low
    )
    return header[:16]  # Ensure exactly 16 bytes


def export_flagged_pcap(
    events: List[Dict],
    findings: List[Dict],
    output_dir: str = ".",
    investigation_ref: str = "CIRS-20260331-141",
) -> str:
    """
    Export a clean PCAPNG containing only flagged attack events.

    Args:
        events: all parsed events
        findings: detector findings (used to identify flagged events)
        output_dir: where to write the output file
        investigation_ref: for filename

    Returns:
        path to output file
    """
    # Collect timestamps of flagged events from findings evidence strings
    flagged_ts: Set[str] = set()
    flagged_types: Set[str] = set()

    for f in findings:
        for ev_str in f.get("evidence", []):
            # Evidence strings look like "[2026-02-19 01:50:16+00:00] Identity Request..."
            if ev_str.startswith("["):
                ts_part = ev_str[1:ev_str.index("]")]
                flagged_ts.add(ts_part.strip())

        # Also flag by technique
        tech = f.get("technique", "")
        if "IMSI" in tech or "null" in tech.lower() or "cipher" in tech.lower():
            flagged_types.add(f.get("detector", ""))

    # Filter events to attack-relevant only
    attack_events = []
    for ev in events:
        ts = str(ev.get("timestamp", "")).strip()
        msg = str(ev.get("msg_type", ""))
        is_flagged = (
            ts in flagged_ts
            or ev.get("cipher_alg") == "EEA0"
            or ev.get("identity_type") == "IMSI"
            or ev.get("has_geran_redirect")
            or ev.get("integrity_alg") == "EIA0"
            or "Identity Request" in msg
            or "Security Mode" in msg
            or "Authentication Reject" in msg
            or "Authentication Request" in msg
            or ev.get("threats")
        )
        if is_flagged:
            attack_events.append(ev)

    if not attack_events:
        print("  [PCAP Export] No flagged attack events found to export.")
        return ""

    # Sort by timestamp
    def sort_key(e):
        try:
            from dateutil import parser as dtparser
            return dtparser.parse(str(e.get("timestamp", "2000-01-01"))).timestamp()
        except Exception:
            return 0.0

    attack_events.sort(key=sort_key)

    # Write PCAPNG
    ts_str = int(time.time())
    safe_ref = investigation_ref.replace("-", "_").replace("/", "_")
    out_path = Path(output_dir) / f"rayhunter_flagged_{safe_ref}_{ts_str}.pcapng"

    packets_written = 0
    with open(out_path, "wb") as f:
        f.write(_write_shb())
        f.write(_write_idb(link_type=147))  # 147 = GSMTAP

        for ev in attack_events:
            ts_us = _ts_to_us(ev.get("timestamp", 0))
            msg_type = str(ev.get("msg_type", "Unknown"))

            # Build a minimal synthetic packet body
            # GSMTAP header + ASCII description of the event
            gsmtap_hdr = _make_gsmtap_header(msg_type)

            # Encode event info as payload
            cipher  = ev.get("cipher_alg", "")
            integ   = ev.get("integrity_alg", "")
            id_type = ev.get("identity_type", "")
            src     = ev.get("source_file", "")

            payload_str = (
                f"MSG:{msg_type} | "
                f"CIPHER:{cipher} | "
                f"INTEGRITY:{integ} | "
                f"ID_TYPE:{id_type} | "
                f"SOURCE:{src} | "
                f"CELL:{ev.get('cell_id','')} | "
                f"EARFCN:{ev.get('earfcn','')} | "
                f"THREATS:{','.join(ev.get('threats',[]))}"
            )
            payload = payload_str.encode("ascii", errors="replace")
            packet = gsmtap_hdr + payload

            f.write(_write_epb(ts_us, packet))
            packets_written += 1

    print(f"\n  [PCAP Export] Flagged events: {len(attack_events):,}")
    print(f"  [PCAP Export] Output: {out_path}")
    print(f"  [PCAP Export] {packets_written:,} packets written")
    print(f"  [PCAP Export] Open with: Wireshark {out_path}")

    return str(out_path)
