#!/usr/bin/env python3
"""
PCAP Parser — GSMTAP/NAS/RRC Event Extractor
=============================================
Parses PCAP/PCAPNG files containing GSMTAP-encapsulated LTE traffic
(type 0x0d = LTE RRC, type 0x01 = GSM Um).

Falls back to raw packet inspection if pyshark is unavailable.

Requires: pyshark (which requires Wireshark/tshark to be installed)
Install:  pip install pyshark
Wireshark: apt install tshark  OR  brew install wireshark
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Any

# GSMTAP type constants
GSMTAP_TYPE_UM        = 0x01   # GSM Um
GSMTAP_TYPE_LTE_RRC   = 0x0d   # LTE RRC
GSMTAP_TYPE_LTE_NAS   = 0x0e   # LTE NAS
GSMTAP_TYPE_ABIS      = 0x02   # GSM Abis
GSMTAP_TYPE_UM_BURST  = 0x03   # GSM burst

GSMTAP_TYPE_NAMES = {
    GSMTAP_TYPE_UM:      "GSM Um",
    GSMTAP_TYPE_LTE_RRC: "LTE RRC",
    GSMTAP_TYPE_LTE_NAS: "LTE NAS",
    GSMTAP_TYPE_ABIS:    "GSM Abis",
}

# NAS message types of interest
SUSPICIOUS_NAS_TYPES = {
    "Identity Request",
    "Security Mode Command",
    "Authentication Reject",
    "Attach Reject",
    "Tracking Area Update Reject",
}

RRC_TYPES_OF_INTEREST = {
    "rrcConnectionRelease",
    "rrcConnectionReconfiguration",
    "measurementReport",
    "mobilityFromEUTRACommand",
    "handoverFromEUTRAPreparationRequest",
    "paging",
}


class PcapParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mcc = cfg.get("network", {}).get("mcc", "505")
        self.mnc = cfg.get("network", {}).get("mnc", "001")
        self._pyshark_available = self._check_pyshark()

    def _check_pyshark(self) -> bool:
        try:
            import pyshark
            return True
        except ImportError:
            return False

    def _ensure_event_loop(self):
        """Create asyncio event loop — fix for Python 3.10+/Windows pyshark."""
        import asyncio
        import sys
        try:
            # On Windows, pyshark requires SelectorEventLoop (not ProactorEventLoop default)
            if sys.platform == "win32":
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except AttributeError:
                    pass
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("closed")
        except RuntimeError:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

    def parse(self, filepath: str) -> List[Dict]:
        """Parse PCAP file, return list of normalised events."""
        if self._pyshark_available:
            return self._parse_with_pyshark(filepath)
        else:
            print("    [WARN] pyshark not available — using basic PCAP parser.")
            return self._parse_basic(filepath)

    def _parse_with_pyshark(self, filepath: str) -> List[Dict]:
        """Full dissection using pyshark + Wireshark dissectors."""
        import pyshark
        events = []
        self._ensure_event_loop()

        try:
            cap = pyshark.FileCapture(
                filepath,
                display_filter="gsmtap or nas-eps or lte-rrc or gsm_a",
                use_json=True,
                include_raw=False,
            )
            cap.load_packets(timeout=60)
        except Exception as e:
            print(f"    [WARN] pyshark failed to open {filepath}: {e}")
            return self._parse_basic(filepath)

        for pkt_idx, pkt in enumerate(cap):
            try:
                ev = self._extract_pyshark_event(pkt, filepath, pkt_idx)
                if ev:
                    events.append(ev)
            except Exception:
                pass

        try:
            cap.close()
        except Exception:
            pass

        return events

    def _extract_pyshark_event(self, pkt, source_file: str, pkt_idx: int) -> Optional[Dict]:
        """Extract a normalised event from a pyshark packet."""
        ev = {
            "source_file": Path(source_file).name,
            "source_type": "pcap",
            "line": pkt_idx,
            "timestamp": str(getattr(pkt, "sniff_time", None)),
            "raw": {},
        }

        # ── GSMTAP layer ─────────────────────────────────────────────
        gsmtap_type = None
        if hasattr(pkt, "gsmtap"):
            gt = pkt.gsmtap
            try:
                gsmtap_type = int(getattr(gt, "type", 0), 16)
            except (ValueError, TypeError):
                try:
                    gsmtap_type = int(getattr(gt, "type", 0))
                except (ValueError, TypeError):
                    pass
            ev["gsmtap_type"] = GSMTAP_TYPE_NAMES.get(gsmtap_type, str(gsmtap_type))

            try:
                ev["earfcn"] = int(getattr(gt, "arfcn", 0))
            except (ValueError, TypeError):
                ev["earfcn"] = None

        # Only process LTE RRC (0x0d), LTE NAS (0x0e), GSM (0x01)
        if gsmtap_type not in (GSMTAP_TYPE_LTE_RRC, GSMTAP_TYPE_LTE_NAS, GSMTAP_TYPE_UM, None):
            return None

        # ── LTE NAS layer ─────────────────────────────────────────────
        if hasattr(pkt, "nas_eps"):
            nas = pkt.nas_eps
            ev["layer"] = "NAS"
            msg_type = getattr(nas, "nas_eps_nas_msg_emm_type", None) or \
                       getattr(nas, "msg_type", None)
            if msg_type:
                ev["msg_type"] = str(msg_type)

            # Cipher algorithm
            cipher = getattr(nas, "nas_eps_emm_toc", None) or \
                     getattr(nas, "nas_eps_emm_nas_cipher_alg", None)
            if cipher:
                cipher_str = str(cipher).lower()
                if "eea0" in cipher_str or cipher_str == "0":
                    ev["cipher_alg"] = "EEA0"
                else:
                    ev["cipher_alg"] = str(cipher)

            # Integrity algorithm
            integrity = getattr(nas, "nas_eps_emm_toi", None) or \
                        getattr(nas, "nas_eps_emm_nas_int_alg", None)
            if integrity:
                int_str = str(integrity).lower()
                if "eia0" in int_str or int_str == "0":
                    ev["integrity_alg"] = "EIA0"
                else:
                    ev["integrity_alg"] = str(integrity)

            # Identity type
            id_type = getattr(nas, "nas_eps_emm_type_of_id", None)
            if id_type:
                id_str = str(id_type).lower()
                if "imsi" in id_str or id_str == "1":
                    ev["identity_type"] = "IMSI"
                elif "imei" in id_str or id_str in ("2", "3"):
                    ev["identity_type"] = "IMEI/IMEISV"
                elif "tmsi" in id_str or id_str == "4":
                    ev["identity_type"] = "TMSI"

            # Paging type
            if "paging" in str(ev.get("msg_type", "")).lower():
                paging_id = getattr(nas, "nas_eps_emm_paging_id", "")
                ev["paging_type"] = "IMSI" if "imsi" in str(paging_id).lower() else "S-TMSI"

        # ── LTE RRC layer ─────────────────────────────────────────────
        if hasattr(pkt, "lte_rrc"):
            rrc = pkt.lte_rrc
            ev["layer"] = ev.get("layer", "RRC") or "RRC"

            # Message type
            for attr in dir(rrc):
                for kw, human in {
                    "rrcconnectionrelease": "RRC Connection Release",
                    "rrcconnectionreconfiguration": "RRC Connection Reconfiguration",
                    "measurementreport": "Measurement Report",
                    "mobilityfromeUTRACommand": "Mobility From EUTRA",
                    "paging": "Paging",
                }.items():
                    if kw in attr.lower():
                        ev["msg_type"] = ev.get("msg_type") or human

            # Handover / redirect markers
            rrc_str = str(dir(rrc)).lower()
            ev["has_mobility_control"] = "mobilitycontrolinfo" in rrc_str
            ev["has_geran_redirect"]   = "geran" in rrc_str or "redirectedcarrier" in rrc_str
            ev["has_measreport"]       = "measurementreport" in rrc_str
            ev["has_prose"]            = "proximityconfig" in rrc_str

            # Cell / frequency info
            try:
                ev["pci"] = int(getattr(rrc, "lte_rrc_physCellId", 0))
            except (ValueError, TypeError):
                pass

        # ── Filter: only return events with substance ─────────────────
        has_data = any([
            ev.get("msg_type"),
            ev.get("cipher_alg"),
            ev.get("identity_type"),
            ev.get("has_mobility_control"),
            ev.get("has_geran_redirect"),
            ev.get("has_prose"),
        ])

        return ev if has_data else None

    def _parse_basic(self, filepath: str) -> List[Dict]:
        """
        Minimal PCAP parser that reads raw packets without Wireshark.
        Detects GSMTAP frame type and flags suspicious byte patterns.
        No full dissection — use only as fallback.

        Timestamp correction: Rayhunter on Android sometimes stores
        boot-relative timestamps (seconds since device boot) rather than
        wall-clock UTC. These appear as 1970-01-0x dates. We detect this
        by checking if the max ts_sec is below a plausibility threshold
        (before year 2000 = Unix ts < 946684800). If so, we anchor the
        final packet to the file's mtime and reconstruct absolute times
        for all packets by preserving their relative spacing.
        """
        import struct
        import os

        events = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"    [ERROR] Cannot read {filepath}: {e}")
            return events

        # Detect PCAP magic
        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                             b"\x0a\x0d\x0d\x0a"):
            print(f"    [WARN] {Path(filepath).name}: not a valid PCAP file")
            return events

        byte_order = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"

        # ── Pass 1: collect all packets with GSMTAP content ──────────
        raw_packets = []  # list of (ts_sec, ts_usec, pkt_data)
        pos = 24  # skip global PCAP header

        while pos + 16 < len(data):
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                    f"{byte_order}IIII", data, pos
                )
                pos += 16
                pkt_data = data[pos:pos + incl_len]
                pos += incl_len
                raw_packets.append((ts_sec, ts_usec, pkt_data))
            except struct.error:
                break

        if not raw_packets:
            return events

        # ── Timestamp correction ──────────────────────────────────────
        # Threshold: if max ts_sec < year 2000 (946684800), timestamps
        # are boot-relative. Anchor last packet to file mtime.
        YEAR_2000_TS = 946684800
        max_ts_sec = max(p[0] for p in raw_packets)

        ts_offset = 0.0
        if max_ts_sec < YEAR_2000_TS:
            try:
                file_mtime = os.path.getmtime(filepath)
                max_relative = max_ts_sec + max(p[1] for p in raw_packets) / 1e6
                ts_offset = file_mtime - max_relative
                print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                      f"detected — anchoring to file mtime "
                      f"(offset +{ts_offset:.0f}s)")
            except Exception:
                pass

        # ── Pass 2: extract events with corrected timestamps ──────────
        for pkt_idx, (ts_sec, ts_usec, pkt_data) in enumerate(raw_packets):
            # Look for GSMTAP in UDP payload (port 4729 = 0x1279)
            if b"\x12\x79" in pkt_data or b"\x79\x12" in pkt_data:
                corrected_ts = ts_sec + ts_usec / 1e6 + ts_offset
                ev = self._extract_gsmtap_basic(
                    pkt_data, filepath, pkt_idx, corrected_ts
                )
                if ev:
                    events.append(ev)

        return events

    def _extract_gsmtap_basic(self, pkt_data: bytes, source: str,
                              idx: int, ts: float) -> Optional[Dict]:
        """Extract GSMTAP type and basic NAS markers from raw packet bytes."""
        from datetime import datetime, timezone

        # Find GSMTAP header after Ethernet + IP + UDP
        # GSMTAP starts with version=0x02
        gsmtap_start = None
        for i in range(len(pkt_data) - 4):
            if pkt_data[i] == 0x02 and pkt_data[i+1] in (0x04, 0x08):
                gsmtap_start = i
                break

        if gsmtap_start is None:
            return None

        gsmtap_hdr = pkt_data[gsmtap_start:]
        if len(gsmtap_hdr) < 4:
            return None

        gsmtap_type = gsmtap_hdr[2]
        payload = gsmtap_hdr[gsmtap_hdr[1] * 4:] if len(gsmtap_hdr) > gsmtap_hdr[1] * 4 else b""

        ev = {
            "source_file": Path(source).name,
            "source_type": "pcap",
            "line": idx,
            "timestamp": str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "raw": {},
            "layer": GSMTAP_TYPE_NAMES.get(gsmtap_type, f"GSMTAP_{gsmtap_type:02x}"),
            "gsmtap_type": gsmtap_type,
        }

        # Detect NAS message type bytes in payload
        # LTE NAS: Security Mode Command = 0x5C, Identity Request = 0x55
        if payload:
            if 0x55 in payload:
                ev["msg_type"] = "Identity Request"
                ev["identity_type"] = "IMSI"
            elif 0x5C in payload:
                ev["msg_type"] = "Security Mode Command"
                # Check for EEA0 (byte after command is usually cipher alg)
                idx_5c = payload.index(0x5C)
                if idx_5c + 2 < len(payload):
                    alg_byte = payload[idx_5c + 2]
                    if (alg_byte & 0x0F) == 0:
                        ev["cipher_alg"] = "EEA0"
                    if (alg_byte >> 4) == 0:
                        ev["integrity_alg"] = "EIA0"
            elif 0x54 in payload:
                ev["msg_type"] = "Authentication Reject"

        return ev if ev.get("msg_type") else None
