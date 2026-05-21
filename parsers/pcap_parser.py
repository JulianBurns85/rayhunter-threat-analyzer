#!/usr/bin/env python3
"""
PCAP Parser – GSMTAP/NAS/RRC Event Extractor
=============================================
Parses PCAP/PCAPNG files containing GSMTAP-encapsulated LTE traffic
(type 0x0d = LTE RRC, type 0x01 = GSM Um).

Falls back to raw packet inspection if pyshark is unavailable.

Requires: pyshark (which requires Wireshark/tshark to be installed)
Install:  pip install pyshark
Wireshark: apt install tshark  OR  brew install wireshark

Fix history:
  v2.2 (22 May 2026):
  - FIX: Removed false-positive cipher detection from _extract_gsmtap_basic.
    The raw byte scanner was triggering EEA0/EIA0 on coincidental bytes near
    0x5C in payloads — (alg_byte & 0x0F) == 0 is true for any byte with low
    nibble 0x0, causing false Security Mode Command findings in real data.
    Basic parser now only detects message type presence (requires NAS header
    discriminator 0x07 before msg byte). Cipher algorithm detection requires
    full pyshark dissection and is not attempted in the basic fallback parser.
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
        """Create asyncio event loop – fix for Python 3.10+/3.12+/Windows pyshark."""
        import asyncio
        import sys

        if sys.platform == "win32":
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            except AttributeError:
                pass

        try:
            asyncio.get_running_loop()
            return
        except RuntimeError:
            pass

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("loop is closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

    def parse(self, filepath: str) -> List[Dict]:
        """Parse PCAP file, return list of normalised events."""
        if self._pyshark_available:
            return self._parse_with_pyshark(filepath)
        else:
            print("    [WARN] pyshark not available – using basic PCAP parser.")
            return self._parse_basic(filepath)

    def _parse_with_pyshark(self, filepath: str) -> List[Dict]:
        """Full dissection using pyshark + Wireshark dissectors."""
        import pyshark
        import os
        from datetime import datetime, timezone
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

        # ── Timestamp validation ──────────────────────────────────────────────
        YEAR_2000_TS = 946684800.0
        if events:
            ts_values = []
            for ev in events:
                try:
                    ts_str = ev.get("timestamp", "")
                    if ts_str and ts_str != "None":
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        ts_values.append(dt.timestamp())
                except Exception:
                    pass

            if ts_values and max(ts_values) < YEAR_2000_TS:
                try:
                    file_mtime = os.path.getmtime(filepath)
                    max_rel = max(ts_values)
                    ts_offset = file_mtime - max_rel
                    print(f"    [INFO] {Path(filepath).name}: pyshark boot-relative "
                          f"timestamps detected – applying mtime offset +{ts_offset:.0f}s")
                    for ev in events:
                        try:
                            ts_str = ev.get("timestamp", "")
                            if ts_str and ts_str != "None":
                                dt = datetime.fromisoformat(
                                    ts_str.replace("Z", "+00:00"))
                                corrected = dt.timestamp() + ts_offset
                                ev["timestamp"] = datetime.fromtimestamp(
                                    corrected, tz=timezone.utc).isoformat()
                        except Exception:
                            pass
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

        # ── GSMTAP layer ───────────────────────────────────────────────────────
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

        if gsmtap_type not in (GSMTAP_TYPE_LTE_RRC, GSMTAP_TYPE_LTE_NAS, GSMTAP_TYPE_UM, None):
            return None

        # ── LTE NAS layer ──────────────────────────────────────────────────────
        if hasattr(pkt, "nas_eps"):
            nas = pkt.nas_eps
            ev["layer"] = "NAS"
            msg_type = getattr(nas, "nas_eps_nas_msg_emm_type", None) or \
                       getattr(nas, "msg_type", None)
            if msg_type:
                ev["msg_type"] = str(msg_type)

            cipher = getattr(nas, "nas_eps_emm_toc", None) or \
                     getattr(nas, "nas_eps_emm_nas_cipher_alg", None)
            if cipher:
                cipher_str = str(cipher).lower()
                if "eea0" in cipher_str or cipher_str == "0":
                    ev["cipher_alg"] = "EEA0"
                else:
                    ev["cipher_alg"] = str(cipher)

            integrity = getattr(nas, "nas_eps_emm_toi", None) or \
                        getattr(nas, "nas_eps_emm_nas_int_alg", None)
            if integrity:
                int_str = str(integrity).lower()
                if "eia0" in int_str or int_str == "0":
                    ev["integrity_alg"] = "EIA0"
                else:
                    ev["integrity_alg"] = str(integrity)

            id_type = getattr(nas, "nas_eps_emm_type_of_id", None)
            if id_type:
                id_str = str(id_type).lower()
                if "imsi" in id_str or id_str == "1":
                    ev["identity_type"] = "IMSI"
                elif "imei" in id_str or id_str in ("2", "3"):
                    ev["identity_type"] = "IMEI/IMEISV"
                elif "tmsi" in id_str or id_str == "4":
                    ev["identity_type"] = "TMSI"

            if "paging" in str(ev.get("msg_type", "")).lower():
                paging_id = getattr(nas, "nas_eps_emm_paging_id", "")
                ev["paging_type"] = "IMSI" if "imsi" in str(paging_id).lower() else "S-TMSI"

        # ── LTE RRC layer ──────────────────────────────────────────────────────
        if hasattr(pkt, "lte_rrc"):
            rrc = pkt.lte_rrc
            ev["layer"] = ev.get("layer", "RRC") or "RRC"

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

            rrc_str = str(dir(rrc)).lower()
            ev["has_mobility_control"] = "mobilitycontrolinfo" in rrc_str
            ev["has_geran_redirect"]   = "geran" in rrc_str or "redirectedcarrier" in rrc_str
            ev["has_measreport"]       = "measurementreport" in rrc_str
            ev["has_prose"]            = "proximityconfig" in rrc_str

            try:
                ev["pci"] = int(getattr(rrc, "lte_rrc_physCellId", 0))
            except (ValueError, TypeError):
                pass

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
        No full dissection – use only as fallback.

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

        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                             b"\x0a\x0d\x0d\x0a"):
            print(f"    [WARN] {Path(filepath).name}: not a valid PCAP file")
            return events

        byte_order = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"

        # ── Pass 1: collect all packets ───────────────────────────────────────
        raw_packets = []
        pos = 24

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

        # ── Timestamp correction ──────────────────────────────────────────────
        YEAR_2000_TS = 946684800
        max_ts_sec = max(p[0] for p in raw_packets)

        ts_offset = 0.0
        if max_ts_sec < YEAR_2000_TS:
            try:
                file_mtime = os.path.getmtime(filepath)
                max_relative = max_ts_sec + max(p[1] for p in raw_packets) / 1e6
                ts_offset = file_mtime - max_relative
                print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                      f"detected – anchoring to file mtime "
                      f"(offset +{ts_offset:.0f}s)")
            except Exception:
                pass

        # ── Pass 2: extract events with corrected timestamps ──────────────────
        for pkt_idx, (ts_sec, ts_usec, pkt_data) in enumerate(raw_packets):
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
        """Extract GSMTAP type and basic NAS markers from raw packet bytes.

        FIX v2.2: Cipher algorithm detection removed from basic parser.
        The previous implementation used (alg_byte & 0x0F) == 0 and
        (alg_byte >> 4) == 0 to detect EEA0/EIA0 from raw bytes — these
        conditions are true for a large proportion of normal byte values,
        causing widespread false positive Security Mode Command findings.

        Cipher detection requires full NAS dissection (pyshark + Wireshark).
        The basic fallback parser only flags message type presence using the
        NAS EMM discriminator byte (0x07) as a validity check.
        """
        from datetime import datetime, timezone

        # Find GSMTAP header after Ethernet + IP + UDP
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

        # Detect NAS message type bytes in payload.
        # Require NAS EMM protocol discriminator (0x07) immediately before
        # the message type byte as a validity check to reduce false positives.
        #
        # FIX v2.2: No cipher_alg or integrity_alg detection here.
        # Raw byte scanning for EEA0/EIA0 is unreliable without full dissection.
        # Cipher detection only occurs via pyshark (_extract_pyshark_event).
        if payload:
            found_msg = False
            for i in range(len(payload) - 1):
                if payload[i] == 0x07:
                    next_byte = payload[i + 1]
                    if next_byte == 0x55:
                        ev["msg_type"] = "Identity Request"
                        ev["identity_type"] = "IMSI"
                        found_msg = True
                        break
                    elif next_byte == 0x5C:
                        ev["msg_type"] = "Security Mode Command"
                        # No cipher_alg set — cannot reliably decode from raw bytes
                        found_msg = True
                        break
                    elif next_byte == 0x54:
                        ev["msg_type"] = "Authentication Reject"
                        found_msg = True
                        break

        return ev if ev.get("msg_type") else None
