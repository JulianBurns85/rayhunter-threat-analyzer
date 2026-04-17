#!/usr/bin/env python3
"""
PCAP Parser — GSMTAP/NAS/RRC Event Extractor
=============================================
FIX v1.3:
  - pyshark runs in a dedicated thread with its own asyncio event loop.
    Fixes "no running event loop" on Windows Python 3.10+.
  - Basic parser detects PCAPNG and warns instead of silently producing
    garbage 1970 timestamps (PCAPNG != PCAP structure).
  - Timestamp anchor uses filename Unix timestamp (Rayhunter convention)
    before falling back to file mtime.
  - MNC/MCC propagated from inferred network on all events.
  - NAS detection uses proper 0x07 EPS-MM PD header to avoid false positives.
"""

from pathlib import Path
from typing import List, Dict, Optional

GSMTAP_TYPE_UM        = 0x01
GSMTAP_TYPE_LTE_RRC   = 0x0d
GSMTAP_TYPE_LTE_NAS   = 0x0e
GSMTAP_TYPE_ABIS      = 0x02

GSMTAP_TYPE_NAMES = {
    GSMTAP_TYPE_UM:      "GSM Um",
    GSMTAP_TYPE_LTE_RRC: "LTE RRC",
    GSMTAP_TYPE_LTE_NAS: "LTE NAS",
    GSMTAP_TYPE_ABIS:    "GSM Abis",
}

# LTE NAS EMM message types (3GPP TS 24.301 Table 9.8.1)
NAS_EMM_MSG_TYPES = {
    0x41: "Attach Request",         0x42: "Attach Accept",
    0x43: "Attach Complete",        0x44: "Attach Reject",
    0x45: "Detach Request",         0x46: "Detach Accept",
    0x48: "TAU Request",            0x49: "TAU Accept",
    0x4A: "TAU Complete",           0x4B: "TAU Reject",
    0x52: "Authentication Request", 0x53: "Authentication Response",
    0x54: "Authentication Reject",
    0x55: "Identity Request",       0x56: "Identity Response",
    0x5C: "Security Mode Command",  0x5D: "Security Mode Complete",
    0x5E: "Security Mode Reject",
    0x60: "EMM Status",             0x61: "EMM Information",
}

MNC_CARRIER_MAP = {
    "01": "Telstra",  "001": "Telstra",
    "02": "Optus",    "002": "Optus",
    "03": "Vodafone", "003": "Vodafone",
    "04": "Vodafone", "004": "Vodafone",
}

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC  = b"\x0a\x0d\x0d\x0a"


class PcapParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mcc = cfg.get("network", {}).get("mcc", "505")
        self.mnc = cfg.get("network", {}).get("mnc", "001")
        self._inferred_mcc = None
        self._inferred_mnc = None
        self._inferred_carrier = None
        self._pyshark_available = self._check_pyshark()

    def set_inferred_network(self, mcc: str, mnc: str):
        """Set network identity inferred from companion NDJSON. Call before parse()."""
        self._inferred_mcc = mcc
        self._inferred_mnc = mnc
        self._inferred_carrier = MNC_CARRIER_MAP.get(mnc, f"MNC={mnc}")

    def _effective_mnc(self) -> str:
        return self._inferred_mnc or self.mnc

    def _effective_mcc(self) -> str:
        return self._inferred_mcc or self.mcc

    def _check_pyshark(self) -> bool:
        try:
            import pyshark
            return True
        except ImportError:
            return False

    def parse(self, filepath: str) -> List[Dict]:
        if self._pyshark_available:
            return self._parse_with_pyshark(filepath)
        print("    [WARN] pyshark not available — install: pip install pyshark")
        return self._parse_basic(filepath)

    def _parse_with_pyshark(self, filepath: str) -> List[Dict]:
        """
        Parse using pyshark in a dedicated thread.

        Running pyshark in its own thread with its own asyncio event loop
        fixes the "no running event loop" error on Windows Python 3.10+.
        Without this, pyshark fails and falls back to the basic parser which
        cannot handle PCAPNG files, producing garbage 1970 timestamps.
        """
        import threading

        result_holder = {"events": [], "error": None}

        def _worker():
            import asyncio
            import sys
            if sys.platform == "win32":
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except AttributeError:
                    pass
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                import pyshark
                cap = pyshark.FileCapture(
                    filepath,
                    display_filter="gsmtap or nas-eps or lte-rrc or gsm_a",
                    use_json=True,
                    include_raw=False,
                )
                cap.load_packets(timeout=60)
                for pkt_idx, pkt in enumerate(cap):
                    try:
                        ev = self._extract_pyshark_event(pkt, filepath, pkt_idx)
                        if ev:
                            result_holder["events"].append(ev)
                    except Exception:
                        pass
                try:
                    cap.close()
                except Exception:
                    pass
            except Exception as e:
                result_holder["error"] = str(e)
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=90)

        if thread.is_alive():
            print(f"    [WARN] pyshark timed out on {Path(filepath).name} — using basic parser.")
            return self._parse_basic(filepath)

        if result_holder["error"] and not result_holder["events"]:
            print(f"    [WARN] pyshark failed on {Path(filepath).name}: "
                  f"{result_holder['error'][:120]}")
            return self._parse_basic(filepath)

        events = result_holder["events"]

        # Boot-relative timestamp correction for pyshark output
        from datetime import datetime, timezone
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
                first_ts = min(ts_values)
                ts_offset = self._compute_ts_offset(filepath, first_ts)
                if ts_offset:
                    print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                          f"— correcting (offset +{ts_offset:.0f}s)")
                    for ev in events:
                        try:
                            ts_str = ev.get("timestamp", "")
                            if ts_str and ts_str != "None":
                                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                ev["timestamp"] = datetime.fromtimestamp(
                                    dt.timestamp() + ts_offset, tz=timezone.utc
                                ).isoformat()
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
            "mcc": self._effective_mcc(),
            "mnc": self._effective_mnc(),
            "carrier": self._inferred_carrier,
        }

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

        if gsmtap_type not in (GSMTAP_TYPE_LTE_RRC, GSMTAP_TYPE_LTE_NAS,
                                GSMTAP_TYPE_UM, None):
            return None

        if hasattr(pkt, "nas_eps"):
            nas = pkt.nas_eps
            ev["layer"] = "NAS"
            msg_type = (getattr(nas, "nas_eps_nas_msg_emm_type", None) or
                        getattr(nas, "msg_type", None))
            if msg_type:
                ev["msg_type"] = str(msg_type)
            cipher = (getattr(nas, "nas_eps_emm_toc", None) or
                      getattr(nas, "nas_eps_emm_nas_cipher_alg", None))
            if cipher:
                ev["cipher_alg"] = ("EEA0" if "eea0" in str(cipher).lower()
                                    or str(cipher) == "0" else str(cipher))
            integrity = (getattr(nas, "nas_eps_emm_toi", None) or
                         getattr(nas, "nas_eps_emm_nas_int_alg", None))
            if integrity:
                ev["integrity_alg"] = ("EIA0" if "eia0" in str(integrity).lower()
                                       or str(integrity) == "0" else str(integrity))
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

        if hasattr(pkt, "lte_rrc"):
            rrc = pkt.lte_rrc
            ev["layer"] = ev.get("layer", "RRC") or "RRC"
            for attr in dir(rrc):
                for kw, human in {
                    "rrcconnectionrelease": "RRC Connection Release",
                    "rrcconnectionreconfiguration": "RRC Connection Reconfiguration",
                    "measurementreport": "Measurement Report",
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
            ev.get("msg_type"), ev.get("cipher_alg"), ev.get("identity_type"),
            ev.get("has_mobility_control"), ev.get("has_geran_redirect"), ev.get("has_prose"),
        ])
        return ev if has_data else None

    def _parse_basic(self, filepath: str) -> List[Dict]:
        """
        Minimal fallback PCAP parser (classic PCAP format only, not PCAPNG).

        PCAPNG files (magic 0x0a0d0d0a) have a completely different block
        structure. Attempting to parse PCAPNG as PCAP produces garbage
        timestamps (typically 1970 dates from misread block lengths).
        This parser detects PCAPNG and returns an empty list with a clear
        warning rather than producing misleading output.
        """
        import struct
        import os
        from datetime import datetime, timezone

        events = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"    [ERROR] Cannot read {filepath}: {e}")
            return events

        magic = data[:4]

        if magic == PCAPNG_MAGIC:
            print(f"    [WARN] {Path(filepath).name} is PCAPNG — basic parser "
                  f"requires classic PCAP. Install tshark + pyshark for PCAPNG support.")
            return events

        if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            print(f"    [WARN] {Path(filepath).name}: unknown format (magic: {magic.hex()})")
            return events

        byte_order = "<" if magic == PCAP_MAGIC_LE else ">"

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

        YEAR_2000_TS = 946684800
        max_ts_sec = max(p[0] for p in raw_packets)
        ts_offset = 0.0

        if max_ts_sec < YEAR_2000_TS:
            first_ts = raw_packets[0][0] + raw_packets[0][1] / 1e6
            ts_offset = self._compute_ts_offset(filepath, first_ts)
            if ts_offset:
                print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                      f"— correcting (offset +{ts_offset:.0f}s)")

        for pkt_idx, (ts_sec, ts_usec, pkt_data) in enumerate(raw_packets):
            if b"\x12\x79" in pkt_data or b"\x79\x12" in pkt_data:
                corrected_ts = ts_sec + ts_usec / 1e6 + ts_offset
                ev = self._extract_gsmtap_basic(pkt_data, filepath, pkt_idx, corrected_ts)
                if ev:
                    events.append(ev)

        return events

    def _compute_ts_offset(self, filepath: str, first_packet_ts: float) -> float:
        """
        Compute boot-relative timestamp correction offset.

        Priority:
        1. Rayhunter filename convention: "1776338000.pcapng" contains a
           10-digit Unix timestamp = session start time. Anchors first packet.
        2. Filesystem mtime as fallback.
        """
        import re
        import os

        stem = Path(filepath).stem
        stem_clean = re.sub(r'\s*\(\d+\)\s*', '', stem)
        stem_clean = stem_clean.replace('_converted', '').strip()

        # 10-digit timestamps starting with 17 = ~2025-2033
        ts_match = re.search(r'\b(17\d{8})\b', stem_clean)
        if ts_match:
            return float(ts_match.group(1)) - first_packet_ts

        try:
            mtime = os.path.getmtime(filepath)
            if mtime > 946684800:
                return mtime - first_packet_ts
        except Exception:
            pass

        return 0.0

    def _extract_gsmtap_basic(self, pkt_data: bytes, source: str,
                               idx: int, ts: float) -> Optional[Dict]:
        """Extract NAS events from raw PCAP bytes using proper LTE NAS header context."""
        from datetime import datetime, timezone

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
        payload_offset = gsmtap_hdr[1] * 4
        payload = gsmtap_hdr[payload_offset:] if len(gsmtap_hdr) > payload_offset else b""

        if not payload or len(payload) < 2:
            return None

        # LTE NAS EMM plain header: byte 0 = 0x07 (EPS-MM PD, no security)
        msg_type_name = None
        identity_type = None
        cipher_alg = None
        integrity_alg = None

        for i in range(len(payload) - 1):
            if payload[i] != 0x07:
                continue
            byte1 = payload[i + 1]
            if byte1 not in NAS_EMM_MSG_TYPES:
                continue
            msg_type_name = NAS_EMM_MSG_TYPES[byte1]
            if byte1 == 0x55 and i + 2 < len(payload):
                id_byte = payload[i + 2] & 0x07
                identity_type = {1: "IMSI", 2: "IMEI/IMEISV", 3: "IMEI/IMEISV",
                                  4: "TMSI", 5: "TMSI"}.get(id_byte, f"TYPE_{id_byte}")
            elif byte1 == 0x5C and i + 2 < len(payload):
                alg_byte = payload[i + 2]
                eea = alg_byte & 0x07
                eia = (alg_byte >> 4) & 0x07
                cipher_alg    = f"EEA{eea}" if eea else "EEA0"
                integrity_alg = f"EIA{eia}" if eia else "EIA0"
            break

        if not msg_type_name:
            return None

        ev = {
            "source_file": Path(source).name,
            "source_type": "pcap",
            "line": idx,
            "timestamp": str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "raw": {},
            "layer": GSMTAP_TYPE_NAMES.get(gsmtap_type, f"GSMTAP_{gsmtap_type:02x}"),
            "gsmtap_type": gsmtap_type,
            "mcc": self._effective_mcc(),
            "mnc": self._effective_mnc(),
            "carrier": self._inferred_carrier,
            "msg_type": msg_type_name,
        }
        if identity_type:
            ev["identity_type"] = identity_type
        if cipher_alg:
            ev["cipher_alg"] = cipher_alg
        if integrity_alg:
            ev["integrity_alg"] = integrity_alg

        return ev
