#!/usr/bin/env python3
"""
PCAP Parser - GSMTAP/NAS/RRC Event Extractor
=============================================
v3.3: Uses direct tshark subprocess instead of pyshark.
      pyshark 0.6 is incompatible with Python 3.14 asyncio.
      Falls back to _parse_basic if tshark not found in PATH.
"""

import os
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

GSMTAP_TYPE_UM       = 0x01
GSMTAP_TYPE_LTE_RRC  = 0x0d
GSMTAP_TYPE_LTE_NAS  = 0x0e
GSMTAP_TYPE_ABIS     = 0x02

GSMTAP_TYPE_NAMES = {
    GSMTAP_TYPE_UM:      "GSM Um",
    GSMTAP_TYPE_LTE_RRC: "LTE RRC",
    GSMTAP_TYPE_LTE_NAS: "LTE NAS",
    GSMTAP_TYPE_ABIS:    "GSM Abis",
}

SUSPICIOUS_NAS_TYPES = {
    "Identity Request", "Security Mode Command",
    "Authentication Reject", "Attach Reject",
    "Tracking Area Update Reject",
}

RRC_TYPES_OF_INTEREST = {
    "rrcConnectionRelease", "rrcConnectionReconfiguration",
    "measurementReport", "mobilityFromEUTRACommand",
    "handoverFromEUTRAPreparationRequest", "paging",
}

# tshark fields to extract
TSHARK_FIELDS = [
    ("frame.time_epoch",                    "ts_epoch"),
    ("_ws.col.Info",                        "col_info"),
    ("nas_eps.nas_msg_emm_type",            "nas_msg_type_raw"),
    ("nas_eps.emm.cause",                   "nas_cause"),
    ("nas_eps.emm.type_of_id",              "nas_id_type"),
    ("nas_eps.emm.EEA",                     "nas_eea"),
    ("nas_eps.emm.EIA",                     "nas_eia"),
    ("nas_eps.emm.paging_id",               "nas_paging_id"),
    ("lte_rrc.c1",                          "rrc_c1"),
    ("lte_rrc.physCellId",                  "rrc_pci"),
    ("lte_rrc.cellIdentity",                "rrc_cell_id"),
    ("lte_rrc.trackingAreaCode",            "rrc_tac"),
    ("lte_rrc.m_TMSI",                      "rrc_m_tmsi"),
    ("lte_rrc.pagingRecordList",            "rrc_paging_list"),
    ("lte_rrc.mobilityControlInfo_element", "rrc_mobility"),
    ("lte_rrc.geranCarrierList_element",    "rrc_geran"),
    ("lte_rrc.proximityConfig_r9_element",  "rrc_prose"),
]

NAS_EMM_TYPE_MAP = {
    "0x41": "Attach Request",        "0x42": "Attach Accept",
    "0x43": "Attach Complete",       "0x44": "Attach Reject",
    "0x45": "Detach Request",        "0x48": "Tracking Area Update Request",
    "0x49": "Tracking Area Update Accept", "0x4b": "Tracking Area Update Reject",
    "0x52": "GUTI Reallocation Command",   "0x54": "Authentication Request",
    "0x55": "Authentication Response",     "0x56": "Authentication Reject",
    "0x5c": "Identity Request",            "0x5d": "Identity Response",
    "0x5e": "Security Mode Command",       "0x5f": "Security Mode Complete",
    "0x60": "Security Mode Reject",        "0x65": "EMM Status",
    "0x69": "EMM Information",
}

NAS_ID_TYPE_MAP = {
    "1": "IMSI", "0x1": "IMSI",
    "2": "IMEI", "0x2": "IMEI",
    "3": "IMEISV", "0x3": "IMEISV",
    "4": "TMSI", "0x4": "TMSI",
}


class PcapParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._tshark = shutil.which("tshark")
        if not self._tshark:
            print("  [WARN] tshark not found in PATH - using basic fallback only")

    def parse(self, filepath: str) -> List[Dict]:
        if self._tshark:
            try:
                events = self._parse_tshark(filepath)
                if events:
                    return events
            except Exception as exc:
                print(f"    [WARN] tshark error in {Path(filepath).name}: {exc}")
        return self._parse_basic(filepath)

    def _parse_tshark(self, filepath: str) -> List[Dict]:
        field_args = []
        for field, _ in TSHARK_FIELDS:
            field_args += ["-e", field]

        cmd = [
            self._tshark, "-r", filepath,
            "-T", "fields",
            "-E", "separator=|",
            "-E", "quote=n",
            "-E", "occurrence=f",
        ] + field_args

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=120, errors="replace"
            )
        except subprocess.TimeoutExpired:
            print(f"    [WARN] tshark timed out on {Path(filepath).name}")
            return []

        if result.returncode not in (0, 1):
            return []

        ts_offset = self._compute_ts_offset(filepath, result.stdout)
        keys = [k for _, k in TSHARK_FIELDS]
        events = []

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            while len(parts) < len(keys):
                parts.append("")
            row = dict(zip(keys, parts))
            ev = self._build_event(row, filepath, ts_offset)
            if ev:
                events.append(ev)

        return events

    def _compute_ts_offset(self, filepath: str, output: str) -> float:
        YEAR_2000 = 946684800
        epochs = []
        for line in output.splitlines():
            parts = line.split("|")
            if parts and parts[0].strip():
                try:
                    epochs.append(float(parts[0].strip()))
                except ValueError:
                    pass
        if not epochs:
            return 0.0
        max_epoch = max(epochs)
        if max_epoch >= YEAR_2000:
            return 0.0
        try:
            mtime = os.path.getmtime(filepath)
            offset = mtime - max_epoch
            print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                  f"detected - anchoring to file mtime (offset +{offset:.0f}s)")
            return offset
        except Exception:
            return 0.0

    def _build_event(self, row: dict, filepath: str, ts_offset: float) -> Optional[Dict]:
        ts_raw = row.get("ts_epoch", "").strip()
        if not ts_raw:
            return None
        try:
            ts = float(ts_raw) + ts_offset
        except ValueError:
            return None

        ev: Dict = {
            "source_file": Path(filepath).name,
            "source_type": "pcap",
            "timestamp":   str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "ts_epoch":    ts,
            "raw":         {},
        }

        # NAS layer
        nas_raw = row.get("nas_msg_type_raw", "").strip().lower()
        if nas_raw:
            human = NAS_EMM_TYPE_MAP.get(nas_raw, "")
            if human:
                ev["msg_type"] = human
                ev["layer"]    = "NAS"

        id_raw = row.get("nas_id_type", "").strip().lower()
        if id_raw:
            ev["identity_type"] = NAS_ID_TYPE_MAP.get(id_raw, id_raw.upper())

        eea = row.get("nas_eea", "").strip()
        if eea:
            ev["cipher_alg"] = "EEA0" if eea in ("0", "0x0") else f"EEA{eea}"

        eia = row.get("nas_eia", "").strip()
        if eia:
            ev["integrity_alg"] = "EIA0" if eia in ("0", "0x0") else f"EIA{eia}"

        paging_id = row.get("nas_paging_id", "").strip()
        if paging_id:
            ev["paging_type"] = "IMSI" if "imsi" in paging_id.lower() else "S-TMSI"

        # RRC layer
        rrc_c1 = row.get("rrc_c1", "").strip()
        if rrc_c1:
            ev["layer"] = ev.get("layer", "RRC") or "RRC"
            rl = rrc_c1.lower()
            if "rrcconnectionrelease"          in rl: ev["msg_type"] = ev.get("msg_type") or "RRC Connection Release"
            elif "rrcconnectionreconfiguration" in rl: ev["msg_type"] = ev.get("msg_type") or "RRC Connection Reconfiguration"
            elif "measurementreport"            in rl: ev["msg_type"] = ev.get("msg_type") or "Measurement Report"
            elif "paging"                       in rl: ev["msg_type"] = ev.get("msg_type") or "Paging"
            elif "mobilityfromeut"              in rl: ev["msg_type"] = ev.get("msg_type") or "Mobility From EUTRA"

        # Cell fields
        cell_id_raw = row.get("rrc_cell_id", "").strip()
        if cell_id_raw:
            try:
                ev["cid"] = str(int(cell_id_raw.replace(" ", ""), 16) >> 4)
            except ValueError:
                ev["cid"] = cell_id_raw

        tac_raw = row.get("rrc_tac", "").strip()
        if tac_raw:
            try:
                ev["tac"] = str(int(tac_raw.replace(" ", ""), 16))
            except ValueError:
                ev["tac"] = tac_raw

        pci_raw = row.get("rrc_pci", "").strip()
        if pci_raw:
            try:
                ev["pci"] = int(pci_raw)
            except ValueError:
                pass

        m_tmsi = row.get("rrc_m_tmsi", "").strip()
        if m_tmsi:
            ev["m_tmsi"] = m_tmsi
            ev["msg"] = ev.get("msg", "") + f" m-TMSI: {m_tmsi}"

        ev["has_mobility_control"] = bool(row.get("rrc_mobility", "").strip())
        ev["has_geran_redirect"]   = bool(row.get("rrc_geran", "").strip())
        ev["has_prose"]            = bool(row.get("rrc_prose", "").strip())

        # col.Info fallback
        col = row.get("col_info", "").strip()
        if col and not ev.get("msg_type"):
            for t in SUSPICIOUS_NAS_TYPES:
                if t.lower() in col.lower():
                    ev["msg_type"] = t
                    break
            if not ev.get("msg_type"):
                for t in RRC_TYPES_OF_INTEREST:
                    if t.lower() in col.lower():
                        ev["msg_type"] = col[:80]
                        break

        has_data = any([
            ev.get("msg_type"), ev.get("cipher_alg"),
            ev.get("identity_type"), ev.get("has_mobility_control"),
            ev.get("has_geran_redirect"), ev.get("has_prose"),
            ev.get("m_tmsi"), ev.get("cid"),
        ])
        return ev if has_data else None

    # ------------------------------------------------------------------ #
    # Basic fallback (no tshark)
    # ------------------------------------------------------------------ #

    def _parse_basic(self, filepath: str) -> List[Dict]:
        events = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"    [ERROR] Cannot read {filepath}: {e}")
            return events

        # Accept both PCAP and PCAPNG magic bytes
        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                             b"\x0a\x0d\x0d\x0a"):
            print(f"    [WARN] {Path(filepath).name}: not a valid PCAP file")
            return events

        is_pcapng  = data[:4] == b"\x0a\x0d\x0d\x0a"
        byte_order = "<"  # default LE

        raw_packets = []

        if is_pcapng:
            # PCAPNG: walk blocks to find Enhanced Packet Blocks (type 6)
            pos = 0
            while pos + 8 < len(data):
                try:
                    block_type   = struct.unpack_from("<I", data, pos)[0]
                    block_len    = struct.unpack_from("<I", data, pos + 4)[0]
                    if block_len < 12 or pos + block_len > len(data):
                        break
                    # Section Header Block (0x0A0D0D0A) - check byte order
                    if block_type == 0x0A0D0D0A:
                        bom = struct.unpack_from("<I", data, pos + 8)[0]
                        byte_order = "<" if bom == 0x1A2B3C4D else ">"
                    # Enhanced Packet Block (6)
                    elif block_type == 6 and block_len >= 28:
                        # ts_high, ts_low at offset 12 and 16 within block
                        ts_high = struct.unpack_from(f"{byte_order}I", data, pos + 12)[0]
                        ts_low  = struct.unpack_from(f"{byte_order}I", data, pos + 16)[0]
                        cap_len = struct.unpack_from(f"{byte_order}I", data, pos + 20)[0]
                        ts_usec = (ts_high << 32) | ts_low  # microseconds
                        pkt_data = data[pos + 28: pos + 28 + cap_len]
                        raw_packets.append((ts_usec / 1e6, pkt_data))
                    # Simple Packet Block (3)
                    elif block_type == 3 and block_len >= 16:
                        cap_len  = struct.unpack_from(f"{byte_order}I", data, pos + 8)[0]
                        pkt_data = data[pos + 16: pos + 16 + cap_len]
                        raw_packets.append((0.0, pkt_data))
                    pos += block_len
                except struct.error:
                    break
        else:
            # Legacy PCAP
            pos = 24
            while pos + 16 < len(data):
                try:
                    ts_sec, ts_usec, incl_len, _ = struct.unpack_from(
                        f"{byte_order}IIII", data, pos
                    )
                    pos += 16
                    pkt_data = data[pos:pos + incl_len]
                    pos += incl_len
                    raw_packets.append((ts_sec + ts_usec / 1e6, pkt_data))
                except struct.error:
                    break

        if not raw_packets:
            return events

        # Timestamp correction
        YEAR_2000 = 946684800.0
        max_ts    = max(p[0] for p in raw_packets)
        ts_offset = 0.0
        if max_ts < YEAR_2000:
            try:
                mtime     = os.path.getmtime(filepath)
                ts_offset = mtime - max_ts
                print(f"    [INFO] {Path(filepath).name}: boot-relative timestamps "
                      f"detected - anchoring to file mtime (offset +{ts_offset:.0f}s)")
            except Exception:
                pass

        for pkt_ts, pkt_data in raw_packets:
            if b"\x12\x79" in pkt_data or b"\x79\x12" in pkt_data:
                corrected = pkt_ts + ts_offset
                ev = self._extract_gsmtap_basic(pkt_data, filepath, corrected)
                if ev:
                    events.append(ev)

        return events

    def _extract_gsmtap_basic(self, pkt_data: bytes, source: str,
                               ts: float) -> Optional[Dict]:
        gsmtap_start = None
        for i in range(len(pkt_data) - 4):
            if pkt_data[i] == 0x02 and pkt_data[i+1] in (0x04, 0x08):
                gsmtap_start = i
                break
        if gsmtap_start is None:
            return None

        hdr = pkt_data[gsmtap_start:]
        if len(hdr) < 4:
            return None

        gsmtap_type = hdr[2]
        payload = hdr[hdr[1] * 4:] if len(hdr) > hdr[1] * 4 else b""

        ev = {
            "source_file": Path(source).name,
            "source_type": "pcap",
            "timestamp":   str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "ts_epoch":    ts,
            "raw":         {},
            "layer":       GSMTAP_TYPE_NAMES.get(gsmtap_type, f"GSMTAP_{gsmtap_type:02x}"),
        }

        if payload:
            for i in range(len(payload) - 1):
                if payload[i] == 0x07:
                    nb = payload[i + 1]
                    if nb == 0x55:
                        ev["msg_type"]      = "Identity Request"
                        ev["identity_type"] = "IMSI"
                        break
                    elif nb == 0x5C:
                        ev["msg_type"] = "Security Mode Command"
                        break
                    elif nb == 0x54:
                        ev["msg_type"] = "Authentication Reject"
                        break

        return ev if ev.get("msg_type") else None
