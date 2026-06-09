#!/usr/bin/env python3
"""
PCAP Parser - GSMTAP/NAS/RRC Event Extractor
=============================================
v3.3.1: Direct tshark subprocess via _ws.col.Info.
        Replaces pyshark (incompatible with Python 3.14 asyncio).
        Confirmed working against Cranbourne East PCAPNG captures.

Fix history:
  v3.3.1 (29 May 2026):
  - REPLACED pyshark with tshark subprocess
  - Uses _ws.col.Info for msg_type (confirmed: MeasurementReport,
    Paging, SecurityModeCommand, Authentication request)
  - Does NOT use -E occurrence=f (causes empty stdout on Windows)
  - Boot-relative timestamp correction via mtime anchoring
  - PCAPNG block parser in _parse_basic fallback

  v2.2 (22 May 2026):
  - Removed false-positive cipher detection from _parse_basic
"""

import os
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

GSMTAP_TYPE_NAMES = {
    0x01: "GSM Um",
    0x0d: "LTE RRC",
    0x0e: "LTE NAS",
    0x02: "GSM Abis",
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

# Map col.Info substrings (lowercase) to canonical msg_type
COL_INFO_MAP = {
    "identity request":               "Identity Request",
    "authentication reject":          "Authentication Reject",
    "authentication request":         "Authentication Request",
    "authentication response":        "Authentication Response",
    "security mode command":          "Security Mode Command",
    "security mode complete":         "Security Mode Complete",
    "security mode reject":           "Security Mode Reject",
    "securitymodecommand":            "Security Mode Command",
    "securitymodecomplete":           "Security Mode Complete",
    "attach reject":                  "Attach Reject",
    "attach request":                 "Attach Request",
    "attach accept":                  "Attach Accept",
    "tracking area update reject":    "Tracking Area Update Reject",
    "rrcconnectionrelease":           "RRC Connection Release",
    "rrcconnectionreconfiguration":   "RRC Connection Reconfiguration",
    "measurementreport":              "Measurement Report",
    "dlinformationtransfer":          "DL Information Transfer",
}

# tshark fields to extract (order matters for pipe-split)
TSHARK_FIELDS = [
    "frame.time_epoch",
    "_ws.col.Info",
    "lte-rrc.physCellId",
    "lte-rrc.cellIdentity",
    "lte-rrc.trackingAreaCode",
    "lte-rrc.mobilityControlInfo_element",
    "lte-rrc.geran_element",
    "lte-rrc.reportProximityConfig_r9_element",
    "nas-eps.emm.type_of_id",
    "lte-rrc.targetPhysCellId",
    "lte-rrc.dl_CarrierFreq",
    "lte-rrc.t304",
    "lte-rrc.newUE_Identity",
]

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
        """Parse PCAP/PCAPNG. tshark primary + basic supplement for NAS."""
        events = []
        if self._tshark:
            try:
                tshark_events = self._parse_tshark(filepath)
                if tshark_events is not None:
                    events = tshark_events
            except Exception as exc:
                print(f"    [WARN] tshark error in {Path(filepath).name}: {exc}")
        # Always run basic parser to catch NAS byte patterns
        # (Identity Request, Auth Reject) that tshark wraps in
        # DLInformationTransfer and does not surface in col.Info
        basic = self._parse_basic(filepath)
        if basic:
            # Only add events with msg_type not already found
            tshark_types = {e.get('msg_type') for e in events if e.get('msg_type')}
            for ev in basic:
                if ev.get('msg_type') and ev['msg_type'] not in tshark_types:
                    events.append(ev)
        return events

    # ------------------------------------------------------------------ #
    # tshark primary parser
    # ------------------------------------------------------------------ #

    def _parse_tshark(self, filepath: str) -> Optional[List[Dict]]:
        field_args = []
        for f in TSHARK_FIELDS:
            field_args += ["-e", f]

        # NOTE: Do NOT use -E occurrence=f -- causes empty stdout on
        # Windows tshark with GSMTAP-encapsulated PCAPNG files.
        cmd = [
            self._tshark, "-r", filepath,
            "-T", "fields",
            "-E", "separator=|",
            "-E", "quote=n",
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
            return None  # tshark broken, fall back to _parse_basic

        if not result.stdout.strip():
            return []

        ts_offset = self._compute_ts_offset(result.stdout, filepath)
        events = []

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            while len(parts) < len(TSHARK_FIELDS):
                parts.append("")
            ev = self._build_event(parts, filepath, ts_offset)
            if ev:
                events.append(ev)

        return events

    def _compute_ts_offset(self, output: str, filepath: str) -> float:
        YEAR_2000 = 946684800.0
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

    def _build_event(self, parts: list, filepath: str,
                     ts_offset: float) -> Optional[Dict]:
        ts_raw = parts[0].strip()
        if not ts_raw:
            return None
        try:
            ts = float(ts_raw) + ts_offset
        except ValueError:
            return None

        col_info = parts[1].strip() if len(parts) > 1 else ""
        pci_raw  = parts[2].strip() if len(parts) > 2 else ""
        cid_raw  = parts[3].strip() if len(parts) > 3 else ""
        tac_raw  = parts[4].strip() if len(parts) > 4 else ""
        mobility = parts[5].strip() if len(parts) > 5 else ""
        geran    = parts[6].strip() if len(parts) > 6 else ""
        prose    = parts[7].strip() if len(parts) > 7 else ""
        id_type       = parts[8].strip()  if len(parts) > 8  else ""
        target_pci    = parts[9].strip()  if len(parts) > 9  else ""
        target_earfcn = parts[10].strip() if len(parts) > 10 else ""
        t304          = parts[11].strip() if len(parts) > 11 else ""
        new_rnti      = parts[12].strip() if len(parts) > 12 else ""

        # Derive msg_type from col.Info
        msg_type = self._col_info_to_msg_type(col_info)
        layer = "RRC"

        # Check for NAS messages in col.Info (they appear as
        # "DLInformationTransfer, Security mode command" etc.)
        if col_info and not msg_type:
            lower = col_info.lower()
            # Catch compound col.Info like "DLInformationTransfer, Security mode command"
            for pattern, human in COL_INFO_MAP.items():
                if pattern in lower:
                    msg_type = human
                    break

        # Identity type
        identity_type = None
        if id_type:
            identity_type = NAS_ID_TYPE_MAP.get(id_type.lower())
        if not identity_type and msg_type == "Identity Request":
            identity_type = "IMSI"

        # Cell fields
        cid = None
        if cid_raw:
            try:
                cid = str(int(cid_raw.replace(" ", ""), 16) >> 4)
            except ValueError:
                cid = cid_raw

        tac = None
        if tac_raw:
            try:
                tac = str(int(tac_raw.replace(" ", ""), 16))
            except ValueError:
                tac = tac_raw

        pci = None
        if pci_raw:
            try:
                pci = int(pci_raw)
            except ValueError:
                pass

        has_data = any([
            msg_type, cid, identity_type,
            bool(mobility), bool(geran), bool(prose),
            bool(target_pci), bool(target_earfcn),
        ])

        if not has_data:
            return None

        ev = {
            "source_file":         Path(filepath).name,
            "source_type":         "pcap",
            "timestamp":           str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "ts_epoch":            ts,
            "raw":                 {},
            "layer":               layer,
            "has_mobility_control": bool(mobility),
            "has_geran_redirect":  bool(geran),
            "has_prose":           bool(prose),
        }
        if msg_type:        ev["msg_type"]      = msg_type
        if identity_type:   ev["identity_type"] = identity_type
        if cid:             ev["cid"]           = cid
        if tac:             ev["tac"]           = tac
        if pci is not None: ev["pci"]           = pci
        if target_pci:
            try:
                ev["target_pci"] = int(target_pci)
            except ValueError:
                pass
        if target_earfcn:
            try:
                ev["target_earfcn"] = int(target_earfcn)
            except ValueError:
                pass
        if t304:
            try:
                ev["t304"] = int(t304)
            except ValueError:
                pass
        if new_rnti:
            ev["new_rnti"] = new_rnti

        return ev

    def _col_info_to_msg_type(self, col_info: str) -> Optional[str]:
        if not col_info:
            return None
        lower = col_info.lower()
        for pattern, human in COL_INFO_MAP.items():
            if pattern in lower:
                return human
        if lower.startswith("paging"):
            return "Paging"
        return None

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

        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                             b"\x0a\x0d\x0d\x0a"):
            print(f"    [WARN] {Path(filepath).name}: not a valid PCAP file")
            return events

        is_pcapng  = data[:4] == b"\x0a\x0d\x0d\x0a"
        byte_order = "<"
        raw_packets = []

        if is_pcapng:
            pos = 0
            while pos + 8 < len(data):
                try:
                    block_type = struct.unpack_from("<I", data, pos)[0]
                    block_len  = struct.unpack_from("<I", data, pos + 4)[0]
                    if block_len < 12 or pos + block_len > len(data):
                        break
                    if block_type == 0x0A0D0D0A:
                        bom = struct.unpack_from("<I", data, pos + 8)[0]
                        byte_order = "<" if bom == 0x1A2B3C4D else ">"
                    elif block_type == 6 and block_len >= 28:
                        ts_high = struct.unpack_from(
                            f"{byte_order}I", data, pos + 12)[0]
                        ts_low  = struct.unpack_from(
                            f"{byte_order}I", data, pos + 16)[0]
                        cap_len = struct.unpack_from(
                            f"{byte_order}I", data, pos + 20)[0]
                        ts_usec = (ts_high << 32) | ts_low
                        pkt_data = data[pos + 28: pos + 28 + cap_len]
                        raw_packets.append((ts_usec / 1e6, pkt_data))
                    elif block_type == 3 and block_len >= 16:
                        cap_len  = struct.unpack_from(
                            f"{byte_order}I", data, pos + 8)[0]
                        pkt_data = data[pos + 16: pos + 16 + cap_len]
                        raw_packets.append((0.0, pkt_data))
                    pos += block_len
                except struct.error:
                    break
        else:
            bo = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
            pos = 24
            while pos + 16 < len(data):
                try:
                    ts_sec, ts_usec, incl_len, _ = struct.unpack_from(
                        f"{bo}IIII", data, pos)
                    pos += 16
                    pkt_data = data[pos:pos + incl_len]
                    pos += incl_len
                    raw_packets.append(
                        (ts_sec + ts_usec / 1e6, pkt_data))
                except struct.error:
                    break

        if not raw_packets:
            return events

        YEAR_2000 = 946684800.0
        max_ts    = max(p[0] for p in raw_packets)
        ts_offset = 0.0
        if max_ts < YEAR_2000:
            try:
                mtime     = os.path.getmtime(filepath)
                ts_offset = mtime - max_ts
                print(f"    [INFO] {Path(filepath).name}: boot-relative "
                      f"timestamps detected - anchoring to file mtime "
                      f"(offset +{ts_offset:.0f}s)")
            except Exception:
                pass

        for pkt_ts, pkt_data in raw_packets:
            if b"\x12\x79" in pkt_data or b"\x79\x12" in pkt_data:
                corrected = pkt_ts + ts_offset
                ev = self._extract_gsmtap_basic(
                    pkt_data, filepath, corrected)
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
        payload = (hdr[hdr[1] * 4:]
                   if len(hdr) > hdr[1] * 4 else b"")

        ev = {
            "source_file": Path(source).name,
            "source_type": "pcap",
            "timestamp":   str(datetime.fromtimestamp(ts, tz=timezone.utc)),
            "ts_epoch":    ts,
            "raw":         {},
            "layer":       GSMTAP_TYPE_NAMES.get(
                               gsmtap_type, f"GSMTAP_{gsmtap_type:02x}"),
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
