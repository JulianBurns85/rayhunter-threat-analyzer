#!/usr/bin/env python3
"""
QMDL Parser — Qualcomm DIAG Frame Extractor
============================================
Parses QMDL files from Rayhunter captures.

Two modes:
  1. SCAT pipeline (preferred): converts QMDL to PCAP via SCAT,
     then hands off to PcapParser for full NAS/RRC dissection.
  2. Raw frame scan: walks raw DIAG frame boundaries to extract
     log codes and key field values without full dissection.

SCAT installation:
  pip install pySCAT
  OR: git clone https://github.com/fgsect/scat && pip install .
"""

import struct
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone

# Qualcomm DIAG frame constants
DIAG_FRAME_DELIMITER = 0x7E
DIAG_ESCAPE_CHAR     = 0x7D

# Log codes for key LTE NAS/RRC messages
DIAG_LOG_LTE_NAS_PLAIN        = 0xB0EC
DIAG_LOG_LTE_NAS_SECURITY     = 0xB0ED
DIAG_LOG_LTE_RRC_OTA          = 0xB0C0
DIAG_LOG_LTE_ML1_SERVING_CELL = 0xB17F
DIAG_LOG_GSM_RR_SIGNALING     = 0x512F

LOG_CODE_NAMES = {
    DIAG_LOG_LTE_NAS_PLAIN:        "LTE NAS OTA (plain)",
    DIAG_LOG_LTE_NAS_SECURITY:     "LTE NAS OTA (security)",
    DIAG_LOG_LTE_RRC_OTA:          "LTE RRC OTA",
    DIAG_LOG_LTE_ML1_SERVING_CELL: "LTE ML1 Serving Cell",
    DIAG_LOG_GSM_RR_SIGNALING:     "GSM RR Signaling",
    0xB17E: "LTE ML1 Cell Resel",
    0xB192: "LTE ML1 Neighbor Cell",
    0xB193: "LTE ML1 Handover",
    0xB195: "LTE ML1 Connected Mode",
}

# NAS EMM message types (same table as pcap_parser)
NAS_MSG_TYPES = {
    0x41: "Attach Request",        0x42: "Attach Accept",
    0x44: "Attach Reject",         0x45: "Detach Request",
    0x48: "Tracking Area Update Request",
    0x49: "Tracking Area Update Accept",
    0x4B: "Tracking Area Update Reject",
    0x4E: "Service Reject",        0x50: "GUTI Reallocation Command",
    0x52: "Authentication Request", 0x53: "Authentication Response",
    0x54: "Authentication Reject", 0x55: "Identity Request",
    0x56: "Identity Response",     0x5D: "Security Mode Command",
    0x5E: "Security Mode Complete", 0x5F: "Security Mode Reject",
}


class QmdlParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.scat_available = self._check_scat()

    def _check_scat(self) -> bool:
        try:
            subprocess.run(["scat", "--help"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def parse(self, filepath: str) -> List[Dict]:
        """Parse QMDL file, return normalised events."""
        if self.scat_available:
            return self._parse_via_scat(filepath)
        print("    [INFO] SCAT not found — using raw DIAG frame scan.")
        print("           For full dissection, install SCAT:")
        print("           pip install pySCAT")
        return self._parse_raw_frames(filepath)

    def _parse_via_scat(self, filepath: str) -> List[Dict]:
        """Convert QMDL to PCAP via SCAT, then use PcapParser."""
        from parsers.pcap_parser import PcapParser

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["scat", "-t", "qc", "-i", filepath,
                 "-o", tmp_path, "--format", "pcap"],
                capture_output=True, timeout=120, text=True
            )
            if result.returncode != 0:
                print(f"    [WARN] SCAT conversion failed: {result.stderr[:200]}")
                return self._parse_raw_frames(filepath)

            pcap_parser = PcapParser(self.cfg)
            events = pcap_parser.parse(tmp_path)
            for ev in events:
                ev["source_type"] = "qmdl"
                ev["source_file"] = Path(filepath).name
            return events

        except subprocess.TimeoutExpired:
            print("    [WARN] SCAT timed out on large QMDL file.")
            return self._parse_raw_frames(filepath)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _parse_raw_frames(self, filepath: str) -> List[Dict]:
        """Walk raw DIAG frames without full dissection."""
        events = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"    [ERROR] Cannot read {filepath}: {e}")
            return events

        frames = self._extract_frames(data)
        print(f"    [QMDL] {len(frames)} raw DIAG frames found")

        for idx, frame in enumerate(frames):
            ev = self._decode_frame(frame, filepath, idx)
            if ev:
                events.append(ev)

        return events

    def _extract_frames(self, data: bytes) -> List[bytes]:
        """Split QMDL byte stream into individual DIAG frames."""
        frames = []
        i = 0
        frame_start = None

        while i < len(data):
            byte = data[i]
            if byte == DIAG_FRAME_DELIMITER:
                if frame_start is not None and i > frame_start + 1:
                    raw_frame = data[frame_start + 1:i]
                    unescaped = self._unescape_frame(raw_frame)
                    if len(unescaped) >= 4:
                        frames.append(unescaped)
                frame_start = i
            i += 1

        return frames

    def _unescape_frame(self, data: bytes) -> bytes:
        """Apply HDLC-like unescaping to DIAG frame."""
        result = bytearray()
        i = 0
        while i < len(data):
            if data[i] == DIAG_ESCAPE_CHAR and i + 1 < len(data):
                result.append(data[i + 1] ^ 0x20)
                i += 2
            else:
                result.append(data[i])
                i += 1
        return bytes(result)

    def _decode_frame(self, frame: bytes, source: str, idx: int):
        """Decode a single DIAG frame into a normalised event."""
        if len(frame) < 4:
            return None

        cmd_code = frame[0]

        # Log packet (cmd_code 0x10)
        if cmd_code != 0x10 or len(frame) < 12:
            return None

        try:
            log_code = struct.unpack_from("<H", frame, 6)[0]
            ts_raw   = struct.unpack_from("<Q", frame, 8)[0]
            ts_sec   = ts_raw / 1000.0
            payload  = frame[16:]
        except struct.error:
            return None

        try:
            ts_str = str(datetime.fromtimestamp(ts_sec, tz=timezone.utc))
        except (OSError, ValueError, OverflowError):
            ts_str = "1970-01-01 00:00:00+00:00"

        # Accept known log codes OR any LTE NAS/RRC range (0xB0xx, 0xB1xx)
        log_name = LOG_CODE_NAMES.get(log_code)
        if not log_name:
            # Broaden: accept any LTE NAS or RRC OTA frame
            hi_byte = (log_code >> 8) & 0xFF
            if hi_byte in (0xB0, 0xB1):
                log_name = f"LTE DIAG 0x{log_code:04X}"
            else:
                return None

        ev = {
            "source_file": Path(source).name,
            "source_type": "qmdl",
            "line":        idx,
            "timestamp":   ts_str,
            "log_code":    f"0x{log_code:04X}",
            "log_name":    log_name,
            "raw":         {},
        }

        # NAS plain message -- extract message type
        if log_code == DIAG_LOG_LTE_NAS_PLAIN and len(payload) >= 4:
            self._extract_nas_from_payload(payload, ev)

        # NAS security-protected -- note cipher in use
        elif log_code == DIAG_LOG_LTE_NAS_SECURITY:
            ev["layer"]    = "NAS"
            ev["msg_type"] = "NAS Security Protected"
            if len(payload) >= 2:
                ev["message"] = "NAS Security Protected PDU"

        # LTE RRC OTA
        elif log_code == DIAG_LOG_LTE_RRC_OTA:
            ev["layer"]    = "RRC"
            ev["msg_type"] = "LTE RRC OTA"
            ev["message"]  = "LTE RRC OTA"

        # LTE ML1 serving cell info
        elif log_code == DIAG_LOG_LTE_ML1_SERVING_CELL:
            ev["layer"]   = "ML1"
            ev["message"] = "LTE ML1 Serving Cell"

        # Generic LTE DIAG
        else:
            ev["layer"]   = "DIAG"
            ev["message"] = log_name

        if "message" not in ev:
            ev["message"] = ev.get("msg_type", log_name)

        return ev

    def _extract_nas_from_payload(self, payload: bytes, ev: dict):
        """Extract NAS message type from DIAG NAS log payload."""
        ev["layer"] = "NAS"
        for i in range(min(len(payload) - 2, 16)):
            if (payload[i] & 0x0F) == 0x07:
                if i + 2 < len(payload):
                    msg_byte = payload[i + 2]
                    if msg_byte in NAS_MSG_TYPES:
                        ev["msg_type"] = NAS_MSG_TYPES[msg_byte]
                        if msg_byte == 0x55 and i + 3 < len(payload):
                            id_type = payload[i + 3] & 0x07
                            ev["identity_type"] = {
                                1: "IMSI", 2: "IMEI",
                                3: "IMEISV", 4: "TMSI"
                            }.get(id_type, f"type_{id_type}")
                        if msg_byte == 0x5D and i + 3 < len(payload):
                            alg = payload[i + 3]
                            ev["cipher_alg"]    = "EEA0" if (alg & 0x0F) == 0 else f"EEA{alg & 0x0F}"
                            ev["integrity_alg"] = "EIA0" if (alg >> 4) == 0 else f"EIA{alg >> 4}"
                        return

    def _extract_rrc_flags(self, payload: bytes, ev: dict):
        """Scan RRC payload for key message signatures."""
        if not payload:
            return
        data_str = payload.hex().lower()
        if "geran" in data_str or "redirectedcarrier" in data_str:
            ev["has_geran_redirect"] = True
        if "mobilitycontrol" in data_str:
            ev["has_mobility_control"] = True
        if "proximityconfig" in data_str:
            ev["has_prose"] = True
