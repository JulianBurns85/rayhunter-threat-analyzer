#!/usr/bin/env python3
"""
QMDL Parser — Qualcomm DIAG Log Frame Extractor
================================================
QMDL is Qualcomm's proprietary binary diagnostic format used by the Snapdragon
modem. Rayhunter records these natively from the Orbic RC400L and TP-Link M7350.

Two modes:
  1. SCAT pipeline (preferred): converts QMDL → PCAP via SCAT tool, then
     hands off to PcapParser for full dissection.
  2. Raw frame scan: manually walks DIAG frame boundaries to extract
     message type codes and key field values without full dissection.

SCAT installation:
  pip install pySCAT  OR  git clone https://github.com/fgsect/scat && pip install .
"""

import struct
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

# Qualcomm DIAG frame constants
DIAG_FRAME_DELIMITER = 0x7E
DIAG_ESCAPE_CHAR     = 0x7D

# Log codes for key LTE NAS/RRC messages
DIAG_LOG_LTE_NAS_PLAIN        = 0xB0EC  # LTE NAS OTA (plain)
DIAG_LOG_LTE_NAS_SECURITY     = 0xB0ED  # LTE NAS OTA (security protected)
DIAG_LOG_LTE_RRC_OTA          = 0xB0C0  # LTE RRC OTA
DIAG_LOG_LTE_ML1_SERVING_CELL = 0xB17F  # LTE ML1 serving cell info (EARFCN etc.)
DIAG_LOG_GSM_RR_SIGNALING     = 0x512F  # GSM RR signaling (2G downgrade)

# Interesting log codes and their descriptions
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


class QmdlParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.scat_available = self._check_scat()

    def _check_scat(self) -> bool:
        """Check if SCAT is available for QMDL → PCAP conversion."""
        try:
            result = subprocess.run(
                ["scat", "--help"],
                capture_output=True, timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def parse(self, filepath: str) -> List[Dict]:
        """Parse QMDL file, return normalised events."""
        if self.scat_available:
            return self._parse_via_scat(filepath)
        else:
            print("    [INFO] SCAT not found — using raw DIAG frame scan.")
            print("           For full dissection, install SCAT:")
            print("           pip install pySCAT")
            return self._parse_raw_frames(filepath)

    def _parse_via_scat(self, filepath: str) -> List[Dict]:
        """Convert QMDL to PCAP via SCAT, then use PCAP parser."""
        from parsers.pcap_parser import PcapParser

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["scat", "-t", "qc", "-i", filepath, "-o", tmp_path, "--format", "pcap"],
                capture_output=True, timeout=120, text=True
            )
            if result.returncode != 0:
                print(f"    [WARN] SCAT conversion failed: {result.stderr[:200]}")
                return self._parse_raw_frames(filepath)

            pcap_parser = PcapParser(self.cfg)
            events = pcap_parser.parse(tmp_path)
            # Tag events as originating from QMDL
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
        """
        Walk raw DIAG frames in QMDL binary.
        Extracts log codes, timestamps, and detects key message types
        without full protocol dissection.
        """
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
        current = []
        escaped = False

        for byte in data:
            if byte == DIAG_FRAME_DELIMITER:
                if current:
                    frames.append(bytes(current))
                    current = []
            elif byte == DIAG_ESCAPE_CHAR:
                escaped = True
            elif escaped:
                current.append(byte ^ 0x20)
                escaped = False
            else:
                current.append(byte)

        return [f for f in frames if len(f) >= 4]

    def _decode_frame(self, frame: bytes, source: str, idx: int) -> Optional[Dict]:
        """
        Decode a single DIAG frame.
        Frame structure:
          [0]     cmd_code (0x10 = log, 0x79 = extended log)
          [1:3]   length (LE uint16)
          [3:5]   log_code (LE uint16)
          [5:13]  timestamp (LE uint64, QCOM epoch = Jan 6 1980)
          [13:]   payload
        """
        if len(frame) < 8:
            return None

        cmd_code = frame[0]

        # Only process log packets (0x10) and extended log packets (0x98)
        if cmd_code not in (0x10, 0x98):
            return None

        try:
            if cmd_code == 0x10:
                log_code = struct.unpack_from("<H", frame, 4)[0]
                ts_raw   = struct.unpack_from("<Q", frame, 8)[0] if len(frame) >= 16 else 0
                payload  = frame[16:] if len(frame) > 16 else b""
            else:  # Extended (0x98)
                log_code = struct.unpack_from("<H", frame, 8)[0]
                ts_raw   = struct.unpack_from("<Q", frame, 12)[0] if len(frame) >= 20 else 0
                payload  = frame[20:] if len(frame) > 20 else b""
        except struct.error:
            return None

        if log_code not in LOG_CODE_NAMES:
            return None

        ev = {
            "source_file": Path(source).name,
            "source_type": "qmdl",
            "line": idx,
            "timestamp": self._decode_qcom_timestamp(ts_raw),
            "raw": {"log_code": hex(log_code), "frame_len": len(frame)},
            "log_code": hex(log_code),
            "log_type": LOG_CODE_NAMES[log_code],
        }

        # ── Decode key log types ──────────────────────────────────────

        if log_code == DIAG_LOG_LTE_NAS_PLAIN and len(payload) >= 4:
            ev.update(self._decode_nas_ota(payload))

        elif log_code == DIAG_LOG_LTE_RRC_OTA and len(payload) >= 6:
            ev.update(self._decode_rrc_ota(payload))

        elif log_code == DIAG_LOG_LTE_ML1_SERVING_CELL and len(payload) >= 8:
            ev.update(self._decode_serving_cell(payload))

        elif log_code == DIAG_LOG_GSM_RR_SIGNALING:
            ev["msg_type"] = "GSM RR Signaling"
            ev["layer"] = "GSM/2G"
            ev["has_geran_redirect"] = True
            ev["harness_alerts"] = ["2G GSM RR signaling detected — potential downgrade"]

        return ev

    def _decode_nas_ota(self, payload: bytes) -> dict:
        """Decode LTE NAS OTA log packet fields."""
        result = {"layer": "NAS"}

        # NAS OTA log: direction(1), message_len(2), message(...)
        if len(payload) < 4:
            return result

        direction = payload[0]  # 0 = uplink, 1 = downlink
        result["direction"] = "UL" if direction == 0 else "DL"

        msg = payload[3:] if len(payload) > 3 else b""

        # LTE NAS header: security_hdr(1), msg_type(1) or more
        if len(msg) >= 2:
            sec_hdr = msg[0] & 0x0F

            # Plain NAS starts with EPS bearer / PD
            # Message type is typically at offset 1 or 3
            for offset in (1, 2, 3):
                if offset < len(msg):
                    byte = msg[offset]
                    from parsers.ndjson_parser import NAS_MSG_TYPES
                    if byte in NAS_MSG_TYPES:
                        result["msg_type"] = NAS_MSG_TYPES[byte]
                        break

            # Security Mode Command — check cipher
            if result.get("msg_type") == "Security Mode Command" and len(msg) >= 4:
                alg_byte = msg[3] if len(msg) > 3 else 0
                eea = alg_byte & 0x07       # bits 0-2
                eia = (alg_byte >> 4) & 0x07  # bits 4-6
                result["cipher_alg"]    = f"EEA{eea}" if eea else "EEA0"
                result["integrity_alg"] = f"EIA{eia}" if eia else "EIA0"

            # Identity Request — extract identity type
            if result.get("msg_type") == "Identity Request" and len(msg) >= 3:
                id_byte = msg[2] & 0x07
                result["identity_type"] = {1: "IMSI", 2: "IMEI/IMEISV", 4: "TMSI"}.get(
                    id_byte, f"UNKNOWN({id_byte})"
                )

        return result

    def _decode_rrc_ota(self, payload: bytes) -> dict:
        """Decode LTE RRC OTA log packet."""
        result = {"layer": "RRC"}
        if len(payload) < 6:
            return result

        # RRC OTA log: direction(1), rb_id(1), length(2), msg_type_ext(1), payload
        rb_id = payload[1]
        result["rb_id"] = rb_id  # SRB0/SRB1/SRB2 or DRB

        # Scan payload for known RRC message patterns
        payload_str = payload.hex().lower()
        if "mobilitycontrolinfo" in payload_str:
            result["has_mobility_control"] = True
            result["msg_type"] = "RRC Connection Reconfiguration"
        elif any(x in payload for x in [b"\x00\x00\x00", b"\xff\x00"]):
            # Look for RRC Connection Release pattern
            pass

        # Check for GERAN redirect bytes
        if len(payload) > 10 and any(payload[i:i+2] == b"\x01\x05" for i in range(len(payload)-1)):
            result["has_geran_redirect"] = True
            result["harness_alerts"] = ["RRC Connection Release with GERAN redirect bytes"]

        return result

    def _decode_serving_cell(self, payload: bytes) -> dict:
        """Decode LTE ML1 serving cell info — EARFCN, PCI, RSRP."""
        result = {}
        try:
            if len(payload) >= 4:
                result["earfcn"] = struct.unpack_from("<I", payload, 0)[0] & 0x3FFFF
            if len(payload) >= 6:
                result["pci"] = struct.unpack_from("<H", payload, 4)[0] & 0x1FF
            if len(payload) >= 10:
                rsrp_raw = struct.unpack_from("<i", payload, 6)[0]
                result["rsrp"] = rsrp_raw / 10.0  # dBm
        except struct.error:
            pass
        return result

    def _decode_qcom_timestamp(self, ts_raw: int) -> str:
        """Convert Qualcomm epoch timestamp to ISO 8601 string."""
        from datetime import datetime, timezone
        # Qualcomm epoch: Jan 6, 1980 00:00:00 UTC
        # Units: 1/65536 seconds (ticks)
        QCOM_EPOCH_OFFSET = 315964800  # Unix timestamp of Jan 6, 1980
        if ts_raw == 0:
            return None
        try:
            unix_ts = QCOM_EPOCH_OFFSET + (ts_raw / 65536.0)
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
