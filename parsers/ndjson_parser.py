#!/usr/bin/env python3
"""
NDJSON Parser — Rayhunter Cellular Event Extractor
===================================================
Confirmed Rayhunter v0.10.x NDJSON schema (from live capture analysis):

  LINE 1 — Header:
    {
      "analyzers": [
        {"name": "Identity (IMSI or IMEI) requested...", "description": "...", "version": N},
        {"name": "Connection Release/Redirected Carrier 2G Downgrade", ...},
        {"name": "LTE SIB 6/7 Downgrade", ...},
        {"name": "Null Cipher", ...},
        {"name": "NAS Null Cipher Requested", ...},
        {"name": "Incomplete SIB", ...},
        {"name": "Test Analyzer", ...},          ← index 6, fires on every SIB1 (noisy)
        {"name": "Diagnostic detector...", ...}
      ],
      "rayhunter": {"arch": "...", "rayhunter_version": "...", "system_os": "..."},
      "report_version": N
    }

  SUBSEQUENT LINES — One per decoded packet:
    {
      "packet_timestamp": "2026-03-09T01:48:02.223Z",
      "skipped_message_reason": null,
      "events": [
        null,           ← index 0: "Identity..." analyzer did NOT fire
        null,           ← index 1: "Connection Release..." did NOT fire
        null,           ← index 2: "LTE SIB 6/7..." did NOT fire
        null,           ← index 3: "Null Cipher" did NOT fire
        null,           ← index 4: "NAS Null Cipher" did NOT fire
        null,           ← index 5: "Incomplete SIB" did NOT fire
        {               ← index 6: "Test Analyzer" FIRED
          "event_type": "Low",
          "message": "SIB1 received CID: 135836191, TAC: 12385, PLMN: 505-01 (packet 7415)"
        },
        null            ← index 7: "Diagnostic detector" did NOT fire
      ]
    }

KEY FACTS:
  - event_type = severity ("Low" / "Medium" / "High" / "Critical")
  - Threat identity comes from the array INDEX matching analyzers[] from header
  - SIB1 messages encode cell_id and TAC in the message string → parsed here
  - "Test Analyzer" (index 6) fires on every SIB1 — useful for cell extraction but noisy

FIX v1.2:
  - MNC/MCC propagation: after parsing, NAS events (Identity Requests etc.) inherit
    the MNC/MCC discovered from SIB1 beacon events in the same capture file.
    Previously NAS events kept the config-default MNC (001) even when SIB1 events
    correctly identified the network as Vodafone (MNC=03). This broke cross-network
    correlation in timeline_correlator.py.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


# ── Analyzer index → threat mapping ──────────────────────────────────
# Keyed by lowercase substring of analyzer name.
# Maps to field updates when that analyzer fires.
ANALYZER_THREAT_MAP = {
    "identity (imsi or imei)": {
        "msg_type": "Identity Request",
        "identity_type": "IMSI",
        "threat": "IMSI_HARVEST",
    },
    "imsi or imei": {
        "msg_type": "Identity Request",
        "identity_type": "IMSI",
        "threat": "IMSI_HARVEST",
    },
    "connection release": {
        "msg_type": "RRC Connection Release",
        "has_geran_redirect": True,
        "threat": "GERAN_REDIRECT",
    },
    "redirected carrier": {
        "msg_type": "RRC Connection Release",
        "has_geran_redirect": True,
        "threat": "GERAN_REDIRECT",
    },
    "2g downgrade": {
        "has_geran_redirect": True,
        "threat": "GERAN_REDIRECT",
    },
    "sib 6": {
        "has_geran_redirect": True,
        "msg_type": "SIB6/7 2G Downgrade",
        "threat": "SIB_DOWNGRADE",
    },
    "sib 7": {
        "has_geran_redirect": True,
        "msg_type": "SIB6/7 2G Downgrade",
        "threat": "SIB_DOWNGRADE",
    },
    "null cipher": {
        "cipher_alg": "EEA0",
        "msg_type": "Security Mode Command",
        "threat": "NULL_CIPHER",
    },
    "nas null cipher": {
        "cipher_alg": "EEA0",
        "integrity_alg": "EIA0",
        "msg_type": "Security Mode Command",
        "threat": "NULL_CIPHER",
    },
    "diagnostic detector": {
        # Noisy but useful — contains IMSI exposure context
        "threat": "IMSI_EXPOSURE_CONTEXT",
    },
    "imsi exposure": {
        "identity_type": "IMSI",
        "threat": "IMSI_EXPOSURE_CONTEXT",
    },
    "proximity": {
        "has_prose": True,
        "threat": "PROSE_TRACKING",
    },
    "handover": {
        "has_mobility_control": True,
        "threat": "HANDOVER_INJECT",
    },
    "authentication reject": {
        "msg_type": "Authentication Reject",
        "threat": "AUTH_REJECT",
    },
    "paging": {
        "msg_type": "Paging",
        "threat": "PAGING",
    },
    # "Test Analyzer" and "Incomplete SIB" → just extract cell data, no threat flag
}

# ── Severity mapping ──────────────────────────────────────────────────
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

# ── SIB1 message pattern ──────────────────────────────────────────────
# "SIB1 received CID: 135836191, TAC: 12385, PLMN: 505-01 (packet 7415)"
SIB1_PATTERN = re.compile(
    r"CID:\s*(\d+).*?TAC:\s*(\d+).*?PLMN:\s*([\d-]+)",
    re.IGNORECASE
)

# ── Australian MNC lookup ─────────────────────────────────────────────
AUS_MNC_CARRIERS = {
    "01": "Telstra",
    "001": "Telstra",
    "02": "Optus",
    "002": "Optus",
    "03": "Vodafone",
    "003": "Vodafone",
    "04": "Vodafone",
    "004": "Vodafone",
}


class NdjsonParser:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mcc = cfg.get("network", {}).get("mcc", "505")
        self.mnc = cfg.get("network", {}).get("mnc", "001")
        # Per-file analyzer list, populated from header line
        self._analyzers: List[str] = []

    def parse(self, filepath: str) -> List[Dict]:
        """Parse a Rayhunter NDJSON file into a list of normalised events."""
        events = []
        self._analyzers = []
        path = Path(filepath)

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    raw = self._try_recover(line)
                    if raw is None:
                        continue

                # Line 1: header with analyzer definitions
                if "analyzers" in raw:
                    self._parse_header(raw)
                    continue

                event = self._normalise(raw, filepath, lineno)
                if event:
                    events.append(event)

        # ── MNC/MCC propagation pass ──────────────────────────────────
        # SIB1 beacon events carry the true PLMN (MCC/MNC) from the cell.
        # NAS events (Identity Requests, SMCs, etc.) occur during the same
        # capture session but have no PLMN field — they keep the config
        # default. This pass finds the inferred MNC from SIB1 events and
        # applies it to all events in this file that still have the default.
        inferred_mcc, inferred_mnc = self._infer_network(events)
        if inferred_mnc and inferred_mnc != self.mnc:
            carrier = AUS_MNC_CARRIERS.get(inferred_mnc, f"MNC={inferred_mnc}")
            print(f"    [NET] {path.name}: inferred network = "
                  f"MCC={inferred_mcc} MNC={inferred_mnc} ({carrier})")
            for ev in events:
                if ev.get("mnc") == self.mnc:
                    ev["mnc"] = inferred_mnc
                if ev.get("mcc") == self.mcc and inferred_mcc:
                    ev["mcc"] = inferred_mcc
                # Store carrier name for use by correlator
                ev["carrier"] = carrier

        return events

    def _infer_network(self, events: List[Dict]):
        """
        Find the MCC/MNC from SIB1 beacon events in this capture file.
        Returns (mcc, mnc) or (None, None) if not determinable.
        Uses the most frequently observed PLMN to handle edge cases where
        a rogue cell briefly advertises a different PLMN.
        """
        from collections import Counter
        plmn_counts = Counter()
        for ev in events:
            cid = ev.get("cell_id")
            mnc = ev.get("mnc")
            mcc = ev.get("mcc")
            # Only count events where MNC was actually extracted from SIB1
            # (not the config default)
            if cid and mnc and mnc != self.mnc:
                plmn_counts[(mcc, mnc)] += 1
            elif cid and mnc == self.mnc:
                # Could still be legitimate if MNC genuinely is 001
                # Count these too but with lower weight
                pass

        if plmn_counts:
            # Most common non-default PLMN wins
            (mcc, mnc), _ = plmn_counts.most_common(1)[0]
            return mcc, mnc

        # Fallback: if all SIB1 events have the default MNC, accept it
        for ev in events:
            if ev.get("cell_id") and ev.get("mnc"):
                return ev.get("mcc"), ev.get("mnc")

        return None, None

    def _parse_header(self, raw: dict):
        """Extract ordered analyzer names from the header line."""
        self._analyzers = []
        for analyzer in raw.get("analyzers", []):
            if isinstance(analyzer, dict):
                self._analyzers.append(analyzer.get("name", "").lower())
            else:
                self._analyzers.append("")

    def _normalise(self, raw: dict, source_file: str, lineno: int) -> Optional[Dict]:
        """Convert a Rayhunter packet line into a normalised event dict."""
        ev = {
            "source_file": Path(source_file).name,
            "source_type": "ndjson",
            "line": lineno,
            "raw": raw,
            # Defaults
            "timestamp": None,
            "cell_id": None, "earfcn": None,
            "mcc": self.mcc, "mnc": self.mnc,
            "tac": None, "pci": None, "rsrp": None, "rat": "LTE",
            "msg_type": None, "msg_subtype": None, "layer": "NAS",
            "cipher_alg": None, "integrity_alg": None,
            "identity_type": None,
            "has_mobility_control": False, "has_geran_redirect": False,
            "has_measreport": False, "has_prose": False,
            "paging_type": None,
            "harness_alerts": [],
            "rayhunter_severity": None,
            "threats": [],
            "carrier": None,
        }

        # ── Timestamp ─────────────────────────────────────────────────
        ev["timestamp"] = (
            raw.get("packet_timestamp")
            or raw.get("timestamp")
            or raw.get("ts")
        )

        # ── Process events[] array ─────────────────────────────────────
        rayhunter_events = raw.get("events") or []
        harness_alerts = []

        for idx, rh_ev in enumerate(rayhunter_events):
            if rh_ev is None:
                continue
            if not isinstance(rh_ev, dict):
                continue

            event_type = str(rh_ev.get("event_type") or "").strip()
            message    = str(rh_ev.get("message") or "").strip()
            severity   = SEVERITY_MAP.get(event_type.lower(), "LOW")

            # Track highest severity seen
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            current_rank = sev_rank.get(ev["rayhunter_severity"] or "INFO", 0)
            if sev_rank.get(severity, 0) > current_rank:
                ev["rayhunter_severity"] = severity

            # Identify which analyzer fired using the header index
            analyzer_name = ""
            if idx < len(self._analyzers):
                analyzer_name = self._analyzers[idx]

            # Fallback: try to identify from message content
            if not analyzer_name:
                analyzer_name = message.lower()

            # Map analyzer to threat fields
            matched = False
            for key, updates in ANALYZER_THREAT_MAP.items():
                if key in analyzer_name or key in message.lower():
                    for field, val in updates.items():
                        if field == "threat":
                            if val not in ev["threats"]:
                                ev["threats"].append(val)
                        elif field.startswith("has_"):
                            ev[field] = ev[field] or val
                        elif not ev.get(field):
                            ev[field] = val
                    matched = True
                    break

            # Extract cell data from SIB1 messages (Test Analyzer fires on every SIB1)
            sib1_match = SIB1_PATTERN.search(message)
            if sib1_match:
                ev["cell_id"] = ev["cell_id"] or sib1_match.group(1)
                ev["tac"]     = ev["tac"]     or sib1_match.group(2)
                plmn = sib1_match.group(3)  # e.g. "505-03" → MCC=505 MNC=03
                if "-" in plmn:
                    parts = plmn.split("-", 1)
                    ev["mcc"] = parts[0]
                    # Preserve original MNC digits — don't zfill to 2 as some
                    # PLMNs use 3-digit MNC. Keep as-is from the beacon.
                    ev["mnc"] = parts[1] if len(parts) > 1 else self.mnc
                # SIB1 events alone are not threats — skip harness alert unless higher severity
                if severity == "LOW" and not matched:
                    continue

            # Build harness alert string (skip Low-severity Test Analyzer SIB1 noise)
            is_sib1_noise = (
                "sib1 received" in message.lower()
                and severity == "LOW"
            )
            if not is_sib1_noise and (event_type or message):
                alert_str = f"[{severity}] {analyzer_name or event_type}: {message}"
                harness_alerts.append(alert_str[:300])

        ev["harness_alerts"] = harness_alerts

        # ── Also scan message text for additional cipher/identity signals ──
        all_messages = " ".join(
            str(e.get("message", "")) for e in rayhunter_events if e
        ).lower()
        if "eea0" in all_messages or "null cipher" in all_messages:
            ev["cipher_alg"] = ev["cipher_alg"] or "EEA0"
        if "eia0" in all_messages:
            ev["integrity_alg"] = ev["integrity_alg"] or "EIA0"
        if "imsi" in all_messages and not ev["identity_type"]:
            ev["identity_type"] = "IMSI"
        if "imei" in all_messages and not ev["identity_type"]:
            ev["identity_type"] = "IMEI/IMEISV"
        if "geran" in all_messages or "2g" in all_messages:
            ev["has_geran_redirect"] = True

        # ── skipped_message_reason ────────────────────────────────────
        skip_reason = str(raw.get("skipped_message_reason") or "")
        if skip_reason and "EncryptedNASMessage" not in skip_reason:
            ev["harness_alerts"].append(f"[INFO] Skip: {skip_reason[:100]}")

        # ── Paging type ───────────────────────────────────────────────
        if ev["msg_type"] == "Paging":
            ev["paging_type"] = "IMSI" if ev.get("identity_type") == "IMSI" else "S-TMSI"

        # ── Only keep events with at least one useful signal ──────────
        has_signal = any([
            ev["msg_type"],
            ev["cipher_alg"],
            ev["identity_type"],
            ev["has_geran_redirect"],
            ev["has_prose"],
            ev["has_mobility_control"],
            ev["harness_alerts"],
            ev["cell_id"],
        ])
        return ev if has_signal else None

    def _try_recover(self, line: str) -> Optional[dict]:
        """Attempt to recover a truncated/malformed JSON line."""
        for suffix in ["}", "}}", "}}}"]:
            try:
                return json.loads(line + suffix)
            except json.JSONDecodeError:
                pass
        return None
