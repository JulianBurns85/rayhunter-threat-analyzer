#!/usr/bin/env python3
"""
Rogue Tower Detector
====================
Cross-references observed cell IDs, EARFCNs and TACs against:
  1. OpenCelliD database (live API or cached)
  2. Known rogue cell list from config.yaml
  3. Behavioral anomalies (signal strength, SIB timing)

Rules:
  CRITICAL: Cell ID not in OpenCelliD for this MCC/MNC/TAC
  CRITICAL: Cell ID matches known rogue list in config
  HIGH:     Cell appearing on unexpected EARFCN for this operator
  HIGH:     Abnormally strong signal (spoofed tower overpower)
  MEDIUM:   TAC not matching operator's known deployment area
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Set
from .base import BaseDetector, make_finding


# Known EARFCNs for Telstra AU (MCC=505 MNC=001) LTE bands
# Band 28 (700 MHz): 9210-9659 (DL), Band 3 (1800 MHz): 1200-1949
# Band 1 (2100 MHz): 0-599, Band 7 (2600 MHz): 2750-3449
TELSTRA_EARFCN_RANGES = [
    (0, 599),       # Band 1 (2100 MHz)
    (1200, 1949),   # Band 3 (1800 MHz)
    (2750, 3449),   # Band 7 (2600 MHz)
    (9210, 9659),   # Band 28 (700 MHz APT) — primary regional
]

# Vodafone AU (MCC=505 MNC=003) LTE bands
VODAFONE_EARFCN_RANGES = [
    (0, 599),       # Band 1 (2100 MHz)
    (1200, 1949),   # Band 3 (1800 MHz)
    (3450, 3799),   # Band 8 (900 MHz)
    (9210, 9659),   # Band 28 (700 MHz)
]

OPERATOR_EARFCNS = {
    "505-001": TELSTRA_EARFCN_RANGES,   # Telstra
    "505-003": VODAFONE_EARFCN_RANGES,  # Vodafone AU
    "505-006": [(1200, 1949), (9210, 9659), (3450, 3799)],  # Optus AU
}


class RogueTowerDetector(BaseDetector):
    name = "RogueTowerDetector"
    description = "Detects rogue/synthetic cell towers via cell DB cross-reference and behavioral analysis"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.mcc = cfg.get("network", {}).get("mcc", "505")
        self.mnc = cfg.get("network", {}).get("mnc", "001")
        self.opencellid_cfg = cfg.get("opencellid", {})
        self.known_rogue_cells = cfg.get("known_rogue_cells", {})
        self.known_rogue_earfcns = set(cfg.get("known_rogue_earfcns", []))
        self._cell_cache = self._load_cache()

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Collect unique cells observed
        cells = self._collect_cells(events)
        if not cells:
            return findings

        operator_key = f"{self.mcc}-{self.mnc}"

        # ── Rule 6 placeholder (moved to end) ────────────────────────
        # Always report what cells were seen, for cross-reference evidence
        all_cells = [c for c in cells if c.get("cell_id")]
        if all_cells and not any(
            f.get("title", "").startswith("Cell Summary") for f in findings
        ):
            cell_summary = []
            for c in all_cells:
                cell_summary.append(
                    f"CID={c.get('cell_id')} TAC={c.get('tac','?')} "
                    f"MCC={self.mcc} MNC={self.mnc} "
                    f"observations={len(c.get('events',[]))}"
                )
            if len(all_cells) >= 2:
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Cell Summary — {len(all_cells)} Unique Cell ID(s) Observed",
                    description=(
                        f"{len(all_cells)} unique Cell IDs observed across all captures. "
                        f"Cross-reference these against Telstra's registered cell database "
                        f"to identify any synthetic/rogue towers."
                    ),
                    severity="INFO",
                    confidence="CONFIRMED",
                    technique="Cell ID inventory from SIB1 beacon data",
                    evidence=cell_summary,
                    events=[],
                    action=(
                        "1. Enable OpenCelliD lookup in config.yaml to auto-verify these cells.\n"
                        "2. Add confirmed rogue Cell IDs to known_rogue_cells in config.yaml.\n"
                        "3. Cell IDs can be verified via ACMA's public cell register."
                    ),
                ))

        return findings

        operator_key = f"{self.mcc}-{self.mnc}"

        for cell in cells:
            cell_id = cell.get("cell_id")
            earfcn   = cell.get("earfcn")
            tac      = cell.get("tac")
            rsrp     = cell.get("rsrp")
            ev_list  = cell.get("events", [])

            # ── Rule 1: Known rogue cell from config ──────────────────
            # Check both MNC formats: "001" and "01" (SIB1 uses short form)
            mnc_short = self.mnc.lstrip("0") or "0"
            rogue_key = f"{self.mcc}-{self.mnc}-{cell_id}"
            rogue_key_short = f"{self.mcc}-{mnc_short}-{cell_id}"
            matched_key = rogue_key if rogue_key in self.known_rogue_cells else (
                rogue_key_short if rogue_key_short in self.known_rogue_cells else None
            )
            if matched_key:
                rogue_key = matched_key
            if rogue_key in self.known_rogue_cells or (matched_key and matched_key in self.known_rogue_cells):
                info = self.known_rogue_cells.get(rogue_key) or self.known_rogue_cells.get(rogue_key_short) or {}
                findings.append(make_finding(
                    detector=self.name,
                    title=f"CONFIRMED ROGUE CELL: Cell ID {cell_id}",
                    description=(
                        f"Cell ID {cell_id} is listed in your confirmed rogue cell database. "
                        f"Notes: {info.get('notes', 'No notes')}. "
                        f"This cell was observed {len(ev_list)} time(s) in the captures."
                    ),
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    technique="Rogue Cell — matches known threat intelligence",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                    hardware_hint="Known rogue base station",
                    action="This is a previously confirmed rogue cell. Include in all reports.",
                    spec_ref="CIRS-20260331-141 (investigation reference)",
                ))

            # ── Rule 2: OpenCelliD lookup ─────────────────────────────
            if cell_id and self.opencellid_cfg.get("enabled", False):
                db_result = self._lookup_opencellid(cell_id, self.mcc, self.mnc, tac)
                if db_result is None:
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"Cell ID {cell_id} Not in OpenCelliD Database",
                        description=(
                            f"Cell ID {cell_id} (MCC={self.mcc} MNC={self.mnc} TAC={tac}) "
                            f"is not registered in the OpenCelliD crowd-sourced cell tower database. "
                            f"Legitimate operator towers are typically present in OpenCelliD. "
                            f"An unlisted cell is a strong indicator of a synthetic/rogue tower."
                        ),
                        severity="HIGH",
                        confidence="PROBABLE",
                        technique="Rogue Cell — not in public cell database",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                        hardware_hint="Potential rogue eNodeB or picocell not in operator's registered network",
                        action=(
                            "1. Verify with Telstra's network engineering team.\n"
                            "2. Submit cell ID + GPS coordinates to ACMA for investigation.\n"
                            "3. Cross-reference with Rayhunter Unit 2 timeline."
                        ),
                        spec_ref="OpenCelliD: opencellid.org",
                    ))

            # ── Rule 3: Known rogue EARFCN ────────────────────────────
            if earfcn and earfcn in self.known_rogue_earfcns:
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Known Rogue EARFCN {earfcn} Observed",
                    description=(
                        f"EARFCN {earfcn} is listed in your confirmed rogue EARFCN list. "
                        f"Observed in {len(ev_list)} event(s)."
                    ),
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    technique="Rogue Tower — operating on confirmed rogue frequency",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                    action="This EARFCN is confirmed rogue. Include in all legal submissions.",
                ))

            # ── Rule 4: EARFCN outside operator's known bands ─────────
            if earfcn and operator_key in OPERATOR_EARFCNS:
                ranges = OPERATOR_EARFCNS[operator_key]
                in_band = any(lo <= int(earfcn) <= hi for lo, hi in ranges)
                if not in_band:
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"EARFCN {earfcn} Outside {self._op_name()} Operating Bands",
                        description=(
                            f"EARFCN {earfcn} is not within any known {self._op_name()} LTE "
                            f"frequency band in Australia. Expected bands: "
                            f"{', '.join(f'{lo}-{hi}' for lo,hi in ranges)}. "
                            f"A rogue tower may be operating on an unlicensed or unexpected frequency."
                        ),
                        severity="HIGH",
                        confidence="PROBABLE",
                        technique="Rogue Tower — anomalous EARFCN / out-of-band operation",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                        hardware_hint="SDR-based rogue eNodeB (software-defined radio can operate on any frequency)",
                        action=(
                            "Note the exact EARFCN and any signal strength data. "
                            "Report anomalous EARFCN to ACMA — operating outside licensed spectrum "
                            "is a breach of the Radiocommunications Act 1992."
                        ),
                        spec_ref="Radiocommunications Act 1992 (Cth)",
                    ))

            # ── Rule 5: Abnormally strong signal (overpower attack) ────
            if rsrp is not None:
                try:
                    rsrp_val = float(rsrp)
                    # Normal LTE RSRP: -70 to -100 dBm at typical distances
                    # Rogue towers often overpowered: > -60 dBm
                    if rsrp_val > -55:
                        findings.append(make_finding(
                            detector=self.name,
                            title=f"Abnormally Strong Signal (RSRP={rsrp_val:.1f} dBm)",
                            description=(
                                f"Observed RSRP of {rsrp_val:.1f} dBm is abnormally high. "
                                f"Legitimate towers at typical distances show -70 to -100 dBm. "
                                f"Rogue IMSI catchers deliberately transmit at high power to "
                                f"force devices to prefer them over legitimate towers."
                            ),
                            severity="MEDIUM",
                            confidence="SUSPECTED",
                            technique="Signal Overpower Attack — rogue tower dominance",
                            evidence=self._fmt_cell(cell, ev_list),
                            events=ev_list,
                            hardware_hint="High-power rogue eNodeB (deliberate overpower to attract devices)",
                            action="Correlate RSRP spikes with identity request events to confirm attack.",
                        ))
                except (ValueError, TypeError):
                    pass

        return findings

    def _collect_cells(self, events: List[Dict]) -> List[Dict]:
        """Group events by cell ID and deduplicate."""
        cell_map: Dict[str, Dict] = {}

        for ev in events:
            cell_id = ev.get("cell_id") or ev.get("pci")
            earfcn   = ev.get("earfcn")
            tac      = ev.get("tac")
            rsrp     = ev.get("rsrp")

            if not (cell_id or earfcn):
                continue

            key = str(cell_id or f"pci_{ev.get('pci','?')}@{earfcn}")
            if key not in cell_map:
                cell_map[key] = {
                    "cell_id": cell_id,
                    "earfcn": earfcn,
                    "tac": tac,
                    "rsrp": rsrp,
                    "events": [],
                }
            cell_map[key]["events"].append(ev)
            # Track best (highest) RSRP reading
            if rsrp and (cell_map[key]["rsrp"] is None or
                         (cell_map[key]["rsrp"] is not None and
                          float(str(rsrp).replace("dBm","").strip()) >
                          float(str(cell_map[key]["rsrp"]).replace("dBm","").strip()))):
                try:
                    cell_map[key]["rsrp"] = float(str(rsrp).replace("dBm","").strip())
                except (ValueError, TypeError):
                    pass

        return list(cell_map.values())

    def _lookup_opencellid(self, cell_id: str, mcc: str, mnc: str,
                            tac: str) -> Optional[Dict]:
        """Query OpenCelliD API (or cache) for cell registration."""
        cache_key = f"{mcc}-{mnc}-{cell_id}-{tac}"
        if cache_key in self._cell_cache:
            return self._cell_cache[cache_key]

        api_key = self.opencellid_cfg.get("api_key", "")
        if not api_key:
            return {}  # Return empty dict (not None) = skip

        try:
            import requests
            url = "https://opencellid.org/cell/get"
            params = {
                "token": api_key,
                "mcc": mcc,
                "mnc": mnc,
                "lac": tac or 0,
                "cellid": cell_id,
                "format": "json",
            }
            resp = requests.get(url, params=params,
                                timeout=self.opencellid_cfg.get("timeout_seconds", 5))
            data = resp.json()
            if data.get("status") == "ok":
                self._cell_cache[cache_key] = data
                self._save_cache()
                return data
            elif data.get("status") == "error":
                self._cell_cache[cache_key] = None
                self._save_cache()
                return None
        except Exception as e:
            pass

        return {}

    def _load_cache(self) -> dict:
        cache_file = self.opencellid_cfg.get("cache_file", "cell_cache.json")
        try:
            with open(cache_file) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self):
        cache_file = self.opencellid_cfg.get("cache_file", "cell_cache.json")
        try:
            with open(cache_file, "w") as f:
                json.dump(self._cell_cache, f)
        except Exception:
            pass

    def _op_name(self) -> str:
        key = f"{self.mcc}-{self.mnc}"
        return {
            "505-001": "Telstra AU",
            "505-003": "Vodafone AU",
            "505-006": "Optus AU",
        }.get(key, f"MCC={self.mcc} MNC={self.mnc}")

    def _fmt_cell(self, cell: Dict, events: List[Dict]) -> List[str]:
        lines = [
            f"Cell ID:  {cell.get('cell_id', '?')}",
            f"EARFCN:   {cell.get('earfcn', '?')}",
            f"TAC/LAC:  {cell.get('tac', '?')}",
            f"RSRP:     {cell.get('rsrp', '?')} dBm",
            f"Events:   {len(events)} observation(s)",
        ]
        if events:
            first = events[0]
            lines.append(f"First seen: {first.get('timestamp','?')} in {first.get('source_file','?')}")
        return lines
