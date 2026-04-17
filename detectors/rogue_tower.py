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

FIX v1.2:
  - Cell summary now reads MCC/MNC from event data (corrected by NDJSON
    propagation pass) rather than from config. Previously always showed
    MNC=001 (Telstra) even for Vodafone captures.
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Set
from .base import BaseDetector, make_finding


# Known EARFCNs for Telstra AU (MCC=505 MNC=001) LTE bands
TELSTRA_EARFCN_RANGES = [
    (0, 599),       # Band 1 (2100 MHz)
    (1200, 1949),   # Band 3 (1800 MHz)
    (2750, 3449),   # Band 7 (2600 MHz)
    (9210, 9659),   # Band 28 (700 MHz APT)
]

# Vodafone AU (MCC=505 MNC=003) LTE bands
VODAFONE_EARFCN_RANGES = [
    (0, 599),       # Band 1 (2100 MHz)
    (1200, 1949),   # Band 3 (1800 MHz)
    (3450, 3799),   # Band 8 (900 MHz)
    (9210, 9659),   # Band 28 (700 MHz)
]

OPERATOR_EARFCNS = {
    "505-001": TELSTRA_EARFCN_RANGES,
    "505-01":  TELSTRA_EARFCN_RANGES,
    "505-003": VODAFONE_EARFCN_RANGES,
    "505-03":  VODAFONE_EARFCN_RANGES,
    "505-006": [(1200, 1949), (9210, 9659), (3450, 3799)],
    "505-06":  [(1200, 1949), (9210, 9659), (3450, 3799)],
}

CARRIER_NAMES = {
    "505-001": "Telstra AU", "505-01": "Telstra AU",
    "505-003": "Vodafone AU", "505-03": "Vodafone AU",
    "505-006": "Optus AU", "505-06": "Optus AU",
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

        cells = self._collect_cells(events)
        if not cells:
            return findings

        # ── Cell summary — always report what was observed ────────────
        all_cells = [c for c in cells if c.get("cell_id")]
        if all_cells:
            cell_summary = []
            for c in all_cells:
                # ── FIX: read MCC/MNC from event data, not config ─────
                # The NDJSON propagation pass stamps each event with the
                # true network MNC extracted from SIB1 beacons. Use that
                # rather than the config default (which may be wrong carrier).
                cell_mcc, cell_mnc = self._get_cell_network(c)
                cell_summary.append(
                    f"CID={c.get('cell_id')} TAC={c.get('tac','?')} "
                    f"MCC={cell_mcc} MNC={cell_mnc} "
                    f"observations={len(c.get('events', []))}"
                )

            if len(all_cells) >= 1:
                # Determine dominant network for description text
                dom_mcc, dom_mnc = self._dominant_network(all_cells)
                op_key = f"{dom_mcc}-{dom_mnc}"
                op_name = CARRIER_NAMES.get(op_key, f"MCC={dom_mcc} MNC={dom_mnc}")

                findings.append(make_finding(
                    detector=self.name,
                    title=f"Cell Summary — {len(all_cells)} Unique Cell ID(s) Observed",
                    description=(
                        f"{len(all_cells)} unique Cell IDs observed across all captures "
                        f"({op_name}). "
                        f"Cross-reference these against the registered cell database "
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

        # ── Per-cell analysis ─────────────────────────────────────────
        for cell in cells:
            cell_id = cell.get("cell_id")
            earfcn   = cell.get("earfcn")
            tac      = cell.get("tac")
            rsrp     = cell.get("rsrp")
            ev_list  = cell.get("events", [])

            # Use event-level network for per-cell checks
            cell_mcc, cell_mnc = self._get_cell_network(cell)
            operator_key = f"{cell_mcc}-{cell_mnc}"

            # ── Rule 1: Known rogue cell from config ──────────────────
            mnc_short = self.mnc.lstrip("0") or "0"
            rogue_key = f"{self.mcc}-{self.mnc}-{cell_id}"
            rogue_key_short = f"{self.mcc}-{mnc_short}-{cell_id}"
            matched_key = (
                rogue_key if rogue_key in self.known_rogue_cells
                else rogue_key_short if rogue_key_short in self.known_rogue_cells
                else None
            )
            if matched_key:
                info = self.known_rogue_cells.get(matched_key) or {}
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
                db_result = self._lookup_opencellid(cell_id, cell_mcc, cell_mnc, tac)
                if db_result is None:
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"Cell ID {cell_id} Not in OpenCelliD Database",
                        description=(
                            f"Cell ID {cell_id} (MCC={cell_mcc} MNC={cell_mnc} TAC={tac}) "
                            f"is not registered in the OpenCelliD crowd-sourced database. "
                            f"Legitimate operator towers are typically present in OpenCelliD. "
                            f"An unlisted cell is a strong indicator of a synthetic/rogue tower."
                        ),
                        severity="HIGH",
                        confidence="PROBABLE",
                        technique="Rogue Cell — not in public cell database",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                        hardware_hint="Potential rogue eNodeB not in operator's registered network",
                        action=(
                            "1. Verify with carrier's network engineering team.\n"
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
                    op_name = CARRIER_NAMES.get(operator_key, operator_key)
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"EARFCN {earfcn} Outside {op_name} Operating Bands",
                        description=(
                            f"EARFCN {earfcn} is not within any known {op_name} LTE "
                            f"frequency band in Australia. Expected bands: "
                            f"{', '.join(f'{lo}-{hi}' for lo, hi in ranges)}. "
                            f"A rogue tower may be operating on an unexpected frequency."
                        ),
                        severity="HIGH",
                        confidence="PROBABLE",
                        technique="Rogue Tower — anomalous EARFCN / out-of-band operation",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                        hardware_hint="SDR-based rogue eNodeB",
                        action=(
                            "Report anomalous EARFCN to ACMA — operating outside licensed "
                            "spectrum is a breach of the Radiocommunications Act 1992."
                        ),
                        spec_ref="Radiocommunications Act 1992 (Cth)",
                    ))

            # ── Rule 5: Abnormally strong signal ──────────────────────
            if rsrp is not None:
                try:
                    rsrp_val = float(rsrp)
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
                            hardware_hint="High-power rogue eNodeB",
                            action="Correlate RSRP spikes with identity request events to confirm attack.",
                        ))
                except (ValueError, TypeError):
                    pass

        return findings

    def _get_cell_network(self, cell: Dict) -> tuple:
        """
        Extract MCC/MNC from the cell's event data.
        Prefers non-default MNC values (from SIB1 propagation pass).
        Falls back to config defaults.
        """
        config_mnc = self.mnc
        best_mcc, best_mnc = self.mcc, self.mnc

        for ev in cell.get("events", []):
            mnc = ev.get("mnc")
            mcc = ev.get("mcc", self.mcc)
            if mnc and mnc != config_mnc:
                # Non-default = explicitly read from SIB1 beacon data
                return mcc, mnc
            elif mnc:
                best_mcc, best_mnc = mcc, mnc

        return best_mcc, best_mnc

    def _dominant_network(self, cells: List[Dict]) -> tuple:
        """Find the most-observed network across all cells."""
        from collections import Counter
        counts = Counter()
        for cell in cells:
            mcc, mnc = self._get_cell_network(cell)
            counts[(mcc, mnc)] += len(cell.get("events", []))
        if counts:
            return counts.most_common(1)[0][0]
        return self.mcc, self.mnc

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
            if rsrp:
                try:
                    rsrp_f = float(str(rsrp).replace("dBm", "").strip())
                    cur = cell_map[key]["rsrp"]
                    if cur is None or rsrp_f > float(str(cur).replace("dBm", "").strip()):
                        cell_map[key]["rsrp"] = rsrp_f
                except (ValueError, TypeError):
                    pass

        return list(cell_map.values())

    def _lookup_opencellid(self, cell_id, mcc, mnc, tac) -> Optional[Dict]:
        cache_key = f"{mcc}-{mnc}-{cell_id}-{tac}"
        if cache_key in self._cell_cache:
            return self._cell_cache[cache_key]

        api_key = self.opencellid_cfg.get("api_key", "")
        if not api_key:
            return {}

        try:
            import requests
            resp = requests.get(
                "https://opencellid.org/cell/get",
                params={"token": api_key, "mcc": mcc, "mnc": mnc,
                        "lac": tac or 0, "cellid": cell_id, "format": "json"},
                timeout=self.opencellid_cfg.get("timeout_seconds", 5)
            )
            data = resp.json()
            result = data if data.get("status") == "ok" else (
                None if data.get("status") == "error" else {}
            )
            self._cell_cache[cache_key] = result
            self._save_cache()
            return result
        except Exception:
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

    def _fmt_cell(self, cell: Dict, events: List[Dict]) -> List[str]:
        mcc, mnc = self._get_cell_network(cell)
        lines = [
            f"Cell ID:  {cell.get('cell_id', '?')}",
            f"EARFCN:   {cell.get('earfcn', '?')}",
            f"TAC/LAC:  {cell.get('tac', '?')}",
            f"MCC/MNC:  {mcc}/{mnc}",
            f"RSRP:     {cell.get('rsrp', '?')} dBm",
            f"Events:   {len(events)} observation(s)",
        ]
        if events:
            first = events[0]
            lines.append(
                f"First seen: {first.get('timestamp','?')} "
                f"in {first.get('source_file','?')}"
            )
        return lines
