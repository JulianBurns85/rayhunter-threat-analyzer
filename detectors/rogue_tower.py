from typing import Any
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
        self.mcc = str(cfg.get("network", {}).get("mcc", "505"))
        self.mnc = str(cfg.get("network", {}).get("mnc", "001"))
        self.opencellid_cfg = cfg.get("opencellid", {})
        det_cfg = cfg.get("detection", {})
        rt_cfg = det_cfg.get("rogue_tower", {}) if isinstance(det_cfg, dict) else {}
        earfcn_cfg = det_cfg.get("earfcn_anomaly", {}) if isinstance(det_cfg, dict) else {}

        self.known_rogue_cells = cfg.get("known_rogue_cells", {})
        self.known_rogue_cids = {str(x) for x in (rt_cfg.get("known_rogue_cids") or [])}
        self.known_rogue_enbs = {int(x) for x in (rt_cfg.get("known_rogue_enbs") or [])}
        self.watchlist_cids = {str(x) for x in (rt_cfg.get("watchlist_cids") or [])}

        rogue_earfcns = list(cfg.get("known_rogue_earfcns") or []) + list(earfcn_cfg.get("known_rogue_earfcns") or [])
        self.known_rogue_earfcns = {int(x) for x in rogue_earfcns if x is not None}
        self._cell_cache = self._load_cache()

    def _norm_op_key(self, mcc: str, mnc: str) -> str:
        mnc_s = str(mnc or self.mnc).strip()
        if mnc_s in {"1", "01", "001"}:
            return f"{mcc}-001"
        if mnc_s in {"3", "03", "003"}:
            return f"{mcc}-003"
        if mnc_s in {"6", "06", "006"}:
            return f"{mcc}-006"
        return f"{mcc}-{mnc_s}"

    def _op_name_for(self, op_key: str) -> str:
        if hasattr(self, "_op_name"):
            try:
                return self._op_name()
            except TypeError:
                pass
        return {
            "505-001": "Telstra",
            "505-003": "Vodafone",
            "505-006": "Optus",
        }.get(op_key, op_key)

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        cells = self._collect_cells(events)
        if not cells:
            return findings

        all_cells = [c for c in cells if c.get("cell_id") and not c.get("is_pci_only")]
        if len(all_cells) >= 2 and not any(
            f.get("title", "").startswith("Cell Summary") for f in findings
        ):
            cell_summary = []
            for c in all_cells:
                c_mcc = c.get("mcc", self.mcc)
                c_mnc = c.get("mnc", self.mnc)
                carrier_map = {
                    "001": "Telstra", "01": "Telstra", "1": "Telstra",
                    "003": "Vodafone AU", "03": "Vodafone AU", "3": "Vodafone AU",
                    "006": "Optus AU", "06": "Optus AU", "6": "Optus AU",
                }
                carrier = carrier_map.get(c_mnc, f"MNC={c_mnc}")
                cell_summary.append(
                    f"CID={c.get('cell_id')} TAC={c.get('tac','?')} "
                    f"MCC={c_mcc} MNC={c_mnc} ({carrier}) "
                    f"observations={len(c.get('events',[]))}"
                )
            findings.append(make_finding(
                detector=self.name,
                title=f"Cell Summary ? {len(all_cells)} Unique Cell ID(s) Observed",
                description=(
                    f"{len(all_cells)} unique Cell IDs observed across all captures. "
                    f"Cross-reference these against registered cell databases "
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

        for cell in cells:
            if cell.get("is_pci_only"):
                continue
            cell_id = cell.get("cell_id")
            cid_str = str(cell_id) if cell_id is not None else ""
            earfcns = cell.get("earfcns") or ([cell.get("earfcn")] if cell.get("earfcn") is not None else [])
            tac = cell.get("tac")
            rsrp = cell.get("rsrp")
            ev_list = cell.get("events", [])
            c_mcc = str(cell.get("mcc") or self.mcc)
            c_mnc = str(cell.get("mnc") or self.mnc)
            op_key = self._norm_op_key(c_mcc, c_mnc)
            op_name = self._op_name_for(op_key)

            # Rule 1a: Analyst rogue list (CID or eNB) ? non-CRITICAL candidate
            enb = self._extract_enb(cell_id)
            if cid_str in self.known_rogue_cids or (enb is not None and enb in self.known_rogue_enbs):
                reason = f"eNB {enb}" if (cid_str not in self.known_rogue_cids and enb in self.known_rogue_enbs) else f"CID {cid_str}"
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Cell {cid_str} is on the analyst rogue list ({reason})",
                    description=(
                        f"Cell ID {cid_str} matched analyst rogue list criteria ({reason}). "
                        f"Observed {len(ev_list)} time(s) in capture."
                    ),
                    severity="HIGH",
                    confidence="SUSPECTED",
                    technique="Analyst rogue cell/eNB list match",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                ))

            # Rule 1b: Watchlist CID
            if cid_str in self.watchlist_cids:
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Watchlist cell {cid_str} observed",
                    description=f"Cell ID {cid_str} is on the analyst watchlist.",
                    severity="MEDIUM",
                    confidence="SUSPECTED",
                    technique="Watchlist cell ID match",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                ))

            # Rule 1c: Legacy confirmed rogue cell map
            mnc_short = self.mnc.lstrip("0") or "0"
            rogue_key = f"{self.mcc}-{self.mnc}-{cell_id}"
            rogue_key_short = f"{self.mcc}-{mnc_short}-{cell_id}"
            matched_key = rogue_key if rogue_key in self.known_rogue_cells else (
                rogue_key_short if rogue_key_short in self.known_rogue_cells else None
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
                    technique="Rogue Cell ? matches known threat intelligence",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                    hardware_hint="Known rogue base station",
                    action="This is a previously confirmed rogue cell. Include in all reports.",
                    spec_ref="CIRS-20260331-141 (investigation reference)",
                ))

            # Rule 2: OpenCelliD lookup (never for PCI-only cells)
            if cid_str and self.opencellid_cfg.get("enabled", False):
                db_result = self._lookup_opencellid(cid_str, c_mcc, c_mnc, tac)
                if db_result in (None, "NOT_FOUND"):
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"Cell ID {cid_str} Not in OpenCelliD Database",
                        description=(
                            f"Cell ID {cid_str} (MCC={c_mcc} MNC={c_mnc} TAC={tac}) "
                            f"is not registered in the OpenCelliD crowd-sourced cell tower database."
                        ),
                        severity="HIGH",
                        confidence="PROBABLE",
                        technique="Rogue Cell ? not in public cell database",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                        spec_ref="OpenCelliD: opencellid.org",
                    ))

            # Rule 3 & 4 across all observed EARFCNs for this cell
            for ef in earfcns:
                if ef is None:
                    continue
                try:
                    ef_int = int(ef)
                except (ValueError, TypeError):
                    continue

                if ef_int in self.known_rogue_earfcns:
                    findings.append(make_finding(
                        detector=self.name,
                        title=f"Known Rogue EARFCN {ef_int} Observed",
                        description=(
                            f"EARFCN {ef_int} is listed in your confirmed rogue EARFCN list. "
                            f"Observed in {len(ev_list)} event(s)."
                        ),
                        severity="HIGH",
                        confidence="SUSPECTED",
                        technique="Rogue Tower ? operating on confirmed rogue frequency",
                        evidence=self._fmt_cell(cell, ev_list),
                        events=ev_list,
                    ))

                if op_key in OPERATOR_EARFCNS:
                    ranges = OPERATOR_EARFCNS[op_key]
                    if not any(lo <= ef_int <= hi for lo, hi in ranges):
                        findings.append(make_finding(
                            detector=self.name,
                            title=f"EARFCN {ef_int} outside {op_name} Operating Bands",
                            description=(
                                f"EARFCN {ef_int} is not within any known {op_name} LTE band. "
                                f"Expected ranges: {', '.join(f'{lo}-{hi}' for lo, hi in ranges)}."
                            ),
                            severity="HIGH",
                            confidence="PROBABLE",
                            technique="EARFCN outside operator band allocation",
                            evidence=self._fmt_cell(cell, ev_list),
                            events=ev_list,
                        ))

            # Rule 5: Abnormally strong signal
            if rsrp is not None and isinstance(rsrp, (int, float)) and rsrp > -55:
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Abnormally Strong Signal (RSRP={rsrp:.1f} dBm)",
                    description=f"Observed RSRP of {rsrp:.1f} dBm is abnormally high.",
                    severity="MEDIUM",
                    confidence="SUSPECTED",
                    technique="Signal Overpower Attack ? rogue tower dominance",
                    evidence=self._fmt_cell(cell, ev_list),
                    events=ev_list,
                ))

        return findings

    @staticmethod
    def _parse_rsrp(val: Any) -> Optional[float]:
        if val is None or isinstance(val, bool):
            return None
        if isinstance(val, (int, float)):
            f = float(val)
            return f if f == f and abs(f) != float("inf") else None
        s = str(val).replace("dBm", "").strip()
        if not s or s.upper() in {"N/A", "NA", "NONE", "NULL", "NAN"}:
            return None
        try:
            f = float(s)
            return f if f == f and abs(f) != float("inf") else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_enb(cell_id: Any) -> Optional[int]:
        try:
            cid_int = int(str(cell_id).strip())
            if cid_int > 255:
                return cid_int >> 8
        except (ValueError, TypeError):
            pass
        return None

    def _collect_cells(self, events: List[Dict]) -> List[Dict]:
        """Group events by cell ID (or PCI fallback) and deduplicate."""
        cell_map: Dict[str, Dict] = {}

        for ev in events:
            raw_cid = ev.get("cell_id")
            has_cid = raw_cid is not None and str(raw_cid).strip() != ""
            raw_pci = ev.get("pci")
            is_pci_only = (not has_cid) and raw_pci is not None
            cell_id = str(raw_cid).strip() if has_cid else raw_pci
            earfcn = ev.get("earfcn")
            tac = ev.get("tac")
            rsrp_val = self._parse_rsrp(ev.get("rsrp"))
            ev_mcc = str(ev.get("mcc") or self.mcc)
            ev_mnc = str(ev.get("mnc") or self.mnc)

            if not (cell_id or earfcn):
                continue

            key = str(cell_id) if not is_pci_only else f"pci_{raw_pci}@{earfcn}"
            if key not in cell_map:
                cell_map[key] = {
                    "cell_id": cell_id,
                    "is_pci_only": is_pci_only,
                    "earfcn": earfcn,
                    "earfcns": [earfcn] if earfcn is not None else [],
                    "tac": tac,
                    "rsrp": rsrp_val,
                    "mcc": ev_mcc,
                    "mnc": ev_mnc,
                    "events": [],
                }
            else:
                if earfcn is not None and earfcn not in cell_map[key]["earfcns"]:
                    cell_map[key]["earfcns"].append(earfcn)
                if earfcn is not None:
                    cell_map[key]["earfcn"] = earfcn
                if tac is not None and cell_map[key]["tac"] is None:
                    cell_map[key]["tac"] = tac

            cell_map[key]["events"].append(ev)
            if rsrp_val is not None:
                cur = cell_map[key]["rsrp"]
                if cur is None or rsrp_val > cur:
                    cell_map[key]["rsrp"] = rsrp_val

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
                msg = str(data.get("message", "")).lower()
                if "not found" in msg:
                    self._cell_cache[cache_key] = "NOT_FOUND"
                    self._save_cache()
                    return "NOT_FOUND"
                return {}
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




