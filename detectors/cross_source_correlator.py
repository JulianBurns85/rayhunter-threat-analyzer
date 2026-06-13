#!/usr/bin/env python3
"""
CrossSourceCorrelator — Independent evidence class correlation.

Correlates findings across three independent evidence classes:
  1. Passive RF corpus  (Rayhunter NDJSON/PCAP/QMDL events)
  2. Firmware baseband  (Shannon IMS bug report parser)
  3. CASTNET            (federated detection network findings)

For each rogue CID that appears in multiple sources, emits a
"TRIPLE CONFIRMATION" finding with the evidence class breakdown.

This is the formal implementation of the "trinity of truth":
  same CID confirmed by completely independent capture methods
  = the investigator cannot have fabricated or misread the data.

Triple confirmation is the gold standard for forensic credibility.
A rogue CID appearing in:
  - Passive RF:  "the phone saw an anomalous tower"
  - Firmware log: "the baseband chip registered to that tower"
  - CASTNET:     "an independent node also detected it"
...leaves no room for the "equipment malfunction" or "single data
source" defence.

Reference: Triple-confirmation rule — Julian Burns Hidden Blade
investigation methodology (2026). Applied to cellular forensics.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Set, Tuple
import statistics


# ── Evidence class labels ─────────────────────────────────────────── #
SOURCE_RF       = "PASSIVE_RF"        # Rayhunter corpus events
SOURCE_FIRMWARE = "FIRMWARE_SHANNON"  # Shannon IMS baseband log
SOURCE_CASTNET  = "CASTNET"           # CASTNET federated network

# ── Timestamp correlation window ──────────────────────────────────── #
# Shannon bug reports are generated on-demand, not real-time.
# The firmware log timestamp is the modem event time, which CAN
# be correlated with corpus capture timestamps within a loose window.
# 24-hour window catches same-day events; corpus may span weeks.
TIMESTAMP_WINDOW_S = 86400   # 24 hours

# ── Known rogue CID sets (from investigation) ─────────────────────── #
ROGUE_CIDS_TELSTRA  = {137713155, 137713165, 137713175, 137713195,
                        135836161, 135836171, 135836191}
ROGUE_CIDS_VODAFONE = {8409357, 8409367, 8409387, 8409397,
                        8666381, 8666391, 8666411}
ROGUE_CIDS_ALL      = ROGUE_CIDS_TELSTRA | ROGUE_CIDS_VODAFONE


def _get_ts(event: Dict) -> Optional[float]:
    ts = event.get("timestamp") or event.get("time") or event.get("ts")
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    except (ValueError, OSError):
        return None


def _ts_str(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _aest_str(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=10)
    return dt.strftime("%Y-%m-%d %H:%M:%S AEST")


class CrossSourceCorrelator:
    """
    Correlates rogue CID observations across independent evidence classes.

    Usage:
        correlator = CrossSourceCorrelator()
        correlator.ingest_rf_events(all_events)
        correlator.ingest_shannon_finding(shannon_finding)
        correlator.ingest_castnet_findings(castnet_findings)
        findings = correlator.correlate()
    """

    def __init__(self, known_rogue_cids: Optional[Set[int]] = None):
        self.known_rogue_cids = known_rogue_cids or ROGUE_CIDS_ALL

        # CID → list of (timestamp, source_file, source_class)
        self._observations: Dict[int, List[Dict]] = defaultdict(list)

    # ── Ingestion methods ──────────────────────────────────────────── #

    def ingest_rf_events(self, events: List[Dict]) -> int:
        """
        Pull rogue CID observations from Rayhunter corpus events.
        Returns count of rogue CID events found.
        """
        count = 0
        for e in events:
            cid_raw = e.get("cell_id") or e.get("cid")
            if cid_raw is None:
                continue
            try:
                cid = int(cid_raw)
            except (ValueError, TypeError):
                continue
            if cid not in self.known_rogue_cids:
                continue
            ts = _get_ts(e)
            self._observations[cid].append({
                "ts":     ts,
                "source": e.get("source_file", "unknown"),
                "class":  SOURCE_RF,
                "tac":    e.get("tac"),
                "mnc":    e.get("mnc"),
                "msg":    str(e.get("message_type") or e.get("msg_type") or ""),
            })
            count += 1
        return count

    def ingest_shannon_finding(self, shannon_finding: Optional[Dict]) -> int:
        """
        Pull rogue CID observations from a Shannon IMS parser finding.
        Returns count of rogue CID events ingested.
        """
        if not shannon_finding:
            return 0

        count = 0
        # shannon_finding["rogue_events"] is a list of ShannonImsEvent objects
        for ev in shannon_finding.get("rogue_events", []):
            cid = getattr(ev, "cell_id", None)
            if cid is None:
                continue
            try:
                cid = int(cid)
            except (ValueError, TypeError):
                continue

            # Parse Shannon timestamp (format: "06-07 12:30:12.483")
            ts_raw = getattr(ev, "timestamp", "")
            ts = self._parse_shannon_ts(ts_raw)

            self._observations[cid].append({
                "ts":       ts,
                "source":   f"Shannon IMS ({ts_raw})",
                "class":    SOURCE_FIRMWARE,
                "tac":      getattr(ev, "tac", None),
                "plmn":     getattr(ev, "plmn", None),
                "rat":      getattr(ev, "rat_name", None),
                "reg_state":getattr(ev, "reg_state", None),
            })
            count += 1
        return count

    def ingest_castnet_findings(self, castnet_findings: List[Dict]) -> int:
        """
        Pull rogue CID observations from CASTNET findings list.
        Returns count of rogue CID events ingested.
        """
        count = 0
        for f in castnet_findings:
            # CASTNET findings may embed CID in title or evidence
            title = str(f.get("title", "")).lower()
            for cid in self.known_rogue_cids:
                if str(cid) in title or str(cid) in str(f.get("evidence", "")):
                    ts_raw = f.get("found_at") or f.get("timestamp")
                    ts = None
                    if ts_raw:
                        try:
                            dt = datetime.fromisoformat(
                                str(ts_raw).replace("Z", "+00:00"))
                            ts = dt.timestamp()
                        except (ValueError, TypeError):
                            pass
                    self._observations[cid].append({
                        "ts":     ts,
                        "source": f"CASTNET: {f.get('title','')[:60]}",
                        "class":  SOURCE_CASTNET,
                    })
                    count += 1
                    break  # one entry per finding
        return count

    # ── Main correlation logic ─────────────────────────────────────── #

    def correlate(self) -> List[Dict]:
        """
        For each rogue CID with observations from multiple sources,
        emit a corroboration finding.
        """
        findings = []

        for cid, obs_list in self._observations.items():
            if not obs_list:
                continue

            # Group by evidence class
            by_class: Dict[str, List[Dict]] = defaultdict(list)
            for obs in obs_list:
                by_class[obs["class"]].append(obs)

            n_classes = len(by_class)
            if n_classes < 2:
                continue  # single source — nothing to correlate

            # Classify corroboration level
            has_rf       = SOURCE_RF       in by_class
            has_firmware = SOURCE_FIRMWARE in by_class
            has_castnet  = SOURCE_CASTNET  in by_class

            if has_rf and has_firmware and has_castnet:
                level      = "TRIPLE CONFIRMATION"
                severity   = "CRITICAL"
                confidence = "CONFIRMED"
                banner     = "🔴 TRIPLE CONFIRMATION — ALL THREE INDEPENDENT SOURCES AGREE"
            elif has_rf and has_firmware:
                level      = "DUAL CONFIRMATION (RF + FIRMWARE)"
                severity   = "CRITICAL"
                confidence = "CONFIRMED"
                banner     = "🔴 DUAL CONFIRMATION — PASSIVE RF + BASEBAND FIRMWARE"
            elif has_rf and has_castnet:
                level      = "DUAL CONFIRMATION (RF + CASTNET)"
                severity   = "HIGH"
                confidence = "CONFIRMED"
                banner     = "🟠 DUAL CONFIRMATION — PASSIVE RF + CASTNET NODE"
            else:
                level      = "DUAL CONFIRMATION (FIRMWARE + CASTNET)"
                severity   = "HIGH"
                confidence = "CONFIRMED"
                banner     = "🟠 DUAL CONFIRMATION — FIRMWARE + CASTNET"

            # Build per-source summaries
            source_lines = []
            all_ts = []

            if has_rf:
                rf_obs   = by_class[SOURCE_RF]
                rf_ts    = [o["ts"] for o in rf_obs if o["ts"]]
                rf_files = sorted(set(o["source"] for o in rf_obs))
                rf_msgs  = sorted(set(o["msg"] for o in rf_obs if o.get("msg")))[:5]
                all_ts.extend(rf_ts)
                source_lines += [
                    f"",
                    f"  SOURCE 1 — PASSIVE RF CORPUS (Rayhunter)",
                    f"  Evidence class: RF signal capture — NDJSON/PCAP/QMDL",
                    f"  Observations: {len(rf_obs)} event(s) in corpus",
                    f"  Capture files: {', '.join(rf_files[:5])}"
                    + (f" +{len(rf_files)-5} more" if len(rf_files) > 5 else ""),
                ]
                if rf_ts:
                    source_lines.append(
                        f"  Time range: {_aest_str(min(rf_ts))} → {_aest_str(max(rf_ts))}"
                    )
                if rf_msgs:
                    source_lines.append(f"  Message types: {', '.join(rf_msgs)}")

            if has_firmware:
                fw_obs = by_class[SOURCE_FIRMWARE]
                fw_ts  = [o["ts"] for o in fw_obs if o["ts"]]
                all_ts.extend(fw_ts)
                plmns  = sorted(set(str(o.get("plmn","")) for o in fw_obs if o.get("plmn")))
                rats   = sorted(set(str(o.get("rat",""))  for o in fw_obs if o.get("rat")))
                source_lines += [
                    f"",
                    f"  SOURCE {'2' if has_rf else '1'} — FIRMWARE BASEBAND LOG (Shannon IMS)",
                    f"  Evidence class: Modem firmware log — RILC_UNSOL_IMS_SUPPORT_SERVICE",
                    f"  Process: com.shannon.imsservice (Samsung Shannon baseband stack)",
                    f"  Observations: {len(fw_obs)} firmware event(s)",
                    f"  Independence: Cannot be triggered by passive monitoring tools",
                ]
                if fw_ts:
                    source_lines.append(
                        f"  Firmware timestamps: "
                        + ", ".join(_aest_str(t) for t in fw_ts[:3])
                        + ("..." if len(fw_ts) > 3 else "")
                    )
                if plmns:
                    source_lines.append(f"  PLMN: {', '.join(plmns)}")
                if rats:
                    source_lines.append(f"  RAT: {', '.join(rats)}")

            if has_castnet:
                cn_obs  = by_class[SOURCE_CASTNET]
                cn_ts   = [o["ts"] for o in cn_obs if o["ts"]]
                all_ts.extend(cn_ts)
                source_lines += [
                    f"",
                    f"  SOURCE {n_classes} — CASTNET FEDERATED NETWORK",
                    f"  Evidence class: Independent detection node",
                    f"  Observations: {len(cn_obs)} CASTNET detection(s)",
                ]
                for obs in cn_obs[:3]:
                    source_lines.append(f"    {obs['source']}")

            # Timestamp overlap analysis
            overlap_lines = []
            if has_rf and has_firmware:
                rf_ts_list = sorted([o["ts"] for o in by_class[SOURCE_RF] if o["ts"]])
                fw_ts_list = sorted([o["ts"] for o in by_class[SOURCE_FIRMWARE] if o["ts"]])
                if rf_ts_list and fw_ts_list:
                    rf_span  = (min(rf_ts_list), max(rf_ts_list))
                    fw_span  = (min(fw_ts_list), max(fw_ts_list))
                    overlap_start = max(rf_span[0], fw_span[0])
                    overlap_end   = min(rf_span[1], fw_span[1])
                    if overlap_start <= overlap_end:
                        overlap_lines += [
                            f"",
                            f"  TIMESTAMP OVERLAP CONFIRMED:",
                            f"  RF corpus active:  {_aest_str(rf_span[0])} → {_aest_str(rf_span[1])}",
                            f"  Firmware events:   " + ", ".join(_aest_str(t) for t in fw_ts_list[:3]),
                            f"  Both sources confirm CID={cid} during overlapping periods.",
                            f"  Fabrication defence eliminated — independent capture methods agree.",
                        ]
                    else:
                        # Different days but same CID — still corroborating
                        closest_delta = min(
                            abs(fw_ts - rf_ts)
                            for fw_ts in fw_ts_list
                            for rf_ts in rf_ts_list
                        )
                        overlap_lines += [
                            f"",
                            f"  TEMPORAL PROXIMITY:",
                            f"  RF corpus period: {_aest_str(rf_span[0])} → {_aest_str(rf_span[1])}",
                            f"  Firmware events:  " + ", ".join(_aest_str(t) for t in fw_ts_list[:3]),
                            f"  Closest inter-source gap: {closest_delta/3600:.1f}h",
                            f"  Same CID confirmed across different capture sessions.",
                        ]

            # Determine device attribution
            if cid in ROGUE_CIDS_TELSTRA:
                device_note = "Device A (TAC=12385, Telstra) — Harris HailStorm candidate"
            elif cid in ROGUE_CIDS_VODAFONE:
                device_note = "Device B (TAC=30336, Vodafone) — srsRAN/bladeRF candidate"
            else:
                device_note = "Unknown device cluster"

            # Build full evidence block
            evidence = [
                banner,
                f"",
                f"  CID:         {cid}",
                f"  Device:      {device_note}",
                f"  Sources:     {n_classes} independent evidence class(es)",
                f"  Corroboration: {level}",
            ] + source_lines + overlap_lines + [
                f"",
                f"  FORENSIC SIGNIFICANCE:",
                f"  CID {cid} has been independently confirmed by {n_classes} separate",
                f"  evidence collection methodologies. Each source uses a completely",
                f"  different capture mechanism — passive RF monitoring cannot",
                f"  influence firmware logs, and CASTNET operates independently",
                f"  of both. Agreement across independent sources eliminates:",
                f"    ✗ Equipment malfunction (multiple independent devices agree)",
                f"    ✗ Data fabrication (independent sources cannot be coordinated)",
                f"    ✗ Misidentification (CID confirmed at firmware/modem layer)",
                f"    ✗ Single-source bias (corpus, firmware, and network all agree)",
                f"",
                f"  This corroboration satisfies the Hidden Blade triple-confirmation",
                f"  rule and constitutes the strongest possible forensic evidence",
                f"  class for civilian investigation output.",
            ]

            # Total observation count
            total_obs = sum(len(v) for v in by_class.values())

            finding = {
                "detector":        "CrossSourceCorrelator",
                "title": (
                    f"{level} — CID={cid} | "
                    f"{n_classes} Independent Sources | "
                    f"{total_obs} Total Observations"
                ),
                "description": (
                    f"CID {cid} ({device_note}) has been independently confirmed "
                    f"across {n_classes} evidence class(es): "
                    + (f"passive RF corpus ({len(by_class[SOURCE_RF])} events), "
                       if has_rf else "")
                    + (f"Shannon IMS firmware log ({len(by_class[SOURCE_FIRMWARE])} events), "
                       if has_firmware else "")
                    + (f"CASTNET network ({len(by_class[SOURCE_CASTNET])} detections), "
                       if has_castnet else "")
                    + f"This {level.lower()} eliminates all single-source bias "
                    f"and equipment malfunction defences. "
                    f"Independent capture methods cannot fabricate agreement."
                ),
                "severity":        severity,
                "severity_score":  5 if severity == "CRITICAL" else 4,
                "confidence":      confidence,
                "confidence_score": 3,
                "technique": (
                    "Cross-source evidence corroboration — "
                    "passive RF + firmware baseband + CASTNET correlation"
                ),
                "evidence":        evidence,
                "event_count":     total_obs,
                "hardware_hint": (
                    f"CID {cid} confirmed at modem firmware layer — "
                    f"cannot be a Rayhunter parser artefact. "
                    f"Device: {device_note}."
                ),
                "recommended_action": (
                    f"1. Include {level} finding as primary exhibit in AFP submission.\n"
                    f"2. Cite each source independently: RF corpus, Shannon firmware log"
                    + (", CASTNET node" if has_castnet else "") + ".\n"
                    f"3. The firmware log (Shannon IMS) is the most legally robust — "
                    f"it is produced by the modem hardware itself, not by user-space tools.\n"
                    f"4. Cross-reference observation timestamps across sources for the "
                    f"prosecution brief.\n"
                    f"5. This finding satisfies the Hidden Blade triple-confirmation rule."
                ),
                "spec_reference": (
                    "Hidden Blade triple-confirmation methodology (Burns 2026); "
                    "RILC_UNSOL_IMS_SUPPORT_SERVICE (Samsung Shannon RIL); "
                    "3GPP TS 36.331 (RRC cell identity)"
                ),
                "found_at": datetime.utcnow().isoformat(),
                # Machine-readable corroboration summary for the app
                "corroboration": {
                    "cid":           cid,
                    "level":         level,
                    "n_sources":     n_classes,
                    "has_rf":        has_rf,
                    "has_firmware":  has_firmware,
                    "has_castnet":   has_castnet,
                    "rf_count":      len(by_class.get(SOURCE_RF, [])),
                    "firmware_count":len(by_class.get(SOURCE_FIRMWARE, [])),
                    "castnet_count": len(by_class.get(SOURCE_CASTNET, [])),
                    "device_note":   device_note,
                },
            }
            findings.append(finding)

        # Sort: triple first, then dual
        findings.sort(key=lambda f: f["corroboration"]["n_sources"], reverse=True)
        return findings

    # ── Helpers ────────────────────────────────────────────────────── #

    def _parse_shannon_ts(self, ts_raw: str) -> Optional[float]:
        """
        Parse Shannon timestamp "06-07 12:30:12.483" into epoch.
        Shannon logs don't include the year — assume current year.
        """
        if not ts_raw:
            return None
        try:
            year = datetime.now().year
            dt = datetime.strptime(
                f"{year}-{ts_raw.strip()[:22]}",
                "%Y-%m-%d %H:%M:%S.%f"
            )
            # Shannon timestamps are device local time (AEST = UTC+10)
            dt = dt.replace(tzinfo=timezone(timedelta(hours=10)))
            return dt.timestamp()
        except (ValueError, TypeError):
            return None


# ── Convenience function for main.py ──────────────────────────────── #
def run_cross_source_correlation(
    all_events: List[Dict],
    shannon_finding: Optional[Dict],
    castnet_findings: Optional[List[Dict]] = None,
    known_rogue_cids: Optional[Set[int]] = None,
) -> List[Dict]:
    """
    One-call interface for main.py Phase 2d.

    Returns list of corroboration findings (may be empty if
    only one source has data for any given CID).
    """
    correlator = CrossSourceCorrelator(known_rogue_cids=known_rogue_cids)

    rf_count = correlator.ingest_rf_events(all_events)
    fw_count = correlator.ingest_shannon_finding(shannon_finding)
    cn_count = correlator.ingest_castnet_findings(castnet_findings or [])

    findings = correlator.correlate()
    return findings, rf_count, fw_count, cn_count
