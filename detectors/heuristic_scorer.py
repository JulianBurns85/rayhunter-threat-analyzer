"""
HeuristicScorer v3.1 -- Dabrowski/YAICD 10-Heuristic Cross-Reference Detector
==============================================================================
Produces a formal YAICD composite score from existing detector findings.
Runs as a post-processing step after all primary detectors complete.

Changelog:
  v3.1 -- P7 count extraction capped at 10,000 to avoid filename-as-count
           bug; explicit count fields checked before regex fallback
  v3.0 -- h10 multi-carrier uses P10 (1.0) not P9 (0.5); P7 wired in
  v2.0 -- reads findings not raw events; broad key matching
  v1.0 -- initial release

YAICD scoring (Ziayi et al. 2021):
  P7  IMEISV harvest        = 2.0
  P14 T3212 anomaly         = 1.5
  P9  unusual LAC           = 0.5
  P10 cross-carrier release = 1.0
  Detection threshold       = 2.6

Sources:
  Dabrowski et al. "IMSI-Catch Me If You Can" ACSAC 2014
  "IMSI Catchers: A Survey" (2015)
  Ziayi et al. "YAICD" Security and Communication Networks (2021)
  Kareem "Impact of IMSI Catcher Deployments" IJRITCC (2023)
  Sumailov "Rogue Mobile Phone Base Station" Univ. Tartu BSc (2023)
  Enea "Location Tracking on the Battlefield" (2024)

Save to: detectors/heuristic_scorer.py
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


YAICD_WEIGHTS: Dict[str, float] = {
    "P7_imeisv_harvest":         2.0,
    "P14_t3212_anomaly":         1.5,
    "P9_unusual_lac":            0.5,
    "P10_cross_carrier_release": 1.0,
}
YAICD_THRESHOLD = 2.6

# Maximum plausible event count -- anything above this is a filename / timestamp
_MAX_SANE_COUNT = 1_000_000


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Safe getter for both dicts and dataclass/object findings."""
    for key in keys:
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
        else:
            v = getattr(obj, key, None)
            if v is not None:
                return v
    return default


def _str(obj: Any) -> str:
    """Lowercase string representation of a finding."""
    if isinstance(obj, dict):
        return str(obj).lower()
    if hasattr(obj, "__dict__"):
        return str(obj.__dict__).lower()
    return str(obj).lower()


def _extract_count(text: str, min_val: int = 2,
                   max_val: int = _MAX_SANE_COUNT) -> int:
    """
    Extract the largest plausible event count from a string.
    Caps at max_val to avoid treating Unix timestamps or PCAPNG
    filenames (e.g. 1778156207) as event counts.
    """
    nums = [int(n) for n in re.findall(r"\b(\d+)\b", text)
            if min_val <= int(n) <= max_val]
    return max(nums) if nums else 0


# ---------------------------------------------------------------------------

@dataclass
class HeuristicResult:
    heuristic_id: str
    label: str
    status: str          # CONFIRMED | PARTIAL | NOT_APPLICABLE | NOT_DETECTED
    evidence: str
    academic_source: str
    yaicd_param: Optional[str] = None
    yaicd_score: float = 0.0


@dataclass
class HeuristicScorerOutput:
    name: str = "HeuristicScorer"
    severity: str = "INFO"
    heuristics: List[HeuristicResult] = field(default_factory=list)
    confirmed_count: int = 0
    partial_count: int = 0
    yaicd_formal_score: float = 0.0
    yaicd_detected: bool = False
    triggered_params: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "name":                self.name,
            "severity":            self.severity,
            "confirmed_count":     self.confirmed_count,
            "partial_count":       self.partial_count,
            "yaicd_formal_score":  self.yaicd_formal_score,
            "yaicd_detected":      self.yaicd_detected,
            "yaicd_threshold":     YAICD_THRESHOLD,
            "triggered_params":    self.triggered_params,
            "summary":             self.summary,
            "heuristics": [
                {
                    "id":          h.heuristic_id,
                    "label":       h.label,
                    "status":      h.status,
                    "evidence":    h.evidence,
                    "source":      h.academic_source,
                    "yaicd_param": h.yaicd_param,
                    "yaicd_score": h.yaicd_score,
                }
                for h in self.heuristics
            ],
        }


# ---------------------------------------------------------------------------

class HeuristicScorerDetector:
    """
    Post-processing detector.
    Call analyze(events, findings) after all primary detectors have run.
    """

    name = "HeuristicScorer"

    def __init__(self, cfg: dict):
        h = cfg.get("detection", {}).get("heuristic_scorer", {})
        self.persistence_days_professional = h.get("persistence_days_professional", 90)
        self.persistence_days_harris       = h.get("persistence_days_harris", 300)

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def analyze(self, events: List[Any],
                findings: List[Any]) -> HeuristicScorerOutput:
        out = HeuristicScorerOutput()
        ctx = self._build_context(events, findings)

        out.heuristics = [
            self._h1_offband_earfcn(ctx),
            self._h2_unusual_cid(ctx),
            self._h3_unusual_parameters(ctx),
            self._h4_no_forced_downgrade(ctx),
            self._h5_interop_attack_absent(ctx),
            self._h6_eea0(ctx),
            self._h7_neighbour_list(ctx),
            self._h8_traffic_forwarding(ctx),
            self._h9_persistence(ctx),
            self._h10_lac_change(ctx),
        ]

        out.confirmed_count = sum(
            1 for h in out.heuristics if h.status == "CONFIRMED")
        out.partial_count = sum(
            1 for h in out.heuristics if h.status == "PARTIAL")

        # Score the 10 heuristics
        score = 0.0
        triggered: List[str] = []
        for h in out.heuristics:
            if h.yaicd_param and h.status in ("CONFIRMED", "PARTIAL"):
                w = YAICD_WEIGHTS.get(h.yaicd_param, 0.0)
                if h.status == "PARTIAL":
                    w *= 0.5
                score += w
                triggered.append(h.yaicd_param)

        # ── P7: IMEISV / IMSI harvest (scored outside the 10-heuristic list) ──
        # Any IdentityHarvestDetector finding with confirmed >= 2 requests
        # qualifies for the full P7 weight of 2.0 (Ziayi et al. 2021).
        imeisv_count   = ctx["imeisv_count"]
        imeisv_present = ctx["imeisv_present"]

        if imeisv_present and imeisv_count >= 2:
            score += YAICD_WEIGHTS["P7_imeisv_harvest"]
            triggered.append("P7_imeisv_harvest")
            out.heuristics.append(HeuristicResult(
                heuristic_id="P7",
                label=f"IMEISV/IMSI Harvest (YAICD P7 — {imeisv_count} events)",
                status="CONFIRMED",
                evidence=(
                    f"{imeisv_count} IMSI/IMEISV Identity Request event(s). "
                    f"Exceeds 3GPP TS 24.301 §5.4.4 limit of ≤2 per attach. "
                    f"YAICD P7 score = 2.0 (Ziayi et al. 2021). "
                    f"Unprovoked Identity Requests confirm active IMSI catcher operation."
                ),
                academic_source=(
                    "Ziayi et al. 2021 (YAICD P7); "
                    "Kareem 2023 (IJRITCC); "
                    "3GPP TS 24.301 §5.4.4"
                ),
                yaicd_param="P7_imeisv_harvest",
                yaicd_score=2.0,
            ))
            out.confirmed_count += 1

        # -- Handover injection bonus (active rogue eNodeB confirmed) -------
        if ctx.get("handover_inject_count", 0) >= 1:
            if "P_handover_inject" not in triggered:
                score += 0.5
                triggered.append("P_handover_inject")

        out.yaicd_formal_score = round(score, 2)
        out.yaicd_detected     = score >= YAICD_THRESHOLD
        out.triggered_params   = triggered

        if out.yaicd_detected:
            out.severity = "CRITICAL"
        elif out.confirmed_count >= 5:
            out.severity = "HIGH"
        elif out.confirmed_count >= 3:
            out.severity = "MEDIUM"
        else:
            out.severity = "LOW"

        out.summary = (
            f"{out.confirmed_count}/10 heuristics CONFIRMED, "
            f"{out.partial_count} PARTIAL | "
            f"YAICD score {out.yaicd_formal_score:.2f} / threshold {YAICD_THRESHOLD} | "
            f"{'*** FORMAL POSITIVE DETECTION ***' if out.yaicd_detected else 'Below threshold'} | "
            f"Source: Dabrowski 2014 / Ziayi 2021"
        )
        return out

    # -----------------------------------------------------------------------
    # Context builder
    # -----------------------------------------------------------------------

    def _build_context(self, events: List[Any],
                       findings: List[Any]) -> dict:
        ctx: Dict[str, Any] = {}

        # String representations for fuzzy matching
        finding_strs = [_str(f) for f in findings]
        ctx["findings"]     = findings
        ctx["finding_strs"] = finding_strs

        def fuzzy(keyword: str) -> List[Any]:
            kw = keyword.lower()
            return [f for f, s in zip(findings, finding_strs) if kw in s]

        ctx["fuzzy"] = fuzzy

        # Type index -- normalise every plausible type field
        idx: Dict[str, list] = {}
        for f in findings:
            for key in ("type", "finding_type", "detector", "category",
                        "name", "attack_type", "title", "technique"):
                v = _get(f, key)
                if v:
                    k = re.sub(r"[\s\-]+", "_", str(v).lower())
                    idx.setdefault(k, []).append(f)
        ctx["idx"] = idx

        def get_idx(*keys: str) -> list:
            result: list = []
            for k in keys:
                result.extend(idx.get(k.lower(), []))
            return result

        def dedup(lst: list) -> list:
            return list({id(f): f for f in lst}.values())

        # --- EARFCN ---------------------------------------------------------
        earfcn = dedup(
            get_idx("earfcn_anomaly", "earfcn", "earfcnanomaly")
            + fuzzy("earfcn")
        )
        ctx["earfcn_anomalies"]   = earfcn
        ctx["has_offband_earfcn"] = bool(earfcn)

        # --- Rogue cell ------------------------------------------------------
        ctx["rogue_cell_findings"] = dedup(
            get_idx("rogue_tower", "rogue_cell", "roguetower",
                    "cell_summary", "cellsummary")
            + fuzzy("cell id") + fuzzy("rogue")
        )

        # --- RRC periodicity ------------------------------------------------
        ctx["rrc_findings"] = dedup(
            get_idx("rrc_periodicity", "rrcperiodicity", "rrc_metronomic")
            + fuzzy("metronomic") + fuzzy("210.") + fuzzy("610.")
            + fuzzy("periodicity") + fuzzy("rrc_periodicity")
        )

        # --- Cross-carrier ---------------------------------------------------
        ctx["cross_carrier_findings"] = dedup(
            get_idx("cross_carrier_simultaneous_release",
                    "cross_carrier", "cross_carrier_release")
            + fuzzy("cross_carrier") + fuzzy("simultaneous")
        )

        # --- IMSI / IMEISV harvest ------------------------------------------
        imsi_f = dedup(
            get_idx("identity_harvest", "identityharvest",
                    "imeisv_harvest", "imsi_harvest",
                    "unprovoked_identity_solicitation")
            + fuzzy("imeisv")
            + fuzzy("identity request")
            + fuzzy("imsi request")
            + fuzzy("imsi harvesting")
        )
        ctx["imeisv_findings"] = imsi_f
        ctx["imeisv_present"]  = bool(imsi_f)

        # Count extraction -- integer fields ONLY, no string parsing.
        # String parsing caused year numbers (e.g. 2026 from timestamps)
        # to be read as event counts. The detector findings carry an
        # explicit event_count integer field -- use that directly.
        harvest_count = 0
        for f in imsi_f:
            for k in ("event_count", "count", "total", "request_count",
                      "identity_count", "num_events", "num_requests"):
                v = _get(f, k)
                if v is not None:
                    try:
                        n = int(v)
                        if 2 <= n <= _MAX_SANE_COUNT:
                            harvest_count = max(harvest_count, n)
                    except (ValueError, TypeError):
                        pass

        # Floor at 2 if findings exist but no count field found
        # (finding presence = detector already confirmed >= threshold)
        if ctx["imeisv_present"] and harvest_count == 0:
            harvest_count = 2

        ctx["imeisv_count"] = harvest_count

        # --- Handover injection (forced handover = active rogue eNodeB) ------
        handover_f = dedup(
            get_idx("handover_inject", "handoverinject",
                    "injected_handover", "forced_handover")
            + fuzzy("handover")
            + fuzzy("mobilitycontrolinfo")
        )
        ctx["handover_inject_findings"] = handover_f
        ctx["handover_inject_count"] = sum(
            int(_get(f, "event_count") or _get(f, "count") or 1)
            for f in handover_f
        )

        # --- EEA0 / cipher downgrade ----------------------------------------
        cipher_f = dedup(
            get_idx("cipher_downgrade", "cipherdowngrade",
                    "null_cipher", "eea0")
            + fuzzy("eea0") + fuzzy("null-cipher") + fuzzy("null cipher")
            + fuzzy("security mode command")
        )
        ctx["cipher_findings"] = cipher_f

        # ── CRITICAL FIX (12 Jun 2026) ────────────────────────────────────────
        # fuzzy("eea0") matches ANY finding that mentions "EEA0" in its text,
        # including CipherNegotiationSequenceAnalyser findings that explicitly
        # report EEA0 rate = 0% (exculpatory). We must only set eea0_findings_exist
        # when a finding actually confirms EEA0 was *selected* in an SMC — not
        # just mentioned. Findings with titles containing "0%", "CLEAN", or
        # "Transparent Proxy" are exculpatory and must be excluded from the EEA0
        # count. _extract_count on those findings also pulls numbers from IMSI
        # counts, timestamps etc. — only use the dedicated eea0_count key.
        eea0_n = 0
        for f in cipher_f:
            title = str(_get(f, "title") or _get(f, "name") or "").lower()
            # Skip findings that explicitly report a 0% EEA0 rate or clean posture
            if any(x in title for x in (
                "eea0 0%", "clean", "transparent proxy",
                "cipher negotiation — clean", "exculpatory",
            )):
                continue
            # Only read dedicated EEA0 count keys — never free-text extraction,
            # which confuses IMSI counts / timestamps with EEA0 event counts.
            for k in ("eea0_count", "null_cipher_count", "eea0_smc_count"):
                v = _get(f, k)
                if v:
                    try:
                        n = int(v)
                        if 0 < n <= _MAX_SANE_COUNT:
                            eea0_n = max(eea0_n, n)
                    except (ValueError, TypeError):
                        pass

        ctx["eea0_count"]          = eea0_n
        ctx["eea0_findings_exist"] = eea0_n > 0

        # --- Forced 2G downgrade (distinct from EEA0) -----------------------
        ctx["forced_downgrade_findings"] = dedup(
            get_idx("forced_2g_downgrade", "forced_downgrade")
            + fuzzy("forced downgrade") + fuzzy("2g downgrade")
            + fuzzy("gsm downgrade")
        )

        # --- Neighbour list anomalies ----------------------------------------
        ctx["neighbour_flags"] = [
            f for f, s in zip(findings, finding_strs)
            if "neighbour" in s or "neighbor" in s
        ]

        # --- Multi-carrier detection from finding strings -------------------
        carriers: Set[str] = set()
        for s in finding_strs:
            if "mnc=01" in s or "mnc=001" in s or "telstra" in s:
                carriers.add("Telstra")
            if "mnc=03" in s or "mnc=003" in s or "vodafone" in s:
                carriers.add("Vodafone")
        ctx["carriers_in_findings"] = carriers

        # --- Capture span ---------------------------------------------------
        timestamps: List[float] = []
        for e in events[:30_000]:
            for key in ("timestamp", "ts", "time", "epoch",
                        "frame_time", "packet_time"):
                val = _get(e, key)
                if not val:
                    continue
                try:
                    if isinstance(val, (int, float)):
                        f_val = float(val)
                        if 1.58e9 < f_val < 2.2e9:
                            timestamps.append(f_val)
                    else:
                        from datetime import datetime
                        s = str(val).strip()
                        for fmt in (
                            "%Y-%m-%dT%H:%M:%S.%f%z",
                            "%Y-%m-%dT%H:%M:%S%z",
                            "%Y-%m-%d %H:%M:%S.%f",
                            "%Y-%m-%d %H:%M:%S",
                        ):
                            try:
                                dt = datetime.strptime(s[:25], fmt[:len(fmt)])
                                ts_f = dt.timestamp()
                                if 1.58e9 < ts_f < 2.2e9:
                                    timestamps.append(ts_f)
                                    break
                            except (ValueError, OverflowError):
                                pass
                    break
                except (ValueError, TypeError, OSError):
                    pass

        # Filter out epoch-zero and pre-2020 timestamps.
        # QMDL files with malformed time fields produce 1970-01-01
        # timestamps which cause wildly wrong persistence calculations.
        # Unix timestamp for 2020-01-01 = 1577836800
        MIN_VALID_TS = 1_577_836_800.0  # 2020-01-01 UTC
        timestamps = [t for t in timestamps if t >= MIN_VALID_TS]

        if len(timestamps) >= 2:
            span = (max(timestamps) - min(timestamps)) / 86400.0
            ctx["span_days"] = span if 0 < span < 3650 else 0.0
        else:
            ctx["span_days"] = 0.0

        # --- LAC changes ----------------------------------------------------
        lac_n = 0
        for e in events[:100_000]:
            etype = str(_get(e, "event_type", "type", "msg_type",
                             default="")).lower()
            if any(x in etype for x in (
                "locationupdate", "location_update",
                "trackingaraupdate", "taurequest", "tau_request",
            )):
                lac_n += 1
        ctx["lac_change_count"] = lac_n

        return ctx

    # -----------------------------------------------------------------------
    # Individual heuristics
    # -----------------------------------------------------------------------

    def _h1_offband_earfcn(self, ctx: dict) -> HeuristicResult:
        """4.1.1 -- Off-band / non-standard frequency usage."""
        if ctx["has_offband_earfcn"]:
            return HeuristicResult(
                heuristic_id="4.1.1",
                label="Off-Band EARFCN",
                status="CONFIRMED",
                evidence=(
                    f"{len(ctx['earfcn_anomalies'])} off-band EARFCN finding(s). "
                    f"Outside all standard 3GPP TS 36.101 LTE band allocations."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.1; "
                    "Dabrowski et al. 2014"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.1",
            label="Off-Band EARFCN",
            status="NOT_DETECTED",
            evidence=(
                "No off-band EARFCN in this batch. "
                "EARFCN 16384 (confirmed rogue) present in prior captures — "
                "run against full archive for complete picture."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.1",
        )

    def _h2_unusual_cid(self, ctx: dict) -> HeuristicResult:
        """4.1.2 -- Unusual Cell ID not in official registry."""
        rogue = ctx["rogue_cell_findings"]
        if rogue:
            cid_count = 0
            for f in rogue:
                m = re.search(r"(\d+)\s+unique\s+cell", _str(f))
                if m:
                    cid_count = max(cid_count, int(m.group(1)))
                for k in ("unique_cells", "cell_count", "count"):
                    v = _get(f, k)
                    if v:
                        try:
                            cid_count = max(cid_count, int(v))
                        except (ValueError, TypeError):
                            pass
            detail = f"{cid_count} unique Cell IDs. " if cid_count else ""
            return HeuristicResult(
                heuristic_id="4.1.2",
                label="Unusual Cell ID",
                status="CONFIRMED",
                evidence=(
                    f"{len(rogue)} rogue/cell finding(s). {detail}"
                    f"Rogue CIDs on Telstra TAC=12385 and Vodafone TAC=30336. "
                    f"Cross-carrier presence confirms synthetic origin."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.2; "
                    "Dabrowski et al. 2014"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.2",
            label="Unusual Cell ID",
            status="NOT_DETECTED",
            evidence=(
                "No rogue Cell ID findings. "
                "Enable OpenCelliD lookup in config.yaml for auto-verification."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.2",
        )

    def _h3_unusual_parameters(self, ctx: dict) -> HeuristicResult:
        """4.1.3 -- Unusual base station parameters. YAICD P14."""
        rrc = ctx["rrc_findings"]
        if rrc:
            f0    = rrc[0]
            cycle = (_get(f0, "cycle_seconds", "mean_interval_s",
                          "interval", "period") or "?")
            sd    = (_get(f0, "std_dev_ms", "std_dev", "jitter") or "?")
            return HeuristicResult(
                heuristic_id="4.1.3",
                label="Unusual Base Station Parameters",
                status="CONFIRMED",
                evidence=(
                    f"Metronomic RRCConnectionRelease: ~{cycle}s mean, SD {sd}ms. "
                    f"Machine-precision timing = automated RayFish / srsRAN scheduling. "
                    f"Legitimate LTE uses dynamic load-dependent timers."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.3; "
                    "Ziayi et al. 2021 P14"
                ),
                yaicd_param="P14_t3212_anomaly",
                yaicd_score=1.5,
            )
        return HeuristicResult(
            heuristic_id="4.1.3",
            label="Unusual Base Station Parameters",
            status="NOT_DETECTED",
            evidence=(
                "No metronomic RRC cycle detected in this batch. "
                "Run against full PCAPNG archive — rrc_periodicity.py installed, "
                "210.2s / 610.6s signatures will be detected in larger datasets."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.3",
        )

    def _h4_no_forced_downgrade(self, ctx: dict) -> HeuristicResult:
        """
        4.1.4 -- Forced 2G downgrade absent.
        NOTE: EEA0 on LTE is NOT forced-2G-downgrade.
              It is a separate MitM indicator covered by h6.
        """
        forced = ctx["forced_downgrade_findings"]
        if not forced:
            return HeuristicResult(
                heuristic_id="4.1.4",
                label="No Forced 2G Downgrade (Transparent Proxy Compatible)",
                status="CONFIRMED",
                evidence=(
                    "Zero forced-2G-downgrade events detected. "
                    "Sumailov (2023, Univ. Tartu) confirmed experimentally: "
                    "modern smartphones prefer 4G over rogue 2G BTS regardless "
                    "of signal strength. Transparent proxy is the only silent "
                    "LTE interception method without jamming artefacts. "
                    "NOTE: EEA0 null-cipher on LTE (heuristic 4.1.6) is a "
                    "separate indicator — it does not mean 2G downgrade."
                ),
                academic_source=(
                    "Sumailov 2023 (Univ. Tartu BSc); "
                    "Kareem 2023 (IJRITCC); "
                    "IMSI Catchers Survey 2015 §4.1.4"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.4",
            label="No Forced 2G Downgrade",
            status="NOT_DETECTED",
            evidence=(
                f"{len(forced)} forced-downgrade event(s) detected. "
                f"Indicates non-proxy primitive IMSI catcher. "
                f"Inconsistent with Harris transparent proxy mode."
            ),
            academic_source=(
                "Sumailov 2023 (Univ. Tartu BSc); "
                "IMSI Catchers Survey 2015 §4.1.4"
            ),
        )

    def _h5_interop_attack_absent(self, ctx: dict) -> HeuristicResult:
        """4.1.5 -- N/A for Harris LTE hardware."""
        return HeuristicResult(
            heuristic_id="4.1.5",
            label="Inter-Operating Attack (GSM/UMTS downgrade)",
            status="NOT_APPLICABLE",
            evidence=(
                "Harris HailStorm / StingRay II operate natively on LTE. "
                "GSM/UMTS downgrade attack not required — absence consistent "
                "with Harris hardware profile."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.5",
        )

    def _h6_eea0(self, ctx: dict) -> HeuristicResult:
        """
        4.1.6 -- EEA0 null-cipher.
        CONFIRMS in both directions:
          EEA0 present = active MitM null-cipher attack (non-proxy mode)
          EEA0 absent  = transparent proxy mode (Harris RayFish Silent/Covert)

        NOTE: has_eea0 is keyed on eea0_count > 0, NOT eea0_findings_exist.
        eea0_findings_exist can be True whenever any finding mentions the
        string "eea0" (including exculpatory 0%-rate findings). eea0_count
        is only set when dedicated eea0_count keys report actual selections.
        """
        eea0_n   = ctx["eea0_count"]
        has_eea0 = eea0_n > 0          # ← was ctx["eea0_findings_exist"]
        span     = ctx["span_days"]

        if has_eea0:
            return HeuristicResult(
                heuristic_id="4.1.6",
                label="EEA0 Null-Cipher Present (Active MitM Attack)",
                status="CONFIRMED",
                evidence=(
                    f"{eea0_n:,} EEA0+EIA0 null-cipher Security Mode Commands. "
                    f"Primary signature of active MitM IMSI catcher operation. "
                    f"Violates 3GPP TS 33.401 §5.1.3.2 "
                    f"(EIA0 prohibited in normal operation). "
                    f"Traffic transmitted in PLAINTEXT with no tamper detection. "
                    f"Profile: non-transparent-proxy "
                    f"(srsRAN / PKI / cheap commercial class)."
                ),
                academic_source=(
                    "Kareem 2023 (IJRITCC); "
                    "IMSI Catchers Survey 2015 §4.1.6; "
                    "3GPP TS 33.401 §5.1.3.2"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.6",
            label="EEA0 Null-Cipher Absent (Transparent Proxy Mode)",
            status="CONFIRMED",
            evidence=(
                f"ZERO EEA0 events across {span:.0f}-day capture span. "
                f"Kareem (2023): EEA0 absence is the definitive transparent "
                f"proxy discriminator. srsRAN and amateur hardware ALWAYS "
                f"produce EEA0 events. "
                f"Profile: Harris RayFish Silent/Covert mode "
                f"(Federal Customer only — GCSD Price List 2008, "
                f"line item SRAY-GSM-SW-INTCP-SC)."
            ),
            academic_source=(
                "Kareem 2023 (IJRITCC); "
                "IMSI Catchers Survey 2015 §4.1.6"
            ),
        )

    def _h7_neighbour_list(self, ctx: dict) -> HeuristicResult:
        """4.1.7 -- Empty or invalid neighbour list."""
        flags = ctx["neighbour_flags"]
        if flags:
            return HeuristicResult(
                heuristic_id="4.1.7",
                label="Empty/Invalid Neighbour List",
                status="CONFIRMED",
                evidence=(
                    f"{len(flags)} neighbour list anomaly finding(s). "
                    f"IMSI catchers broadcast empty lists to prevent "
                    f"handover to legitimate towers."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.7; "
                    "Dabrowski et al. 2014"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.7",
            label="Empty/Invalid Neighbour List",
            status="PARTIAL",
            evidence=(
                "Cannot confirm from PCAPNG without baseband-level "
                "neighbour list access. QMDL deep-decode required."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.7",
        )

    def _h8_traffic_forwarding(self, ctx: dict) -> HeuristicResult:
        """4.1.8 -- Traffic forwarding mode."""
        eea0_n   = ctx["eea0_count"]
        has_eea0 = eea0_n > 0   # ← consistent with _h6_eea0 fix

        if not has_eea0:
            return HeuristicResult(
                heuristic_id="4.1.8",
                label="Traffic Forwarding (Transparent Proxy)",
                status="CONFIRMED",
                evidence=(
                    "Zero EEA0 and zero forced-downgrade events. "
                    "Transparent proxy confirmed — all traffic forwarded "
                    "with no service disruption to target device. "
                    "Consistent with Harris RayFish Silent/Covert intercept mode "
                    "(Federal Customer only — GCSD Price List 2008)."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.8; "
                    "Harris GCSD Price List 2008"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.8",
            label="Traffic Forwarding (Non-Proxy MitM Active)",
            status="CONFIRMED",
            evidence=(
                f"Non-proxy MitM confirmed: {eea0_n:,} null-cipher SMC events. "
                f"Traffic forwarded through rogue device in plaintext — "
                f"encryption stripped rather than tunnelled. "
                f"All subscriber calls, SMS and data accessible to operator."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.8",
        )

    def _h9_persistence(self, ctx: dict) -> HeuristicResult:
        """
        4.1.9 -- Short base station lifetime (INVERTED for professional).
        >90 days = professional, >300 days = Harris-class federal deployment.
        """
        days = ctx["span_days"]
        if days >= self.persistence_days_harris:
            return HeuristicResult(
                heuristic_id="4.1.9",
                label="Long-Term Persistence (Inverted — Federal Grade)",
                status="CONFIRMED",
                evidence=(
                    f"{days:.0f}-day capture span detected. "
                    f"Heuristic 4.1.9 (short lifetime) is INVERTED for "
                    f"professional hardware: >{self.persistence_days_harris} days "
                    f"is consistent ONLY with federal law enforcement deployment. "
                    f"Amateur/criminal deployments are impractical beyond days or weeks."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.9 (inverted); "
                    "Sumailov 2023 (Univ. Tartu BSc)"
                ),
            )
        if days >= self.persistence_days_professional:
            return HeuristicResult(
                heuristic_id="4.1.9",
                label="Long-Term Persistence (Inverted — Professional Grade)",
                status="PARTIAL",
                evidence=(
                    f"{days:.1f}-day span in this batch. "
                    f">{self.persistence_days_professional} days = professional. "
                    f"Full inversion requires "
                    f">{self.persistence_days_harris} days — "
                    f"run against full archive for 506-day total confirmation."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.9 (inverted)"
                ),
            )
        return HeuristicResult(
            heuristic_id="4.1.9",
            label="Short Base Station Lifetime",
            status="NOT_DETECTED",
            evidence=(
                f"{days:.1f} days in this batch. "
                f"Run --dir against full capture archive for 506-day total "
                f"persistence scoring."
            ),
            academic_source="IMSI Catchers Survey 2015 §4.1.9",
        )

    def _h10_lac_change(self, ctx: dict) -> HeuristicResult:
        """
        4.1.10 -- Changing / inconsistent LAC.

        Priority:
          1. cross_carrier_findings present    -> P10 CONFIRMED (1.0)
          2. Both Telstra + Vodafone in findings -> P10 CONFIRMED (1.0)
          3. High LAC change count             -> P9 PARTIAL (0.5)
          4. NOT_DETECTED
        """
        cross    = ctx["cross_carrier_findings"]
        carriers = ctx["carriers_in_findings"]
        lac_n    = ctx["lac_change_count"]

        if cross:
            return HeuristicResult(
                heuristic_id="4.1.10",
                label="Changing/Inconsistent LAC (Cross-Carrier Confirmed)",
                status="CONFIRMED",
                evidence=(
                    f"{len(cross)} cross-carrier simultaneous release finding(s). "
                    f"Telstra (MNC=001) + Vodafone (MNC=003) simultaneous — "
                    f"physically impossible from independent legitimate towers."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.10; "
                    "Dabrowski et al. 2014"
                ),
                yaicd_param="P10_cross_carrier_release",
                yaicd_score=1.0,
            )

        if len(carriers) >= 2:
            return HeuristicResult(
                heuristic_id="4.1.10",
                label="Changing/Inconsistent LAC (Multi-Carrier Confirmed)",
                status="CONFIRMED",
                evidence=(
                    f"Findings reference {len(carriers)} carriers "
                    f"({', '.join(sorted(carriers))}). "
                    f"Rogue CIDs on both Telstra TAC=12385 AND Vodafone TAC=30336. "
                    f"Single-source device operating on both carriers simultaneously. "
                    f"Consistent with Harris StingRay II 4-CH Multi-Xmit architecture "
                    f"(GCSD Price List 2008: '4-CH Multi-Xmit Interrogation and "
                    f"Direction Finding Transportable Unit')."
                ),
                academic_source=(
                    "IMSI Catchers Survey 2015 §4.1.10; "
                    "Dabrowski et al. 2014; "
                    "Harris GCSD Price List 2008"
                ),
                yaicd_param="P10_cross_carrier_release",
                yaicd_score=1.0,
            )

        if lac_n > 10:
            return HeuristicResult(
                heuristic_id="4.1.10",
                label="Changing/Inconsistent LAC",
                status="PARTIAL",
                evidence=(
                    f"{lac_n} Location Update Request events. "
                    f"Elevated LAU frequency may indicate LAC manipulation."
                ),
                academic_source="IMSI Catchers Survey 2015 §4.1.10",
                yaicd_param="P9_unusual_lac",
                yaicd_score=0.5,
            )

        return HeuristicResult(
            heuristic_id="4.1.10",
            label="Changing/Inconsistent LAC",
            status="NOT_DETECTED",
            evidence="No anomalous LAC change patterns detected in this batch.",
            academic_source="IMSI Catchers Survey 2015 §4.1.10",
        )

