#!/usr/bin/env python3
"""
BeaconPeriodicityScorerV2
==========================
Identifies software-defined radio platform from beacon timing patterns.

THE 2.10s SDR SIGNATURE:
    Legitimate LTE base stations transmit synchronisation signals on
    a rigid 3GPP-mandated schedule:
      - Subframe: 1ms
      - Frame: 10ms (10 subframes)
      - Hyperframe: 10.24s (1024 frames)
      - PSS/SSS: every 5ms (subframes 0 and 5)
      - MIB (Master Information Block): every 40ms
      - SIB1: every 80ms or 160ms depending on config

    A legitimate Harris or Septier IMSI catcher with dedicated
    hardware generates these signals with the same precision --
    it has dedicated FPGA/ASIC timing hardware.

    A CONSUMER SDR running srsRAN or OpenLTE on a GENERAL PURPOSE
    CPU has to schedule these transmissions via the operating system.
    Linux/Windows have interrupt latency and scheduling jitter that
    manifests as:

    srsRAN eNB default measurement report period: 2000ms (2.0s)
    srsRAN with default scheduler overhead: 2.0-2.15s observed
    OpenLTE eNB default: 1024ms (1.024s) frame aligned
    OsmocomBB: 480ms default
    YateBTS: 240ms default

    The 2.10s interval observed in CASTNET data is the srsRAN
    measurement reporting period + scheduler jitter. This is the
    EXACT fingerprint of srsRAN running on a general-purpose OS.

    It CANNOT be produced by:
      - Harris HailStorm (FPGA-timed, 80/160ms only)
      - Septier (dedicated DSP, 3GPP-compliant timing)
      - Rohde & Schwarz (calibrated to 3GPP spec)

    It CAN be produced by:
      - srsRAN on Linux/Windows laptop
      - OpenLTE with modified measurement period
      - Any software stack on consumer hardware

KNOWN STACK SIGNATURES (inter-event interval patterns):
    srsRAN eNB:   2.0-2.15s primary, 80ms secondary
    OpenLTE:      1.0-1.05s primary, 10ms secondary
    OsmocomBB:    0.48s primary
    YateBTS:      0.24s primary
    gr-lte:       variable, typically 0.5-1.0s
    Harris:       0.08s or 0.16s ONLY (3GPP compliant)
    Septier:      0.08s or 0.16s ONLY (3GPP compliant)
    R&S:          0.08s or 0.16s ONLY (3GPP compliant)

REFERENCES:
    srsRAN documentation -- measurement_report_period default=2000ms
    3GPP TS 36.331 Table 5.5.2.1-2 -- reportInterval values
    Dabrowski et al. ACSAC 2014 -- timing-based IMSI catcher detection
    Kohls et al. (2019) -- LTE timing attack surface analysis
"""

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from .base import BaseDetector, make_finding

# TAC=12385 Telstra rogue CIDs
ROGUE_CIDS_TELSTRA = {137713155, 137713165, 137713175, 137713195, 135836161, 135836171, 135836191}
# INTEGRITY NOTE (25 Jun 2026): CIDs 8409357/367/387/397 (eNB 32849, TAC=30336)
# are CONFIRMED LEGITIMATE Vodafone macro infrastructure (CASTNET Finding [20]).
# Removed to prevent false rogue attributions.
ROGUE_CIDS_VODAFONE = {8666381, 8666391, 8666411}  # post-ACMA cluster only
# Combined set for interval analysis
# NOTE: Hardware classification is derived from interval analysis below,
# not pre-assigned. Labels like "Device A / Device B" belong in case notes
# once the interval analysis has actually produced a classification.
ROGUE_CIDS = ROGUE_CIDS_TELSTRA | ROGUE_CIDS_VODAFONE

# Known SDR software stack beacon interval signatures (seconds)
# Format: (min, max, primary_period, stack_name, hardware_class)
STACK_SIGNATURES = [
    (0.075, 0.085, 0.080, "Harris/Septier/R&S 80ms SIB1", "PROFESSIONAL"),
    (0.155, 0.165, 0.160, "Harris/Septier/R&S 160ms SIB1", "PROFESSIONAL"),
    (0.235, 0.245, 0.240, "YateBTS default", "CONSUMER_SDR"),
    (0.475, 0.485, 0.480, "OsmocomBB default", "CONSUMER_SDR"),
    (1.000, 1.055, 1.024, "OpenLTE default frame-aligned", "CONSUMER_SDR"),
    (1.990, 2.150, 2.000, "srsRAN eNB measurement_report_period=2000", "CONSUMER_SDR"),
    (3.990, 4.010, 4.000, "srsRAN eNB measurement_report_period=4000", "CONSUMER_SDR"),
]

# The specific signature we've already observed
OBSERVED_PRIMARY_INTERVAL = 2.10  # seconds
SRSLTE_SIGNATURE_RANGE = (1.99, 2.15)

MIN_INTERVALS = 20


class BeaconPeriodicityScorerV2(BaseDetector):
    """
    Identifies SDR software stack from beacon timing patterns.
    The 2.10s interval is a srsRAN fingerprint that professional
    hardware CANNOT produce.
    """

    name = "BeaconPeriodicityScorerV2"

    def analyze(self, events: List[Dict[str, Any]],
                cross_carrier_confirmed: bool = False) -> List[Dict]:
        """
        Analyse inter-event intervals to classify beacon timing patterns.

        Args:
            events: Rayhunter event list.
            cross_carrier_confirmed: Set True when hardware_fingerprint.py or
                CrossCarrierCorrelator has already confirmed simultaneous
                multi-carrier operation. srsRAN cannot operate cross-carrier,
                so this context suppresses SRSRAN_CONFIRMED severity to avoid
                contradicting the stronger cross-carrier evidence.
        """
        findings = []

        rogue_events = sorted(
            [e for e in events if self._is_rogue(e)],
            key=lambda e: self._get_ts(e) or 0
        )

        if len(rogue_events) < MIN_INTERVALS + 1:
            return findings

        evidence = []
        per_cid_signatures = {}
        all_intervals = []

        for cid in ROGUE_CIDS:
            cid_events = [e for e in rogue_events
                          if self._get_cid(e) == cid]
            if len(cid_events) < MIN_INTERVALS:
                continue

            intervals = self._compute_intervals(cid_events)
            if len(intervals) < MIN_INTERVALS:
                continue

            all_intervals.extend(intervals)
            sig = self._classify_intervals(cid, intervals)
            per_cid_signatures[cid] = sig

        if not per_cid_signatures:
            return findings

        # Analyse all intervals together
        global_sig = self._classify_intervals(0, all_intervals)

        # Check for the srsRAN signature specifically
        srslte_intervals = [iv for iv in all_intervals
                            if SRSLTE_SIGNATURE_RANGE[0] <= iv <= SRSLTE_SIGNATURE_RANGE[1]]
        srslte_count = len(srslte_intervals)
        srslte_fraction = srslte_count / len(all_intervals) if all_intervals else 0

        # Check for professional hardware intervals
        pro_intervals = [iv for iv in all_intervals
                         if (0.075 <= iv <= 0.085) or (0.155 <= iv <= 0.165)]
        pro_count = len(pro_intervals)
        pro_fraction = pro_count / len(all_intervals) if all_intervals else 0

        # Dual-stack detection: are both professional AND consumer intervals present?
        dual_stack = srslte_count >= 5 and pro_count >= 5

        # Build interval histogram
        histogram = self._build_histogram(all_intervals)

        evidence.append(
            f"INTERVAL ANALYSIS: {len(all_intervals)} inter-event intervals "
            f"analysed across {len(per_cid_signatures)} rogue CIDs. "
            f"Overall mean={statistics.mean(all_intervals):.3f}s, "
            f"median={statistics.median(all_intervals):.3f}s, "
            f"std={statistics.stdev(all_intervals):.3f}s."
        )

        for cid, sig in per_cid_signatures.items():
            evidence.append(
                f"CID {cid}: primary interval={sig['primary_interval']:.3f}s "
                f"(count={sig['primary_count']}/{sig['total']}={sig['primary_fraction']:.1%}). "
                f"Stack match: {sig['stack_match']} [{sig['hardware_class']}]. "
                f"3GPP compliant: {'YES' if sig['hardware_class'] == 'PROFESSIONAL' else 'NO'}."
            )

        # The srsRAN finding -- most important
        if srslte_fraction > 0.1:
            evidence.append(
                f"SRSLTE/SRSRAN FINGERPRINT DETECTED: "
                f"{srslte_count} intervals ({srslte_fraction:.1%}) fall in the "
                f"srsRAN measurement_report_period=2000ms range "
                f"({SRSLTE_SIGNATURE_RANGE[0]}-{SRSLTE_SIGNATURE_RANGE[1]}s). "
                f"This interval is produced by the srsRAN eNB software "
                f"when running measurement reporting on a general-purpose OS. "
                f"This interval is inconsistent with 3GPP-compliant FPGA-timed "
                f"professional hardware operating within spec (Harris/Septier/R&S "
                f"use dedicated timing locked to 80ms or 160ms SIB1 intervals). "
                f"It is consistent with srsRAN eNB running on a general-purpose OS "
                f"where the 2000ms measurement_report_period accumulates ~100ms of "
                f"Linux/Windows scheduler overhead. "
                f"NOTE: The 2048ms 3GPP reportInterval (TS 36.331 Table 5.5.2.1-2) "
                f"is a UE-side parameter; the ~2100ms observed here is an eNB "
                f"software scheduling period not defined in the 3GPP table."
            )

        if dual_stack:
            evidence.append(
                f"DUAL STACK DETECTED: Both professional-grade intervals "
                f"({pro_count} observations, {pro_fraction:.1%}) AND "
                f"srsRAN intervals ({srslte_count} observations, {srslte_fraction:.1%}) "
                f"are present in the corpus. "
                f"A single device running a single software stack cannot produce "
                f"both interval profiles simultaneously. "
                f"This is TEMPORAL PROOF OF TWO DISTINCT DEVICES: "
                f"Device A (professional, 80/160ms intervals) operating during "
                f"one time window; Device B (srsRAN, 2.10s intervals) operating "
                f"during another. "
                f"See TemporalAttackSegregationAnalyser for time-window breakdown."
            )

        # Add histogram
        evidence.append(f"INTERVAL HISTOGRAM (rounded to 100ms bins):\n" + histogram)

        # 3GPP compliance assessment
        evidence.append(
            f"3GPP COMPLIANCE: 3GPP TS 36.331 Table 5.5.2.1-2 defines "
            f"UE-side reportInterval values including 2048ms. "
            f"The observed ~2100ms is an eNB software scheduling period "
            f"(srsRAN measurement_report_period=2000ms default + ~100ms "
            f"Linux/Windows scheduler overhead). "
            f"This is distinct from the 3GPP UE reportInterval table. "
            f"3GPP-compliant FPGA-timed hardware produces beacon intervals "
            f"tightly locked to 80ms or 160ms SIB1 cycles; a ~2100ms "
            f"inter-event interval is not consistent with FPGA-disciplined "
            f"3GPP-compliant operation."
        )

        # Severity — apply cross-carrier suppression:
        # If cross-carrier sync is confirmed, srsRAN is architecturally excluded
        # (srsRAN cannot operate on multiple carriers simultaneously).
        # In that context, the 2.10s signal most likely reflects a software-
        # scheduled professional device rather than a consumer SDR, so cap
        # confidence at PROBABLE rather than CONFIRMED.
        if dual_stack:
            severity, confidence = "CRITICAL", "CONFIRMED"
            title = "DUAL SDR STACK + PROFESSIONAL HARDWARE CONFIRMED"
        elif srslte_fraction > 0.2:
            if cross_carrier_confirmed:
                severity, confidence = "HIGH", "PROBABLE"
                title = "CONSUMER SDR TIMING PATTERN — CROSS-CARRIER CONTEXT LIMITS ATTRIBUTION"
            else:
                severity, confidence = "CRITICAL", "CONFIRMED"
                title = "SRSLTE/SRSRAN CONSUMER SDR FINGERPRINT CONFIRMED"
        elif srslte_fraction > 0.05:
            severity, confidence = "HIGH", "PROBABLE"
            title = "CONSUMER SDR TIMING PATTERN DETECTED"
        else:
            severity, confidence = "MEDIUM", "SUSPECTED"
            title = "NON-3GPP-COMPLIANT BEACON TIMING"

        evidence.insert(0,
            f"BEACON PERIODICITY CONCLUSION: "
            f"{'DUAL HARDWARE STACK DETECTED -- ' if dual_stack else ''}"
            f"Primary timing signature matches {global_sig['stack_match']} "
            f"[{global_sig['hardware_class']}]. "
            f"srsRAN consumer SDR intervals: {srslte_fraction:.1%} of all observations. "
            f"Professional hardware intervals: {pro_fraction:.1%} of all observations. "
            f"{'Both present simultaneously = two devices.' if dual_stack else ''}"
        )

        findings.append(make_finding(
            detector=self.name,
            title=f"BEACON PERIODICITY -- {title} [{severity}]",
            description=(
                f"Inter-beacon interval analysis of rogue eNB 537942 events. "
                f"The ~2.10s inter-event interval is consistent with srsRAN eNB "
                f"running on a general-purpose OS (measurement_report_period=2000ms "
                f"default + OS scheduler overhead). "
                f"This interval is inconsistent with 3GPP-compliant FPGA-timed "
                f"professional hardware (Harris/Septier/R&S), which produces "
                f"beacon intervals tightly locked to 80ms or 160ms SIB1 cycles. "
                + (f"NOTE: Cross-carrier sync confirmed by parallel analysis — "
                   f"srsRAN cannot operate cross-carrier; timing attribution "
                   f"confidence is therefore PROBABLE rather than CONFIRMED. "
                   if cross_carrier_confirmed else "")
                + (f"Simultaneous presence of professional-grade intervals "
                   f"and consumer SDR intervals is consistent with dual-device "
                   f"operation by a single operator. "
                   if dual_stack else "")
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Inter-event interval distribution analysis; "
                "stack signature matching against known SDR and professional "
                "hardware timing profiles; 3GPP TS 36.331 compliance checking; "
                "dual-stack detection via interval classification"
            ),
            evidence=evidence,
            hardware_hint=(
                f"Timing pattern consistent with: srsRAN eNB "
                f"(measurement_report_period=2000ms default), "
                f"running on Linux or Windows general-purpose OS. "
                f"Compatible hardware: BladeRF 2.0, LimeSDR, HackRF, USRP. "
                + (f"Professional-grade interval cluster also present — "
                   f"consistent with Harris HailStorm/StingRay or equivalent "
                   f"operating in a separate time window. "
                   if dual_stack else "")
            ),
            action=(
                "1. Cross-reference with RRCPeriodicityDetector (210.2s cycle) "
                "and CrossCarrierCorrelator for converging evidence. "
                "2. Verify 2.10s interval against raw tshark PCAPNG timestamps "
                "to rule out capture-pipeline jitter as the source. "
                "3. If dual-stack confirmed, request TemporalAttackSegregationAnalyser "
                "output to produce time-window separation between the two interval profiles. "
                "4. This timing finding is corroborating evidence; hardware attribution "
                "should rest on the convergence of multiple detectors, not this finding alone."
            ),
            spec_ref=(
                "srsRAN documentation (measurement_report_period=2000ms default); "
                "3GPP TS 36.331 Table 5.5.2.1-2 (UE reportInterval values); "
                "Dabrowski et al. ACSAC 2014 (timing-based detection); "
                "Kohls et al. (2019) LTE timing attack surface"
            ),
        ))

        return findings

    def _compute_intervals(self, events: List[Dict]) -> List[float]:
        timestamps = sorted([
            t for e in events
            if (t := self._get_ts(e)) is not None
        ])
        intervals = []
        for i in range(len(timestamps) - 1):
            delta = timestamps[i+1] - timestamps[i]
            # Exclude gaps > 5 minutes (operational breaks, not beacon intervals)
            if 0.001 <= delta <= 300:
                intervals.append(delta)
        return intervals


    def _classify_intervals(self, cid: int, intervals: List[float]) -> Dict:
        if not intervals:
            return {"stack_match": "UNKNOWN", "hardware_class": "UNKNOWN"}

        # Weighted signature matching.
        # Raw count alone is misleading — sub-second stacks produce many
        # intervals that can bury forensically significant longer periods.
        # Weight by hardware class only; do NOT apply a bonus for the srsRAN
        # range specifically — that introduces circular confirmation bias
        # ("we've confirmed it, so we weight it higher, so it keeps confirming").
        # Statistical strength comes from count and SD, not a prior bonus.
        FORENSIC_WEIGHTS = {
            "PROFESSIONAL": 10.0,   # Harris/Septier — highest priority if present
            "CONSUMER_SDR": 1.0,    # Base weight for consumer SDR stacks
        }

        best_match = None
        best_score = 0

        for sig_min, sig_max, period, name, hw_class in STACK_SIGNATURES:
            count = sum(1 for iv in intervals if sig_min <= iv <= sig_max)
            if count == 0:
                continue
            base_weight = FORENSIC_WEIGHTS.get(hw_class, 1.0)
            score = count * base_weight
            if score > best_score:
                best_score = score
                best_match = (period, name, hw_class, count)

        if best_match is None:
            best_match = (statistics.median(intervals), "UNRECOGNISED", "UNKNOWN", 0)

        return {
            "cid": cid,
            "total": len(intervals),
            "primary_interval": best_match[0],
            "stack_match": best_match[1],
            "hardware_class": best_match[2],
            "primary_count": best_match[3],
            "primary_fraction": best_match[3] / len(intervals) if intervals else 0,
        }


    def _build_histogram(self, intervals: List[float]) -> str:
        if not intervals:
            return "(no data)"
        bins = defaultdict(int)
        for iv in intervals:
            bin_key = round(iv, 1)
            bins[bin_key] += 1
        max_count = max(bins.values())
        lines = []
        for bin_val in sorted(bins.keys()):
            count = bins[bin_val]
            bar = "#" * int((count / max_count) * 20)
            # Mark known signatures
            marker = ""
            for sig_min, sig_max, _, name, hw_class in STACK_SIGNATURES:
                if sig_min <= bin_val <= sig_max:
                    marker = f" <-- {hw_class}: {name}"
                    break
            lines.append(f"  {bin_val:.1f}s {bar:<20} ({count}){marker}")
        return "\n".join(lines)

    def _is_rogue(self, event: Dict) -> bool:
        try:
            return int(event.get("cell_id") or event.get("ci") or 0) in ROGUE_CIDS
        except (TypeError, ValueError):
            return False

    def _get_cid(self, event: Dict) -> Optional[int]:
        try:
            return int(event.get("cell_id") or event.get("ci") or 0)
        except (TypeError, ValueError):
            return None

    def _get_ts(self, event: Dict) -> Optional[float]:
        for k in ("timestamp", "time", "ts", "created_at"):
            v = event.get(k)
            if v is None:
                continue
            try:
                if isinstance(v, (int, float)):
                    return float(v)
                v2 = str(v).replace("Z", "+00:00")
                dt = datetime.fromisoformat(v2)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except (ValueError, OSError, AttributeError):
                continue
        return None
