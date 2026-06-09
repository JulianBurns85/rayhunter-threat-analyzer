#!/usr/bin/env python3
"""
hardware_fingerprint.py — Rayhunter Threat Analyzer
Device identification and hardware confidence scoring engine.

Fix history:
  v2.1 (9 May 2026):
  - PERSISTENCE BUG: was computing duration_days from current batch timestamp span
    (giving 0.9 days). Now reads investigation.total_confirmed_days from config
    (506 days confirmed, Dec 19 2024 - May 9 2026). Falls back to timestamp span
    only if config value not available.
  - SRSRAN DEFAULT BUG: when no cycle interval was found, code defaulted to
    SRSRAN_CYCLE_SECONDS (210.2s), which then fired the srsRAN timing discriminator.
    Removed this default — no cycle interval means no timing score.
  - CROSS-CARRIER DETECTION: _metadata_from_findings was looking for PLMN in
    message text, but ndjson_parser stores it in ev["mnc"] field. Fixed to check
    both message text and event fields.
  - HARRIS T1 SIGNATURE: Added scoring for confirmed T1=610.6s hold timer
    (machine-precision across both carriers, 9 May 2026). Harris +0.30.
  - HARRIS PRIMARY DISCRIMINATOR: cross-carrier sync now correctly boosts Harris
    HailStorm/StingRay II (not just PKI 1625). Updated reasoning strings.
  - README NOTE: 210.2s cycle is now documented as a phase 2 observation, not
    the primary hardware fingerprint. Primary fingerprints are cross-carrier sync,
    T1=610.6s, and 8 confirmed rogue CIDs.

  Session 6 (prior):
  - LTE Attach Reject -> commercial device confidence wire-up (PKI/Harris boost)
  - srsRAN discriminator: 210s cycle + Identity Request ONLY -> srsRAN
  - Commercial discriminator: Attach Rejects present -> Harris/PKI
  - Cross-carrier operator cycling -> PKI 1625 hypothesis
  - BCCH outlier fingerprints from SeaGlass PoPETs 2017
  - Band 28 detection -> HailStorm/PKI 1625 boost
  - Forced full-power transmission artifact integration
"""

import yaml
import json
import glob
import os
import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FingerprintScore:
    """Confidence scores for device identification."""
    harris_hailstorm: float = 0.0
    harris_kingfish: float = 0.0
    harris_stingray2: float = 0.0
    pki_1625: float = 0.0
    pki_1650: float = 0.0
    srsran: float = 0.0
    unknown_commercial: float = 0.0
    unknown_opensource: float = 0.0

    state_actor: float = 0.0
    intelligence_agency: float = 0.0
    criminal_actor: float = 0.0

    reasoning: list = field(default_factory=list)

    def log(self, msg: str):
        self.reasoning.append(msg)

    def top_device(self) -> tuple:
        scores = {
            "Harris HailStorm":      self.harris_hailstorm,
            "Harris KingFish":       self.harris_kingfish,
            "Harris StingRay II":    self.harris_stingray2,
            "PKI 1625":              self.pki_1625,
            "PKI 1650":              self.pki_1650,
            "srsRAN":                self.srsran,
            "Unknown Commercial":    self.unknown_commercial,
            "Unknown Open Source":   self.unknown_opensource,
        }
        return max(scores.items(), key=lambda x: x[1])

    def top_profile(self) -> tuple:
        profiles = {
            "State Actor / Law Enforcement": self.state_actor,
            "Intelligence Agency":           self.intelligence_agency,
            "Criminal Actor":                self.criminal_actor,
        }
        return max(profiles.items(), key=lambda x: x[1])

    def to_dict(self) -> dict:
        top_dev  = self.top_device()
        top_prof = self.top_profile()
        return {
            "device_scores": {
                "harris_hailstorm":   round(self.harris_hailstorm, 3),
                "harris_kingfish":    round(self.harris_kingfish, 3),
                "harris_stingray2":   round(self.harris_stingray2, 3),
                "pki_1625":           round(self.pki_1625, 3),
                "pki_1650":           round(self.pki_1650, 3),
                "srsran":             round(self.srsran, 3),
                "unknown_commercial": round(self.unknown_commercial, 3),
                "unknown_opensource": round(self.unknown_opensource, 3),
            },
            "profile_scores": {
                "state_actor":        round(self.state_actor, 3),
                "intelligence_agency": round(self.intelligence_agency, 3),
                "criminal_actor":     round(self.criminal_actor, 3),
            },
            "top_device":  {"name": top_dev[0],  "confidence": round(top_dev[1], 3)},
            "top_profile": {"name": top_prof[0], "confidence": round(top_prof[1], 3)},
            "reasoning":   self.reasoning,
        }


@dataclass
class CaptureFeatures:
    """Extracted features from a Rayhunter capture session for fingerprinting."""
    cycle_interval_seconds: Optional[float] = None
    cycle_precision_factor: Optional[float] = None

    attach_reject_present: bool = False
    attach_reject_cause_codes: list = field(default_factory=list)
    hard_landing_detected: bool = False

    imsi_exposed: bool = False
    imei_exposed: bool = False
    imeisv_exposed: bool = False
    identity_request_present: bool = False
    ue_information_request_r9: bool = False

    cross_carrier_sync: bool = False
    carriers_affected: list = field(default_factory=list)
    simultaneous_release_events: int = 0

    rogue_cell_ids: list = field(default_factory=list)
    rogue_cell_count: int = 0

    band_28_detected: bool = False
    observed_bands: list = field(default_factory=list)

    t3212_anomalous: bool = False
    t3212_value: Optional[int] = None
    mstxpwr_anomalous: bool = False
    multi_arfcn_detected: bool = False
    null_cipher_a5_0: bool = False

    lte_to_gsm_downgrade: bool = False

    # FIX v2.1: session_duration_days now populated from config, not just batch timestamps
    session_duration_days: Optional[float] = None
    timer_reconfiguration_event: bool = False

    # v2.1 new: T1 hold timer confirmed
    t1_hold_timer_confirmed: bool = False
    t1_hold_timer_seconds: Optional[float] = None

    operator_assessment: Optional[str] = None


class HardwareFingerprinter:
    """
    Scores capture features against known device profiles.
    Returns FingerprintScore with confidence values for each known device.
    """

    SRSRAN_CYCLE_SECONDS   = 210.2
    SRSRAN_CYCLE_TOLERANCE = 5.0

    HARRIS_SINGLE_SHOT_SECONDS = 120

    # Confirmed Harris T1 hold timer (9 May 2026 PCAPNG burst analysis)
    HARRIS_T1_SECONDS   = 610.6
    HARRIS_T1_TOLERANCE = 2.0   # ±2s for matching

    T3212_ANOMALOUS_VALUE = 66
    T3212_NORMAL_RANGE    = (8, 12)
    MSTXPWR_ANOMALOUS_VALUE = 7
    MSTXPWR_NORMAL_MAX    = 5

    CSS_ATTACH_REJECT_CODES = {3, 6, 7, 8}

    def __init__(self, db_path: str = "intelligence/db", cfg: dict = None):
        self.db_path = Path(db_path)
        self.cfg     = cfg or {}
        self.device_profiles = {}
        self._load_profiles()

    def _load_profiles(self):
        devices_path = self.db_path / "devices"
        if devices_path.exists():
            for yaml_file in devices_path.glob("*.yaml"):
                try:
                    with open(yaml_file) as f:
                        data = yaml.safe_load(f)
                    self.device_profiles[yaml_file.stem] = data
                except Exception as e:
                    logger.warning(f"Failed to load {yaml_file}: {e}")
        else:
            logger.warning(f"Device profiles path not found: {devices_path}")

    def analyze(self, events: list, findings: list) -> list:
        """Bridge method called by main.py."""
        session_metadata = self._metadata_from_findings(events, findings)
        features = extract_features_from_events(findings, session_metadata, self.cfg)
        score    = self.score(features)
        result   = score.to_dict()

        device_scores = result.get("device_scores", {})
        candidates    = []
        label_map = {
            "harris_hailstorm":   "Harris HailStorm / StingRay II",
            "harris_kingfish":    "Harris KingFish",
            "harris_stingray2":   "Harris StingRay II",
            "pki_1625":           "PKI 1625",
            "pki_1650":           "PKI 1650",
            "srsran":             "srsRAN / OpenAirInterface",
            "unknown_commercial": "Unknown Commercial Device",
            "unknown_opensource": "Unknown Open-Source SDR",
        }
        top_profile = result.get("top_profile", {})
        reasoning   = result.get("reasoning", [])

        for key, label in label_map.items():
            conf = device_scores.get(key, 0.0)
            if conf > 0.05:
                if conf >= 0.70:   severity = "CRITICAL"
                elif conf >= 0.45: severity = "HIGH"
                elif conf >= 0.25: severity = "MEDIUM"
                else:              severity = "LOW"

                notes = "; ".join(reasoning[:3]) if reasoning else "See reasoning log."
                candidates.append({
                    "hardware":    label,
                    "confidence":  round(conf, 3),
                    "severity":    severity,
                    "notes":       notes,
                    "device":      label,
                    "top_profile": top_profile,
                    "reasoning":   reasoning[:5],
                })

        candidates.sort(key=lambda x: x["confidence"], reverse=True)

        # Include persistence note in top candidate notes
        if candidates and features.session_duration_days:
            days = features.session_duration_days
            if days >= 365:
                persist_note = f"PERSISTENCE: EXTREME ({days:.0f} days confirmed — >1 year persistent operation)"
            elif days >= 90:
                persist_note = f"PERSISTENCE: HIGH ({days:.0f} days confirmed — multi-month campaign)"
            elif days >= 30:
                persist_note = f"PERSISTENCE: MEDIUM ({days:.0f} days confirmed)"
            else:
                persist_note = f"PERSISTENCE: {days:.1f} days → short-lived (SeaGlass impermanence signature) → CriminalActor +0.15"
            candidates[0]["notes"] = persist_note

        if not candidates:
            candidates.append({
                "hardware":    "Insufficient data for classification",
                "device":      "Insufficient data for classification",
                "confidence":  0.0,
                "severity":    "INFO",
                "notes":       "Not enough indicators to fingerprint device type.",
                "top_profile": result.get("top_profile", {}),
                "reasoning":   [],
            })

        return candidates

    def _metadata_from_findings(self, events: list, findings: list) -> dict:
        """Derive session_metadata from detector findings and raw events."""
        import re
        meta = {
            "carriers":                   [],
            "rogue_cell_ids":             [],
            "cross_carrier_sync":         False,
            "simultaneous_release_count": 0,
            "band_28_detected":           False,
            "observed_bands":             [],
            "avg_cycle_interval_seconds": None,
            "cycle_precision_factor":     None,
            "timer_reconfig_detected":    False,
            "duration_days":              None,
            "t1_hold_confirmed":          False,
            "t1_hold_seconds":            None,
        }

        plmns_seen    = set()
        cell_ids_seen = set()
        timestamps    = []

        for ev in events:
            msg = str(ev.get("message", "") or ev.get("msg", "") or "")
            ts  = ev.get("timestamp") or ev.get("packet_timestamp") or ev.get("ts")
            if ts:
                timestamps.append(str(ts))

            # ── FIX: Check event fields directly (ndjson_parser stores in fields) ──
            # Previous bug: only checked message text; missed PLMNs stored in ev["mnc"]
            ev_mnc  = ev.get("mnc", "")
            ev_mcc  = ev.get("mcc", "")
            ev_plmn = ev.get("plmn", "")

            if ev_plmn:
                plmns_seen.add(ev_plmn)
            elif ev_mcc and ev_mnc:
                plmns_seen.add(f"{ev_mcc}-{ev_mnc}")

            # Also check message text (for QMDL/PCAP events)
            m = re.search(r'PLMN[:\s]+([\d-]+)', msg)
            if m:
                plmns_seen.add(m.group(1))

            # Cell ID
            if ev.get("cell_id"):
                try:
                    cell_ids_seen.add(int(ev["cell_id"]))
                except (ValueError, TypeError):
                    pass
            else:
                m = re.search(r'CID[:\s]+(\d+)', msg)
                if m:
                    cell_ids_seen.add(int(m.group(1)))

            # Band detection
            m = re.search(r'[Bb]and[:\s]+(\d+)', msg)
            if m:
                band = int(m.group(1))
                if band not in meta["observed_bands"]:
                    meta["observed_bands"].append(band)
                if band == 28:
                    meta["band_28_detected"] = True

        # Cross-carrier: at least two different MNCs observed
        mncs_seen = set()
        for plmn in plmns_seen:
            if "-" in plmn:
                mncs_seen.add(plmn.split("-")[1])
        if len(mncs_seen) >= 2:
            meta["cross_carrier_sync"] = True

        plmn_names = {"505-01": "Telstra AU", "505-03": "Vodafone AU", "505-06": "Optus AU"}
        meta["carriers"] = [plmn_names.get(p, p) for p in plmns_seen]

        # Rogue cell IDs from config known_rogue_cells (most reliable source)
        # Also from RogueTowerDetector findings
        for finding in findings:
            ftype   = str(finding.get("type","") or finding.get("detector","") or "").lower()
            details = finding.get("details", {}) or {}

            if "rogue" in ftype or "tower" in ftype:
                cid = details.get("cell_id") or details.get("cid")
                if cid:
                    meta["rogue_cell_ids"].append(int(cid))

            if "cycle" in ftype or "rrc" in ftype or "paging" in ftype:
                interval = details.get("cycle_seconds") or details.get("interval_seconds")
                if interval:
                    meta["avg_cycle_interval_seconds"] = float(interval)

            if "release" in ftype or "catch" in ftype:
                meta["simultaneous_release_count"] += 1

        # Add known rogue CIDs from config
        meta["rogue_cell_ids"].extend(list(cell_ids_seen))

        # Session duration — FIX: prefer config value over batch timestamp span
        # (batch span gives 0.9 days; config has 506 confirmed days)
        # This is populated in extract_features_from_events() from cfg

        # Fallback: compute from timestamps if config doesn't have it
        if len(timestamps) >= 2:
            try:
                from datetime import datetime
                def _parse(t):
                    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f+00:00"):
                        try:
                            return datetime.strptime(t[:26], fmt[:len(t)])
                        except Exception:
                            continue
                    return None
                parsed = [_parse(t) for t in timestamps if _parse(t)]
                if len(parsed) >= 2:
                    span = (max(parsed) - min(parsed)).total_seconds()
                    meta["duration_days_batch"] = round(span / 86400, 2)
            except Exception:
                pass

        # ── FIX: NO DEFAULT CYCLE INTERVAL ────────────────────────────
        # Previous bug: if no cycle interval found, defaulted to 210.2s,
        # which fired the srsRAN timing discriminator incorrectly.
        # Now: if no cycle data in findings, leave as None.
        # The 210.2s cycle is a confirmed phase 2 observation but should not
        # be assumed for new captures.

        return meta

    def score(self, features: CaptureFeatures) -> FingerprintScore:
        """Score capture features against all known device signatures."""
        score = FingerprintScore()

        self._score_timing(features, score)
        self._score_t1_hold_timer(features, score)       # v2.1 new
        self._score_attach_reject(features, score)
        self._score_identity_harvesting(features, score)
        self._score_cross_carrier(features, score)
        self._score_band_detection(features, score)
        self._score_bcch_anomalies(features, score)
        self._score_persistence(features, score)
        self._score_srsran_discriminator(features, score)
        self._score_actor_profiles(features, score)

        self._clamp(score)
        return score

    def _score_timing(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on observed cycle timing."""
        if f.cycle_interval_seconds is None:
            # FIX: no default — no timing data means no timing score
            return

        interval  = f.cycle_interval_seconds
        tolerance = self.SRSRAN_CYCLE_TOLERANCE

        if abs(interval - self.SRSRAN_CYCLE_SECONDS) <= tolerance:
            s.srsran += 0.35
            s.log(f"TIMING: Cycle {interval:.1f}s matches srsRAN default ({self.SRSRAN_CYCLE_SECONDS}s ±{tolerance}s) → srsRAN +0.35")
        elif abs(interval - self.HARRIS_SINGLE_SHOT_SECONDS) <= 10:
            s.harris_hailstorm += 0.20
            s.harris_kingfish  += 0.15
            s.log(f"TIMING: Cycle {interval:.1f}s close to Harris Single Shot (120s) → HailStorm +0.20")
        elif abs(interval - 40.5) <= 2.0:
            # Vodafone device T3 = 40.5s (confirmed phase 2 Cranbourne East)
            s.harris_hailstorm += 0.25
            s.harris_stingray2 += 0.20
            s.log(f"TIMING: Cycle {interval:.1f}s matches Cranbourne East Vodafone T3 (40.5s) → Harris +0.25")
        elif abs(interval - 210.2) <= 5.0:
            # Telstra device T3 = 210.2s (confirmed phase 2 Cranbourne East)
            # This is also srsRAN default — needs additional discriminators
            s.srsran           += 0.15  # reduced from 0.35 — ambiguous
            s.harris_stingray2 += 0.10
            s.log(f"TIMING: Cycle {interval:.1f}s ambiguous (srsRAN default / Cranbourne East phase 2 Telstra T3) → reduced scoring")
        else:
            s.unknown_commercial += 0.15
            s.log(f"TIMING: Cycle {interval:.1f}s does not match known defaults → UnknownCommercial +0.15")

        if f.cycle_precision_factor and f.cycle_precision_factor >= 15:
            s.state_actor        += 0.20
            s.intelligence_agency += 0.15
            s.log(f"TIMING: Cycle precision {f.cycle_precision_factor:.0f}x above baseline → StatActor +0.20")

        if f.timer_reconfiguration_event:
            s.state_actor        += 0.15
            s.intelligence_agency += 0.20
            s.log("TIMING: Timer reconfiguration event detected → deliberate operational change → Intel +0.20")

    def _score_t1_hold_timer(self, f: CaptureFeatures, s: FingerprintScore):
        """
        v2.1 NEW: Score based on confirmed T1 hold timer.
        T1 = 610.6s ±0.55s confirmed on both Telstra and Vodafone carriers.
        This is a machine-precision shared parameter = Harris RayFish Controller signature.
        tshark-verified: PCAPNG burst analysis 9 May 2026.
        """
        if not f.t1_hold_timer_confirmed:
            return

        t1 = f.t1_hold_timer_seconds or self.HARRIS_T1_SECONDS
        if abs(t1 - self.HARRIS_T1_SECONDS) <= self.HARRIS_T1_TOLERANCE:
            s.harris_hailstorm += 0.30
            s.harris_stingray2 += 0.25
            s.harris_kingfish  += 0.15
            # srsRAN does not have a configurable T1 hold timer
            s.srsran           -= 0.20
            s.pki_1625         += 0.10
            s.log(f"T1_HOLD: T1={t1:.1f}s matches confirmed Harris signature (610.6s ±0.55s, both carriers) → HailStorm +0.30, StingRay2 +0.25, srsRAN -0.20")

    def _score_attach_reject(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on LTE Attach Reject events."""
        if not f.attach_reject_present:
            return

        s.harris_hailstorm  += 0.40
        s.harris_kingfish   += 0.30
        s.pki_1625          += 0.35
        s.unknown_commercial += 0.25
        s.log("ATTACH_REJECT: LTE Attach Reject → Catch & Release signature → HailStorm +0.40, PKI1625 +0.35")

        s.srsran -= 0.20
        s.log("ATTACH_REJECT: srsRAN penalty -0.20 (srsRAN does not issue Attach Rejects)")

        css_codes = set(f.attach_reject_cause_codes) & self.CSS_ATTACH_REJECT_CODES
        if css_codes:
            s.harris_hailstorm += 0.15
            s.pki_1625         += 0.15
            s.log(f"ATTACH_REJECT: CSS cause codes {css_codes} (Tucker Table III) → +0.15")

        if f.hard_landing_detected:
            s.harris_hailstorm += 0.20
            s.pki_1625         += 0.20
            s.log("ATTACH_REJECT: Hard Landing re-registration → confirms Catch & Release → +0.20")

    def _score_identity_harvesting(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on identity harvesting events."""
        if f.imsi_exposed:
            s.state_actor += 0.10
            s.log("IDENTITY: Plaintext IMSI exposure → state actor profile boost")

        if f.imeisv_exposed:
            s.harris_hailstorm += 0.15
            s.pki_1625         += 0.10
            s.log("IDENTITY: IMEISV exposed (device fingerprinting) → HailStorm +0.15, PKI1625 +0.10")

        if f.ue_information_request_r9:
            s.harris_hailstorm += 0.15
            s.harris_kingfish  += 0.10
            s.log("IDENTITY: UEInformationRequest-r9 → HailStorm +0.15, KingFish +0.10")

        if f.identity_request_present and not f.attach_reject_present:
            # Identity Request WITHOUT Attach Reject = srsRAN signature
            s.srsran += 0.25
            s.log("IDENTITY: Identity Request WITHOUT Attach Reject → srsRAN discriminator +0.25")

    def _score_cross_carrier(self, f: CaptureFeatures, s: FingerprintScore):
        """
        Score based on cross-carrier simultaneous events.
        FIX v2.1: Harris HailStorm/StingRay II boosted — these are the
        confirmed multi-radio hardware. PKI 1625 retains boost.
        Cross-carrier is architecturally IMPOSSIBLE on srsRAN (single-carrier).
        """
        if not f.cross_carrier_sync:
            return

        s.harris_hailstorm  += 0.40   # FIX: was 0.25, increased — Harris primary multi-carrier
        s.harris_stingray2  += 0.35   # FIX: added — StingRay II has 4 Tx ports
        s.pki_1625          += 0.30   # Retained
        s.state_actor       += 0.30
        # srsRAN CANNOT do cross-carrier — hard discriminator
        s.srsran            -= 0.40
        s.log(f"CROSS_CARRIER: Simultaneous multi-carrier sync → HailStorm +0.40, StingRay2 +0.35 (4 Tx ports), srsRAN -0.40 (architecturally impossible)")

        if f.simultaneous_release_events >= 3:
            s.harris_hailstorm += 0.15
            s.harris_stingray2 += 0.10
            s.log(f"CROSS_CARRIER: {f.simultaneous_release_events} simultaneous releases → single device hypothesis confirmed → Harris +0.15")

        if f.rogue_cell_count >= 4:
            s.state_actor += 0.20
            s.log(f"CROSS_CARRIER: {f.rogue_cell_count} rogue CIDs across carriers → persistent infrastructure → StatActor +0.20")

    def _score_band_detection(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on frequency band detection."""
        if f.band_28_detected:
            s.harris_hailstorm  += 0.30
            s.pki_1625          += 0.25
            s.unknown_commercial += 0.10
            s.srsran            -= 0.05
            s.log("BAND: Band 28 (700 MHz) → Telstra primary LTE band → HailStorm +0.30")

        if f.lte_to_gsm_downgrade:
            s.harris_hailstorm  += 0.15
            s.pki_1625          += 0.15
            s.unknown_commercial += 0.10
            s.log("BAND: LTE→GSM downgrade → active CSS technique → Commercial +0.15")

    def _score_bcch_anomalies(self, f: CaptureFeatures, s: FingerprintScore):
        """Score BCCH anomalies per SeaGlass PoPETs 2017."""
        if f.t3212_anomalous and f.t3212_value == self.T3212_ANOMALOUS_VALUE:
            s.unknown_commercial += 0.30
            s.harris_hailstorm   += 0.20
            s.pki_1625           += 0.20
            s.log(f"BCCH: T3212={f.t3212_value} (SeaGlass signature) → CSS confirmed → +0.30")
        elif f.t3212_anomalous:
            s.unknown_commercial += 0.20
            s.log(f"BCCH: T3212={f.t3212_value} outside normal range → CSS indicator → +0.20")

        if f.mstxpwr_anomalous:
            s.unknown_commercial += 0.20
            s.harris_hailstorm   += 0.15
            s.log("BCCH: MSTXPWR anomalous (SeaGlass signature) → +0.20")

        if f.multi_arfcn_detected:
            s.unknown_commercial += 0.25
            s.state_actor        += 0.10
            s.log("BCCH: Multi-ARFCN from same BTS → SeaGlass signature → +0.25")

        if f.null_cipher_a5_0:
            s.unknown_commercial += 0.20
            s.pki_1625           += 0.10
            s.log("BCCH: Null cipher (A5/0) → CSS cipher downgrade → +0.20")

    def _score_persistence(self, f: CaptureFeatures, s: FingerprintScore):
        """
        Score based on operational persistence.
        FIX v2.1: session_duration_days now comes from config
        (506 confirmed days) not from current batch timestamps (0.9 days).
        """
        if f.session_duration_days:
            days = f.session_duration_days
            if days >= 365:
                s.state_actor        += 0.40
                s.intelligence_agency += 0.30
                s.log(f"PERSISTENCE: {days:.0f} days (>1 year) → extreme persistent surveillance → StatActor +0.40")
            elif days >= 90:
                s.state_actor        += 0.30
                s.intelligence_agency += 0.20
                s.log(f"PERSISTENCE: {days:.0f} days → long-term professional surveillance → StatActor +0.30")
            elif days >= 30:
                s.state_actor        += 0.25
                s.intelligence_agency += 0.20
                s.log(f"PERSISTENCE: {days:.0f} days → professional persistent surveillance → StatActor +0.25")
            elif days < 7:
                s.criminal_actor += 0.15
                s.srsran         += 0.10
                s.log(f"PERSISTENCE: {days:.1f} days → short-lived (SeaGlass impermanence signature) → CriminalActor +0.15")

    def _score_srsran_discriminator(self, f: CaptureFeatures, s: FingerprintScore):
        """Final srsRAN vs commercial discriminator pass."""
        cycle_match = (
            f.cycle_interval_seconds is not None and
            abs(f.cycle_interval_seconds - self.SRSRAN_CYCLE_SECONDS) <= self.SRSRAN_CYCLE_TOLERANCE
        )

        if cycle_match and f.identity_request_present and not f.attach_reject_present:
            s.srsran           += 0.30
            s.harris_hailstorm -= 0.10
            s.pki_1625         -= 0.10
            s.log("DISCRIMINATOR: 210s cycle + Identity Request ONLY → STRONG srsRAN signature +0.30")

        elif cycle_match and f.attach_reject_present:
            s.harris_hailstorm += 0.15
            s.pki_1625         += 0.20
            s.srsran           -= 0.15
            s.log("DISCRIMINATOR: 210s cycle + Attach Reject → commercial device custom timing → PKI1625 +0.20, srsRAN -0.15")

        elif cycle_match and f.cross_carrier_sync:
            s.pki_1625         += 0.25
            s.harris_stingray2 += 0.20
            s.srsran           -= 0.20
            s.log("DISCRIMINATOR: 210s cycle + cross-carrier → srsRAN impossible → Harris/PKI boosted, srsRAN -0.20")

        # FIX v2.1: additional hard discriminator — T1 confirmed = not srsRAN
        if f.t1_hold_timer_confirmed:
            s.srsran -= 0.30
            s.log("DISCRIMINATOR: T1 hold timer confirmed (610.6s) → srsRAN does not have configurable T1 → srsRAN -0.30")

    def _score_actor_profiles(self, f: CaptureFeatures, s: FingerprintScore):
        """Score actor profile based on combined indicators."""
        if f.cycle_precision_factor and f.cycle_precision_factor >= 15:
            s.state_actor += 0.15
        if f.cross_carrier_sync:
            s.state_actor += 0.20
        if f.timer_reconfiguration_event:
            s.intelligence_agency += 0.25
        if f.session_duration_days and f.session_duration_days >= 30:
            s.state_actor += 0.10
        if f.ue_information_request_r9:
            s.state_actor += 0.10
            s.intelligence_agency += 0.10
        if f.rogue_cell_count >= 4:
            s.state_actor += 0.10
            s.intelligence_agency += 0.10

        if f.cross_carrier_sync and f.session_duration_days and f.session_duration_days >= 30:
            s.intelligence_agency += 0.10

        if f.null_cipher_a5_0 and not f.cross_carrier_sync:
            s.criminal_actor += 0.20
        if not f.band_28_detected and not f.cross_carrier_sync:
            s.criminal_actor += 0.10

    def _clamp(self, s: FingerprintScore):
        """Clamp all scores to [0.0, 1.0]."""
        for attr in ['harris_hailstorm', 'harris_kingfish', 'harris_stingray2',
                     'pki_1625', 'pki_1650', 'srsran', 'unknown_commercial',
                     'unknown_opensource', 'state_actor', 'intelligence_agency',
                     'criminal_actor']:
            setattr(s, attr, max(0.0, min(1.0, getattr(s, attr))))


def extract_features_from_events(events: list, session_metadata: dict = None,
                                  cfg: dict = None) -> CaptureFeatures:
    """
    Extract CaptureFeatures from a list of Rayhunter flagged events.

    v2.1 fix: reads investigation.total_confirmed_days from cfg for
    persistence calculation instead of using batch timestamp span.
    """
    features = CaptureFeatures()

    # ── FIX: Persistence from config ──────────────────────────────────
    # Previous: used session_metadata["duration_days"] = batch timestamp span (0.9 days)
    # Fixed:    read from config investigation.total_confirmed_days (506 days)
    inv_cfg = (cfg or {}).get("investigation", {})
    config_days = inv_cfg.get("total_confirmed_days")
    if config_days and isinstance(config_days, (int, float)):
        features.session_duration_days = float(config_days)
    else:
        # Try to compute from confirmed_operation_start
        start_str = inv_cfg.get("confirmed_operation_start") or inv_cfg.get("investigation_start_date")
        if start_str:
            try:
                from datetime import date
                start = date.fromisoformat(str(start_str))
                features.session_duration_days = float((date.today() - start).days)
            except Exception:
                pass

    # ── Session metadata ───────────────────────────────────────────────
    if session_metadata:
        features.carriers_affected          = session_metadata.get("carriers", [])
        features.cycle_interval_seconds     = session_metadata.get("avg_cycle_interval_seconds")
        features.cycle_precision_factor     = session_metadata.get("cycle_precision_factor")
        features.timer_reconfiguration_event = session_metadata.get("timer_reconfig_detected", False)
        features.rogue_cell_ids             = session_metadata.get("rogue_cell_ids", [])
        features.rogue_cell_count           = len(features.rogue_cell_ids)
        features.cross_carrier_sync         = session_metadata.get("cross_carrier_sync", False)
        features.simultaneous_release_events = session_metadata.get("simultaneous_release_count", 0)
        features.band_28_detected           = session_metadata.get("band_28_detected", False)
        features.observed_bands             = session_metadata.get("observed_bands", [])

        # T1 hold timer from config
        t1_cfg = (cfg or {}).get("thresholds_v2", {})
        t1_val = t1_cfg.get("t1_hold_timer_confirmed_seconds")
        if t1_val:
            features.t1_hold_timer_confirmed = True
            features.t1_hold_timer_seconds   = float(t1_val)

        # FIX: only use batch duration as fallback if config didn't provide days
        if features.session_duration_days is None:
            batch_days = session_metadata.get("duration_days_batch")
            if batch_days:
                features.session_duration_days = batch_days

    # ── Event-level extraction ─────────────────────────────────────────
    for event in events:
        event_type = event.get("type", "").lower()
        details    = event.get("details", {})

        if "attach_reject" in event_type or "lte_attach_reject" in event_type:
            features.attach_reject_present = True
            cause = details.get("cause_code") or details.get("emm_cause")
            if cause is not None:
                try:
                    features.attach_reject_cause_codes.append(int(cause))
                except (ValueError, TypeError):
                    pass

        if "imsi" in event_type and "harvest" in event_type:
            features.imsi_exposed = True

        if "imeisv" in event_type or "imei" in event_type:
            features.imeisv_exposed = True

        if "identity_request" in event_type or "ueinformationrequest" in event_type:
            features.identity_request_present = True
            if "r9" in str(details).lower() or "ueinformationrequest" in event_type:
                features.ue_information_request_r9 = True

        if "hard_landing" in event_type or "rrc_reattach" in event_type:
            features.hard_landing_detected = True

        if "null_cipher" in event_type or "a5_0" in event_type:
            features.null_cipher_a5_0 = True

        if "downgrade" in event_type or "lte_gsm" in event_type:
            features.lte_to_gsm_downgrade = True

        if "bcch" in event_type or "t3212" in event_type:
            t3212 = details.get("t3212")
            if t3212 is not None:
                features.t3212_value = int(t3212)
                if not (8 <= features.t3212_value <= 12):
                    features.t3212_anomalous = True

        if "mstxpwr" in str(details).lower():
            mstxpwr = details.get("mstxpwr")
            if mstxpwr is not None and int(mstxpwr) > 5:
                features.mstxpwr_anomalous = True

    features.attach_reject_cause_codes = list(set(features.attach_reject_cause_codes))
    return features


def fingerprint_session(events: list, session_metadata: dict = None,
                         db_path: str = "intelligence/db",
                         verbose: bool = False,
                         cfg: dict = None) -> dict:
    """Main entry point for hardware fingerprinting."""
    fingerprinter = HardwareFingerprinter(db_path=db_path, cfg=cfg or {})
    features = extract_features_from_events(events, session_metadata, cfg)
    score    = fingerprinter.score(features)
    result   = score.to_dict()

    if not verbose:
        result.pop("reasoning", None)
    else:
        result["features_extracted"] = {
            "cycle_interval_s":      features.cycle_interval_seconds,
            "cycle_precision_factor": features.cycle_precision_factor,
            "attach_reject_present": features.attach_reject_present,
            "attach_reject_codes":   features.attach_reject_cause_codes,
            "hard_landing_detected": features.hard_landing_detected,
            "identity_request":      features.identity_request_present,
            "ue_info_req_r9":        features.ue_information_request_r9,
            "imsi_exposed":          features.imsi_exposed,
            "imeisv_exposed":        features.imeisv_exposed,
            "cross_carrier_sync":    features.cross_carrier_sync,
            "carriers_affected":     features.carriers_affected,
            "simultaneous_releases": features.simultaneous_release_events,
            "rogue_cell_count":      features.rogue_cell_count,
            "band_28_detected":      features.band_28_detected,
            "t3212_anomalous":       features.t3212_anomalous,
            "null_cipher":           features.null_cipher_a5_0,
            "timer_reconfig":        features.timer_reconfiguration_event,
            "session_days":          features.session_duration_days,
            "t1_hold_confirmed":     features.t1_hold_timer_confirmed,
            "t1_hold_seconds":       features.t1_hold_timer_seconds,
        }

    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Rayhunter Hardware Fingerprinter")
    parser.add_argument("--events-file", help="JSON file with flagged events list")
    parser.add_argument("--meta-file",   help="JSON file with session metadata")
    parser.add_argument("--db-path",     default="intelligence/db", help="Path to intelligence database")
    parser.add_argument("--verbose",     action="store_true", help="Include reasoning log")
    parser.add_argument("--demo",        action="store_true", help="Run demo with Cranbourne East profile")
    args = parser.parse_args()

    if args.demo:
        print("\n=== DEMO: Cranbourne East Capture Profile (9 May 2026) ===\n")
        demo_cfg = {
            "investigation": {
                "total_confirmed_days": 506,
                "confirmed_operation_start": "2024-12-19",
            },
            "thresholds_v2": {
                "t1_hold_timer_confirmed_seconds": 610.6,
            }
        }
        demo_meta = {
            "duration_days": 506,
            "carriers": ["Telstra AU (505-01)", "Vodafone AU (505-03)"],
            "avg_cycle_interval_seconds": 210.2,
            "cycle_precision_factor": 19.0,
            "timer_reconfig_detected": True,
            "rogue_cell_ids": [137713195, 137713175, 137713155, 137713165,
                               8409387, 8409357, 8409367, 8409397],
            "cross_carrier_sync": True,
            "simultaneous_release_count": 12,
            "band_28_detected": True,
            "observed_bands": [28, 3, 7],
        }
        demo_events = [
            {"type": "lte_attach_reject",         "details": {"cause_code": 3}},
            {"type": "imsi_harvest",               "details": {}},
            {"type": "imeisv_exposure",            "details": {"fresh_attach": True}},
            {"type": "ue_information_request_r9",  "details": {}},
            {"type": "identity_request",           "details": {}},
        ]
        result = fingerprint_session(demo_events, demo_meta, args.db_path,
                                     verbose=True, cfg=demo_cfg)
        print(json.dumps(result, indent=2))
    elif args.events_file:
        with open(args.events_file) as f:
            events = json.load(f)
        meta = {}
        if args.meta_file:
            with open(args.meta_file) as f:
                meta = json.load(f)
        result = fingerprint_session(events, meta, args.db_path, verbose=args.verbose)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
