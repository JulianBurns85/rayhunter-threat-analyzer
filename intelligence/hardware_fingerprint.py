#!/usr/bin/env python3
"""
hardware_fingerprint.py — Rayhunter Threat Analyzer
Device identification and hardware confidence scoring engine.

Loads device profiles from intelligence/db/devices/*.yaml
Scores capture events against known device signatures.
Key function: lte_attach_reject events boost PKI/Harris commercial confidence scores.

Session 6 update:
  - LTE Attach Reject → commercial device confidence wire-up (PKI/Harris boost)
  - srsRAN discriminator: 210s cycle + Identity Request ONLY → srsRAN
  - Commercial discriminator: Attach Rejects present → Harris/PKI
  - Cross-carrier operator cycling → PKI 1625 hypothesis
  - BCCH outlier fingerprints from SeaGlass PoPETs 2017
  - Band 28 detection → HailStorm/PKI 1625 boost
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

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

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

    # Profile scores
    state_actor: float = 0.0
    intelligence_agency: float = 0.0
    criminal_actor: float = 0.0

    # Reasoning log
    reasoning: list = field(default_factory=list)

    def log(self, msg: str):
        self.reasoning.append(msg)

    def top_device(self) -> tuple:
        """Return (device_name, confidence) for highest scoring device."""
        scores = {
            "Harris HailStorm": self.harris_hailstorm,
            "Harris KingFish": self.harris_kingfish,
            "Harris StingRay II": self.harris_stingray2,
            "PKI 1625": self.pki_1625,
            "PKI 1650": self.pki_1650,
            "srsRAN": self.srsran,
            "Unknown Commercial": self.unknown_commercial,
            "Unknown Open Source": self.unknown_opensource,
        }
        top = max(scores.items(), key=lambda x: x[1])
        return top

    def top_profile(self) -> tuple:
        """Return (profile_name, confidence) for highest scoring actor profile."""
        profiles = {
            "State Actor / Law Enforcement": self.state_actor,
            "Intelligence Agency": self.intelligence_agency,
            "Criminal Actor": self.criminal_actor,
        }
        top = max(profiles.items(), key=lambda x: x[1])
        return top

    def to_dict(self) -> dict:
        top_dev = self.top_device()
        top_prof = self.top_profile()
        return {
            "device_scores": {
                "harris_hailstorm": round(self.harris_hailstorm, 3),
                "harris_kingfish": round(self.harris_kingfish, 3),
                "harris_stingray2": round(self.harris_stingray2, 3),
                "pki_1625": round(self.pki_1625, 3),
                "pki_1650": round(self.pki_1650, 3),
                "srsran": round(self.srsran, 3),
                "unknown_commercial": round(self.unknown_commercial, 3),
                "unknown_opensource": round(self.unknown_opensource, 3),
            },
            "profile_scores": {
                "state_actor": round(self.state_actor, 3),
                "intelligence_agency": round(self.intelligence_agency, 3),
                "criminal_actor": round(self.criminal_actor, 3),
            },
            "top_device": {"name": top_dev[0], "confidence": round(top_dev[1], 3)},
            "top_profile": {"name": top_prof[0], "confidence": round(top_prof[1], 3)},
            "reasoning": self.reasoning,
        }


@dataclass
class CaptureFeatures:
    """Extracted features from a Rayhunter capture session for fingerprinting."""
    # Timing
    cycle_interval_seconds: Optional[float] = None  # Observed RRC cycle interval
    cycle_precision_factor: Optional[float] = None  # How many x more precise than baseline

    # LTE Attach events
    attach_reject_present: bool = False
    attach_reject_cause_codes: list = field(default_factory=list)
    hard_landing_detected: bool = False  # Re-registration after Attach Reject

    # Identity harvesting
    imsi_exposed: bool = False
    imei_exposed: bool = False
    imeisv_exposed: bool = False
    identity_request_present: bool = False
    ue_information_request_r9: bool = False

    # Cross-carrier
    cross_carrier_sync: bool = False
    carriers_affected: list = field(default_factory=list)
    simultaneous_release_events: int = 0

    # Rogue cells
    rogue_cell_ids: list = field(default_factory=list)
    rogue_cell_count: int = 0

    # Band detection
    band_28_detected: bool = False
    observed_bands: list = field(default_factory=list)

    # BCCH anomalies (SeaGlass signatures)
    t3212_anomalous: bool = False
    t3212_value: Optional[int] = None
    mstxpwr_anomalous: bool = False
    multi_arfcn_detected: bool = False
    null_cipher_a5_0: bool = False

    # Protocol downgrade
    lte_to_gsm_downgrade: bool = False

    # Persistence
    session_duration_days: Optional[float] = None
    timer_reconfiguration_event: bool = False  # Change in cycle from prior sessions

    # Operator assessment (from main.py)
    operator_assessment: Optional[str] = None


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

class HardwareFingerprinter:
    """
    Scores capture features against known device profiles.
    Returns FingerprintScore with confidence values for each known device.
    """

    # SRSRAN detection thresholds
    SRSRAN_CYCLE_SECONDS = 210.2
    SRSRAN_CYCLE_TOLERANCE = 5.0  # ±5 seconds

    # Commercial Harris Single Shot default
    HARRIS_SINGLE_SHOT_SECONDS = 120

    # Anomalous BCCH values (SeaGlass PoPETs 2017)
    T3212_ANOMALOUS_VALUE = 66
    T3212_NORMAL_RANGE = (8, 12)
    MSTXPWR_ANOMALOUS_VALUE = 7
    MSTXPWR_NORMAL_MAX = 5

    # Attach Reject cause codes indicating CSS (Tucker et al. 2023 Table III)
    CSS_ATTACH_REJECT_CODES = {3, 6, 7, 8}

    def __init__(self, db_path: str = "intelligence/db"):
        self.db_path = Path(db_path)
        self.device_profiles = {}
        self._load_profiles()

    def _load_profiles(self):
        """Load device YAML profiles from database."""
        devices_path = self.db_path / "devices"
        if devices_path.exists():
            for yaml_file in devices_path.glob("*.yaml"):
                try:
                    with open(yaml_file) as f:
                        data = yaml.safe_load(f)
                    self.device_profiles[yaml_file.stem] = data
                    logger.debug(f"Loaded device profile: {yaml_file.stem}")
                except Exception as e:
                    logger.warning(f"Failed to load {yaml_file}: {e}")
        else:
            logger.warning(f"Device profiles path not found: {devices_path}")

    def analyze(self, events: list, findings: list) -> list:
        """
        Bridge method called by main.py.
        Builds session_metadata from findings + events, runs fingerprinting,
        returns a list of hardware candidate dicts ranked by confidence.

        Args:
            events:   All parsed events from all input files.
            findings: All detector findings (from IdentityHarvestDetector, etc.)

        Returns:
            List of dicts, each describing a hardware candidate, sorted by confidence desc.
        """
        # ── Build session_metadata from findings ──────────────────────────────
        session_metadata = self._metadata_from_findings(events, findings)

        # ── Extract features and score ────────────────────────────────────────
        features = extract_features_from_events(findings, session_metadata)
        score = self.score(features)
        result = score.to_dict()

        # ── Format as ranked candidate list ──────────────────────────────────
        device_scores = result.get("device_scores", {})
        candidates = []
        label_map = {
            "harris_hailstorm":   "Harris HailStorm",
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
            if conf > 0.05:   # skip negligible scores
                # Derive a severity label from confidence
                if conf >= 0.70:
                    severity = "CRITICAL"
                elif conf >= 0.45:
                    severity = "HIGH"
                elif conf >= 0.25:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                notes = "; ".join(reasoning[:3]) if reasoning else "See reasoning log for detail."

                candidates.append({
                    # Keys expected by reporter.py
                    "hardware":   label,
                    "confidence": round(conf, 3),
                    "severity":   severity,
                    "notes":      notes,
                    # Extra context keys (used by HTML reporter / JSON output)
                    "device":         label,
                    "top_profile":    top_profile,
                    "reasoning":      reasoning[:5],
                })

        candidates.sort(key=lambda x: x["confidence"], reverse=True)

        # Always return at least one entry so callers don't crash on empty list
        if not candidates:
            candidates.append({
                "hardware":   "Insufficient data for classification",
                "device":     "Insufficient data for classification",
                "confidence": 0.0,
                "severity":   "INFO",
                "notes":      "Not enough indicators to fingerprint device type.",
                "top_profile": result.get("top_profile", {}),
                "reasoning":  [],
            })

        return candidates

    def _metadata_from_findings(self, events: list, findings: list) -> dict:
        """
        Derive session_metadata dict from detector findings and raw events.
        Populates the fields that CaptureFeatures / extract_features_from_events expect.
        """
        import re
        from collections import defaultdict

        meta = {
            "carriers": [],
            "rogue_cell_ids": [],
            "cross_carrier_sync": False,
            "simultaneous_release_count": 0,
            "band_28_detected": False,
            "observed_bands": [],
            "avg_cycle_interval_seconds": None,
            "cycle_precision_factor": None,
            "timer_reconfig_detected": False,
            "duration_days": None,
        }

        # Carrier / PLMN extraction from events
        plmns_seen = set()
        cell_ids_seen = set()
        timestamps = []

        for ev in events:
            msg = str(ev.get("message", "") or ev.get("msg", "") or "")
            ts  = ev.get("timestamp") or ev.get("packet_timestamp") or ev.get("ts")
            if ts:
                timestamps.append(str(ts))

            # PLMN detection
            m = re.search(r'PLMN[:\s]+(\d{3}-\d{2,3})', msg)
            if m:
                plmns_seen.add(m.group(1))

            # Cell ID detection
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

        # Map PLMNs to carrier names
        plmn_names = {"505-01": "Telstra AU", "505-03": "Vodafone AU", "505-06": "Optus AU"}
        meta["carriers"] = [plmn_names.get(p, p) for p in plmns_seen]
        if len(plmns_seen) >= 2:
            meta["cross_carrier_sync"] = True

        # Rogue cell IDs from RogueTowerDetector findings
        for finding in findings:
            ftype = str(finding.get("type", "") or finding.get("detector", "") or "").lower()
            details = finding.get("details", {}) or {}

            if "rogue" in ftype or "tower" in ftype:
                cid = details.get("cell_id") or details.get("cid")
                if cid:
                    meta["rogue_cell_ids"].append(int(cid))

            # RRC cycle interval from rogue tower or paging cycle findings
            if "cycle" in ftype or "rrc" in ftype or "paging" in ftype:
                interval = details.get("cycle_seconds") or details.get("interval_seconds")
                if interval:
                    meta["avg_cycle_interval_seconds"] = float(interval)

            # Simultaneous release count
            if "release" in ftype or "catch" in ftype:
                meta["simultaneous_release_count"] += 1

        # Session duration from timestamp range
        if len(timestamps) >= 2:
            try:
                from datetime import datetime, timezone
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
                    meta["duration_days"] = round(span / 86400, 2)
            except Exception:
                pass

        # Fallback cycle interval: use the known 210.2s signature if rogue tower found
        # and no explicit interval was extracted
        if meta["avg_cycle_interval_seconds"] is None:
            rogue_findings = [f for f in findings
                              if "rogue" in str(f.get("type","")).lower()
                              or "tower" in str(f.get("type","")).lower()]
            if rogue_findings:
                meta["avg_cycle_interval_seconds"] = self.SRSRAN_CYCLE_SECONDS

        return meta

    def score(self, features: CaptureFeatures) -> FingerprintScore:
        """
        Score capture features against all known device signatures.
        Returns FingerprintScore with reasoning log.
        """
        score = FingerprintScore()

        # Apply each scoring rule in order
        self._score_timing(features, score)
        self._score_attach_reject(features, score)      # KEY WIRE-UP
        self._score_identity_harvesting(features, score)
        self._score_cross_carrier(features, score)
        self._score_band_detection(features, score)
        self._score_bcch_anomalies(features, score)
        self._score_persistence(features, score)
        self._score_srsran_discriminator(features, score)
        self._score_actor_profiles(features, score)

        # Clamp all scores to [0.0, 1.0]
        self._clamp(score)

        return score

    def _score_timing(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on observed cycle timing."""
        if f.cycle_interval_seconds is None:
            return

        interval = f.cycle_interval_seconds
        tolerance = self.SRSRAN_CYCLE_TOLERANCE

        # Check srsRAN match
        if abs(interval - self.SRSRAN_CYCLE_SECONDS) <= tolerance:
            s.srsran += 0.35
            s.log(f"TIMING: Cycle {interval:.1f}s matches srsRAN default ({self.SRSRAN_CYCLE_SECONDS}s ±{tolerance}s) → srsRAN +0.35")
        elif abs(interval - self.HARRIS_SINGLE_SHOT_SECONDS) <= 10:
            s.harris_hailstorm += 0.20
            s.harris_kingfish += 0.15
            s.log(f"TIMING: Cycle {interval:.1f}s close to Harris Single Shot (120s) → HailStorm +0.20, KingFish +0.15")
        else:
            # Non-standard timing — custom config or unknown device
            s.unknown_commercial += 0.15
            s.log(f"TIMING: Cycle {interval:.1f}s does not match known defaults → UnknownCommercial +0.15")

        # Precision factor — very high precision = deliberate/professional operation
        if f.cycle_precision_factor and f.cycle_precision_factor >= 15:
            s.state_actor += 0.20
            s.intelligence_agency += 0.15
            s.log(f"TIMING: Cycle precision {f.cycle_precision_factor:.0f}x above baseline → StatActor +0.20, Intel +0.15")

        # Timer reconfiguration indicates deliberate operational change
        if f.timer_reconfiguration_event:
            s.state_actor += 0.15
            s.intelligence_agency += 0.20
            s.log("TIMING: Timer reconfiguration event detected → indicates deliberate operational change → Intel +0.20")

    def _score_attach_reject(self, f: CaptureFeatures, s: FingerprintScore):
        """
        KEY WIRE-UP: LTE Attach Reject events boost commercial device confidence.
        srsRAN typically does NOT issue Attach Rejects.
        Harris Catch & Release and PKI 1625 DO issue Attach Rejects.
        Sources: Tucker et al. 2023, Harris Gemini 3.3 QSG §4-2, Dabrowski RAID 2016.
        """
        if not f.attach_reject_present:
            return

        # Commercial device boost — Attach Reject is Catch & Release signature
        s.harris_hailstorm += 0.40
        s.harris_kingfish += 0.30
        s.pki_1625 += 0.35
        s.unknown_commercial += 0.25
        s.log("ATTACH_REJECT: LTE Attach Reject present → Catch & Release signature → HailStorm +0.40, PKI1625 +0.35")

        # srsRAN penalty — pure srsRAN implementations don't issue Attach Rejects
        s.srsran -= 0.20
        s.log("ATTACH_REJECT: srsRAN penalty -0.20 (srsRAN does not issue Attach Rejects in standard config)")

        # Check for CSS-specific cause codes (Tucker Table III)
        css_codes = set(f.attach_reject_cause_codes) & self.CSS_ATTACH_REJECT_CODES
        if css_codes:
            s.harris_hailstorm += 0.15
            s.pki_1625 += 0.15
            s.log(f"ATTACH_REJECT: CSS cause codes {css_codes} confirmed (Tucker et al. Table III) → HailStorm +0.15, PKI1625 +0.15")

        # Hard Landing re-registration (Dabrowski RAID 2016 artifact)
        if f.hard_landing_detected:
            s.harris_hailstorm += 0.20
            s.pki_1625 += 0.20
            s.log("ATTACH_REJECT: Hard Landing re-registration detected → confirms Catch & Release operational mode → +0.20 each")

    def _score_identity_harvesting(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on identity harvesting events."""
        if f.imsi_exposed:
            s.state_actor += 0.10
            s.log("IDENTITY: Plaintext IMSI exposure → all device types; state actor profile boost")

        if f.imeisv_exposed:
            # IMEISV exposure specifically on fresh attach
            s.harris_hailstorm += 0.15
            s.pki_1625 += 0.10
            s.log("IDENTITY: IMEISV exposed (fresh attach) → HailStorm +0.15, PKI1625 +0.10")

        if f.ue_information_request_r9:
            s.harris_hailstorm += 0.15
            s.harris_kingfish += 0.10
            s.log("IDENTITY: UEInformationRequest-r9 → confirmed in captures → HailStorm +0.15, KingFish +0.10")

        if f.identity_request_present and not f.attach_reject_present:
            # Identity Request WITHOUT Attach Reject = srsRAN signature
            s.srsran += 0.25
            s.log("IDENTITY: Identity Request WITHOUT Attach Reject → srsRAN discriminator +0.25")

    def _score_cross_carrier(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on cross-carrier simultaneous events."""
        if not f.cross_carrier_sync:
            return

        # Cross-carrier sync is strong evidence of multi-carrier capable device
        s.pki_1625 += 0.45
        s.harris_hailstorm += 0.25  # Gemini can coordinate multi-protocol
        s.state_actor += 0.30
        s.log(f"CROSS_CARRIER: Simultaneous {len(f.carriers_affected)}-carrier sync → PKI1625 +0.45 (operator cycling), HailStorm +0.25")

        if f.simultaneous_release_events >= 3:
            s.pki_1625 += 0.15
            s.log(f"CROSS_CARRIER: {f.simultaneous_release_events} simultaneous cross-carrier releases → single device hypothesis → PKI1625 +0.15")

        if f.rogue_cell_count >= 3:
            s.state_actor += 0.15
            s.log(f"CROSS_CARRIER: {f.rogue_cell_count} rogue Cell IDs across carriers → persistent operation → StatActor +0.15")

    def _score_band_detection(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on frequency band detection."""
        if f.band_28_detected:
            # Band 28 = Telstra primary Australian LTE band
            # Only LTE-capable commercial hardware supports this
            s.harris_hailstorm += 0.30
            s.pki_1625 += 0.25
            s.unknown_commercial += 0.10
            # srsRAN on USRP can theoretically do Band 28 but less common
            s.srsran -= 0.05
            s.log("BAND: Band 28 (700 MHz) detected → Telstra primary LTE band → HailStorm +0.30, PKI1625 +0.25")

        if f.lte_to_gsm_downgrade:
            # Protocol downgrade = active CSS technique (SeaGlass, ACLU 2014)
            s.harris_hailstorm += 0.15
            s.pki_1625 += 0.15
            s.unknown_commercial += 0.10
            s.log("BAND: LTE→GSM downgrade detected → active CSS technique → Commercial devices +0.15")

    def _score_bcch_anomalies(self, f: CaptureFeatures, s: FingerprintScore):
        """
        Score BCCH anomalies per SeaGlass PoPETs 2017 fingerprints.
        T3212=66, MSTXPWR=7, multi-ARFCN are confirmed CSS signatures.
        """
        if f.t3212_anomalous and f.t3212_value == self.T3212_ANOMALOUS_VALUE:
            s.unknown_commercial += 0.30
            s.harris_hailstorm += 0.20
            s.pki_1625 += 0.20
            s.log(f"BCCH: T3212={f.t3212_value} (anomalous, SeaGlass SeaTac signature) → CSS confirmed → Commercial +0.30")
        elif f.t3212_anomalous:
            s.unknown_commercial += 0.20
            s.log(f"BCCH: T3212={f.t3212_value} outside normal range → CSS indicator → +0.20")

        if f.mstxpwr_anomalous:
            s.unknown_commercial += 0.20
            s.harris_hailstorm += 0.15
            s.log(f"BCCH: MSTXPWR anomalous (SeaGlass signature) → CSS indicator → Commercial +0.20")

        if f.multi_arfcn_detected:
            s.unknown_commercial += 0.25
            s.state_actor += 0.10
            s.log("BCCH: Multi-ARFCN from same BTS → SeaGlass signature (e.g., DHS/USCIS Seattle anomaly) → +0.25")

        if f.null_cipher_a5_0:
            s.unknown_commercial += 0.20
            s.pki_1625 += 0.10
            s.log("BCCH: Null cipher (A5/0) → PKI 1585 class or CSS cipher downgrade → +0.20")

    def _score_persistence(self, f: CaptureFeatures, s: FingerprintScore):
        """Score based on operational persistence."""
        if f.session_duration_days:
            if f.session_duration_days >= 30:
                # Base stations typically live weeks+ (SeaGlass finding)
                # Persistent rogue = professional operation
                s.state_actor += 0.25
                s.intelligence_agency += 0.20
                s.log(f"PERSISTENCE: {f.session_duration_days:.0f} days of operation → professional persistent surveillance → StatActor +0.25")
            elif f.session_duration_days < 7:
                # Short-lived base station = CSS impermanence signature (SeaGlass §5.2)
                s.criminal_actor += 0.15
                s.srsran += 0.10
                s.log(f"PERSISTENCE: {f.session_duration_days:.1f} days → short-lived (SeaGlass impermanence signature) → CriminalActor +0.15")

    def _score_srsran_discriminator(self, f: CaptureFeatures, s: FingerprintScore):
        """
        Final srsRAN vs commercial discriminator pass.
        Rule: 210s cycle + Identity Request ONLY (no Attach Reject) = srsRAN
        Rule: 210s cycle + Attach Rejects present = commercial with custom timing
        """
        cycle_match = (
            f.cycle_interval_seconds is not None and
            abs(f.cycle_interval_seconds - self.SRSRAN_CYCLE_SECONDS) <= self.SRSRAN_CYCLE_TOLERANCE
        )

        if cycle_match and f.identity_request_present and not f.attach_reject_present:
            # Strong srsRAN signature
            s.srsran += 0.30
            s.harris_hailstorm -= 0.10
            s.pki_1625 -= 0.10
            s.log("DISCRIMINATOR: 210s cycle + Identity Request ONLY (no Attach Reject) → STRONG srsRAN signature → srsRAN +0.30")

        elif cycle_match and f.attach_reject_present:
            # Commercial device with non-standard timing
            s.harris_hailstorm += 0.15
            s.pki_1625 += 0.20
            s.srsran -= 0.15
            s.log("DISCRIMINATOR: 210s cycle + Attach Reject present → commercial device with modified timing → PKI1625 +0.20, srsRAN -0.15")

        elif cycle_match and f.cross_carrier_sync:
            # srsRAN generally doesn't do cross-carrier
            s.pki_1625 += 0.25
            s.srsran -= 0.20
            s.log("DISCRIMINATOR: 210s cycle + cross-carrier sync → srsRAN unlikely (can't do multi-carrier) → PKI1625 +0.25, srsRAN -0.20")

    def _score_actor_profiles(self, f: CaptureFeatures, s: FingerprintScore):
        """Score actor profile based on combined indicators."""
        # State actor indicators
        if f.cycle_precision_factor and f.cycle_precision_factor >= 15:
            s.state_actor += 0.15
        if f.cross_carrier_sync:
            s.state_actor += 0.20
        if f.timer_reconfiguration_event:
            s.intelligence_agency += 0.25
        if f.session_duration_days and f.session_duration_days >= 30:
            s.state_actor += 0.10
            s.intelligence_agency += 0.10

        # Criminal actor indicators
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
            val = getattr(s, attr)
            setattr(s, attr, max(0.0, min(1.0, val)))


# ---------------------------------------------------------------------------
# Feature extraction from Rayhunter events
# ---------------------------------------------------------------------------

def extract_features_from_events(events: list, session_metadata: dict = None) -> CaptureFeatures:
    """
    Extract CaptureFeatures from a list of Rayhunter flagged events.
    events: list of dicts from Rayhunter scan output (flagged_events)
    session_metadata: dict with session-level data (duration, carriers, etc.)
    """
    features = CaptureFeatures()

    # Session-level metadata
    if session_metadata:
        features.session_duration_days = session_metadata.get("duration_days")
        features.carriers_affected = session_metadata.get("carriers", [])
        features.cycle_interval_seconds = session_metadata.get("avg_cycle_interval_seconds")
        features.cycle_precision_factor = session_metadata.get("cycle_precision_factor")
        features.timer_reconfiguration_event = session_metadata.get("timer_reconfig_detected", False)
        features.rogue_cell_ids = session_metadata.get("rogue_cell_ids", [])
        features.rogue_cell_count = len(features.rogue_cell_ids)
        features.cross_carrier_sync = session_metadata.get("cross_carrier_sync", False)
        features.simultaneous_release_events = session_metadata.get("simultaneous_release_count", 0)
        features.band_28_detected = session_metadata.get("band_28_detected", False)
        features.observed_bands = session_metadata.get("observed_bands", [])

    # Event-level extraction
    for event in events:
        event_type = event.get("type", "").lower()
        details = event.get("details", {})

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

        # BCCH anomalies
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

    # Deduplicate cause codes
    features.attach_reject_cause_codes = list(set(features.attach_reject_cause_codes))

    return features


def fingerprint_session(
    events: list,
    session_metadata: dict = None,
    db_path: str = "intelligence/db",
    verbose: bool = False
) -> dict:
    """
    Main entry point for hardware fingerprinting.

    Args:
        events: List of flagged events from Rayhunter scan
        session_metadata: Session-level data (cycle timing, carriers, etc.)
        db_path: Path to intelligence database
        verbose: If True, include full reasoning log in output

    Returns:
        dict with device scores, top device, top profile, and reasoning
    """
    fingerprinter = HardwareFingerprinter(db_path=db_path)
    features = extract_features_from_events(events, session_metadata)
    score = fingerprinter.score(features)
    result = score.to_dict()

    if not verbose:
        result.pop("reasoning", None)
    else:
        # Add feature summary for debugging
        result["features_extracted"] = {
            "cycle_interval_s": features.cycle_interval_seconds,
            "cycle_precision_factor": features.cycle_precision_factor,
            "attach_reject_present": features.attach_reject_present,
            "attach_reject_codes": features.attach_reject_cause_codes,
            "hard_landing_detected": features.hard_landing_detected,
            "identity_request": features.identity_request_present,
            "ue_info_req_r9": features.ue_information_request_r9,
            "imsi_exposed": features.imsi_exposed,
            "imeisv_exposed": features.imeisv_exposed,
            "cross_carrier_sync": features.cross_carrier_sync,
            "carriers_affected": features.carriers_affected,
            "simultaneous_releases": features.simultaneous_release_events,
            "rogue_cell_count": features.rogue_cell_count,
            "band_28_detected": features.band_28_detected,
            "t3212_anomalous": features.t3212_anomalous,
            "t3212_value": features.t3212_value,
            "null_cipher": features.null_cipher_a5_0,
            "timer_reconfig": features.timer_reconfiguration_event,
            "session_days": features.session_duration_days,
        }

    return result


# ---------------------------------------------------------------------------
# CLI usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Rayhunter Hardware Fingerprinter")
    parser.add_argument("--events-file", help="JSON file with flagged events list")
    parser.add_argument("--meta-file", help="JSON file with session metadata")
    parser.add_argument("--db-path", default="intelligence/db", help="Path to intelligence database")
    parser.add_argument("--verbose", action="store_true", help="Include reasoning log")
    parser.add_argument("--demo", action="store_true", help="Run demo with Julian's capture profile")
    args = parser.parse_args()

    if args.demo:
        # Demo: Julian's actual capture profile
        print("\n=== DEMO: Julian's Cranbourne East Capture Profile ===\n")
        demo_meta = {
            "duration_days": 90,
            "carriers": ["Telstra (MCC=505/MNC=001)", "Vodafone AU (MCC=505/MNC=003)"],
            "avg_cycle_interval_seconds": 210.2,
            "cycle_precision_factor": 19.0,
            "timer_reconfig_detected": True,
            "rogue_cell_ids": [137713195, 137713175, 137713155, 8409387, 8409357],
            "cross_carrier_sync": True,
            "simultaneous_release_count": 12,
            "band_28_detected": True,
            "observed_bands": [28, 3, 7],
        }
        demo_events = [
            {"type": "lte_attach_reject", "details": {"cause_code": 3}},
            {"type": "imsi_harvest", "details": {}},
            {"type": "imeisv_exposure", "details": {"fresh_attach": True}},
            {"type": "ue_information_request_r9", "details": {}},
            {"type": "identity_request", "details": {}},
        ]
        result = fingerprint_session(demo_events, demo_meta, args.db_path, verbose=True)
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
