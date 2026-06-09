"""
FleetSignatureDetector — AU RF Signature Library
Passive detection of known Australian fleet, government, and infrastructure
RF profiles from BLE, LTE, TETRA, and other signals.

All detection is PASSIVE — no transmission. Sources: public procurement,
ACMA register, vendor documentation.

Version: 1.0 | June 2026
"""

import yaml
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    INFO    = "info"
    FLAG    = "flag"
    WARNING = "warning"
    HIGH    = "high"


class SignalType(str, Enum):
    TETRA       = "tetra"
    LTE         = "lte"
    LTE_M       = "lte_m"
    BLE         = "ble"
    WIFI        = "wifi"
    P25         = "p25"
    OCUSYNC3    = "ocusync3"
    ISM_915     = "ismsub_ghz"
    GSM         = "gsm"
    UHF_CB      = "uhf_cb"
    WIFI_NAN    = "wifi_nan"


@dataclass
class ObservedSignal:
    """A signal observed by the passive scanner."""
    signal_type: str
    freq_mhz: Optional[float] = None
    carrier: Optional[str] = None
    band: Optional[str] = None
    manufacturer_id: Optional[str] = None
    service_uuid: Optional[str] = None
    advertisement_interval_ms: Optional[float] = None
    rsrp_dbm: Optional[float] = None
    burst_duration_ms: Optional[float] = None
    burst_interval_s: Optional[float] = None
    payload_type: Optional[str] = None
    ssid: Optional[str] = None
    mac_address: Optional[str] = None
    separation_indicator: Optional[bool] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    raw_metadata: dict = field(default_factory=dict)


@dataclass
class RemoteIDPayload:
    """Decoded CASA Remote ID payload from drone broadcast."""
    serial_number: Optional[str] = None
    operator_registration: Optional[str] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    altitude_m_agl: Optional[float] = None
    velocity_ms: Optional[float] = None
    timestamp_utc: Optional[datetime] = None
    manufacturer_id: Optional[str] = None


@dataclass
class DetectionResult:
    """Result from matching observed signals against a signature profile."""
    signature_id: str
    label: str
    category: str
    subcategory: str
    confidence: float
    alert_level: str
    matched_signals: list
    missing_signals: list
    booster_signals: list
    display_color: str
    map_icon: str
    notes: str
    forensic_note: str
    timestamp: datetime
    location_lat: Optional[float]
    location_lon: Optional[float]
    remote_id: Optional[RemoteIDPayload] = None
    requires_corroboration: bool = False


class FleetSignatureDetector:
    """
    Loads the AU RF Signature Library YAML files and matches
    observed passive signals against known fleet profiles.
    """

    def __init__(self, library_dir: str):
        self.library_dir = Path(library_dir)
        self.signatures = {}
        self.composite_signatures = {}
        self._load_library()

    def _load_library(self):
        """Load all YAML intelligence files from the library directory."""
        yaml_files = list(self.library_dir.glob("au_*.yaml"))
        if not yaml_files:
            raise FileNotFoundError(
                f"No AU signature YAML files found in {self.library_dir}"
            )

        total = 0
        for f in yaml_files:
            try:
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                sigs = data.get("signatures", [])
                for sig in sigs:
                    sid = sig["id"]
                    if sig.get("composite") and sig.get("requires_all"):
                        self.composite_signatures[sid] = sig
                    else:
                        self.signatures[sid] = sig
                total += len(sigs)
                logger.info(f"Loaded {len(sigs)} signatures from {f.name}")
            except Exception as e:
                logger.error(f"Failed to load {f}: {e}")

        logger.info(
            f"Fleet library ready: {len(self.signatures)} base signatures, "
            f"{len(self.composite_signatures)} composite profiles "
            f"({total} total from {len(yaml_files)} files)"
        )

    def _match_signal(self, observed: ObservedSignal, sig_spec: dict) -> float:
        """
        Match a single observed signal against a signature signal spec.
        Returns a match score 0.0-1.0.
        """
        score = 0.0
        checks = 0

        stype = sig_spec.get("type", "")
        obs_type = observed.signal_type.lower()
        spec_type = stype.lower()

        # Handle compound type strings like wifi_or_ocusync, wifi_nan
        spec_types = [t.strip() for t in spec_type.replace("wifi_nan", "wifi").split("_or_")]
        if obs_type not in spec_types and not any(obs_type == t for t in spec_types):
            # Also allow wifi_nan to match wifi
            if not (spec_type == "wifi_nan" and obs_type == "wifi"):
                return 0.0

        checks += 1
        score += 1.0

        if sig_spec.get("carrier") and observed.carrier:
            checks += 1
            spec_carriers = [c.strip() for c in sig_spec["carrier"].split("_or_")]
            if any(c in observed.carrier.lower() for c in spec_carriers):
                score += 1.0

        if sig_spec.get("band") and observed.band:
            checks += 1
            if sig_spec["band"].upper() == observed.band.upper():
                score += 1.0

        if sig_spec.get("manufacturer_id") and observed.manufacturer_id:
            checks += 1
            if sig_spec["manufacturer_id"].lower() == observed.manufacturer_id.lower():
                score += 1.0

        if sig_spec.get("service_uuid") and observed.service_uuid:
            checks += 1
            if sig_spec["service_uuid"].lower() == observed.service_uuid.lower():
                score += 1.0

        if sig_spec.get("payload_type") and observed.payload_type:
            checks += 1
            if sig_spec["payload_type"].lower() in observed.payload_type.lower():
                score += 1.0

        if sig_spec.get("ssid_pattern") and observed.ssid:
            checks += 1
            patterns = sig_spec["ssid_pattern"].replace(" ", "").split("or")
            for p in patterns:
                prefix = p.strip().rstrip("*")
                if observed.ssid.startswith(prefix):
                    score += 1.0
                    break

        if sig_spec.get("separation_indicator") is True and observed.separation_indicator:
            checks += 1
            score += 1.0

        return score / checks if checks > 0 else 0.0

    def _evaluate_base_signature(
        self,
        sig: dict,
        observed_signals: list[ObservedSignal],
        location: tuple = None
    ) -> Optional[DetectionResult]:
        """
        Evaluate a single (non-composite) signature against observed signals.
        Returns DetectionResult if confidence exceeds threshold, else None.
        """
        required_specs = sig.get("signals", [])
        if not required_specs:
            return None

        matched = []
        missing = []
        total_weight = 0.0
        matched_weight = 0.0

        for spec in required_specs:
            weight = spec.get("confidence_weight", 1.0)
            total_weight += weight
            best_match = 0.0
            best_obs = None

            for obs in observed_signals:
                score = self._match_signal(obs, spec)
                if score > best_match:
                    best_match = score
                    best_obs = obs

            if best_match >= 0.7:
                matched.append({
                    "spec": spec.get("type"),
                    "score": round(best_match, 3),
                    "observed_type": best_obs.signal_type if best_obs else None
                })
                matched_weight += weight * best_match
            elif best_match >= 0.4:
                matched.append({
                    "spec": spec.get("type"),
                    "score": round(best_match, 3),
                    "observed_type": best_obs.signal_type if best_obs else None,
                    "partial": True
                })
                matched_weight += weight * best_match * 0.5
            else:
                missing.append(spec.get("type"))

        if total_weight == 0:
            return None

        match_ratio = matched_weight / total_weight
        confidence = sig.get("confidence_base", 0.70) * match_ratio

        # If any single spec scored perfectly, don't punish missing secondary specs too hard
        perfect_hits = sum(1 for m in matched if isinstance(m, dict) and m.get("score", 0) >= 1.0)
        if perfect_hits >= 1 and len(required_specs) > 1:
            confidence = max(confidence, sig.get("confidence_base", 0.70) * 0.55)

        if len(required_specs) == 1:
            threshold = 0.45
        elif sig.get("combination_required"):
            threshold = 0.65
        else:
            threshold = 0.48
        if confidence < threshold:
            return None

        return DetectionResult(
            signature_id=sig["id"],
            label=sig.get("label", sig["id"]),
            category=sig.get("category", "unknown"),
            subcategory=sig.get("subcategory", ""),
            confidence=round(min(confidence, 1.0), 4),
            alert_level=sig.get("alert_level", AlertLevel.INFO),
            matched_signals=matched,
            missing_signals=missing,
            booster_signals=[],
            display_color=sig.get("display_color", "gray"),
            map_icon=sig.get("map_icon", "unknown"),
            notes=sig.get("notes", ""),
            forensic_note=sig.get("forensic_note", ""),
            timestamp=datetime.utcnow(),
            location_lat=location[0] if location else None,
            location_lon=location[1] if location else None,
            requires_corroboration=sig.get("requires_corroboration", False)
        )

    def _evaluate_composite(
        self,
        comp: dict,
        base_results: dict[str, DetectionResult],
        observed_signals: list[ObservedSignal],
        location: tuple = None
    ) -> Optional[DetectionResult]:
        """
        Evaluate a composite signature — requires all component base
        signatures to have already matched.
        """
        required_ids = comp.get("requires_all", [])
        if not required_ids:
            return None
        if not all(rid in base_results for rid in required_ids):
            return None

        matched_confs = [base_results[rid].confidence for rid in required_ids]
        if not matched_confs:
            return None
        base_conf = min(matched_confs)
        composite_base = comp.get("confidence_base", 0.85)
        confidence = min(composite_base * (base_conf / 0.70), 1.0)

        boosters = []
        for booster in comp.get("optional_boosters", []):
            bid = booster.get("id")
            if bid and bid in base_results:
                boost = booster.get("confidence_boost", 0.05)
                confidence = min(confidence + boost, 1.0)
                boosters.append(bid)

        return DetectionResult(
            signature_id=comp["id"],
            label=comp.get("label", comp["id"]),
            category=comp.get("category", "unknown"),
            subcategory=comp.get("subcategory", ""),
            confidence=round(confidence, 4),
            alert_level=comp.get("alert_level", AlertLevel.INFO),
            matched_signals=[rid for rid in required_ids],
            missing_signals=[],
            booster_signals=boosters,
            display_color=comp.get("display_color", "gray"),
            map_icon=comp.get("map_icon", "unknown"),
            notes=comp.get("notes", comp.get("differentiator", "")),
            forensic_note=comp.get("forensic_note", ""),
            timestamp=datetime.utcnow(),
            location_lat=location[0] if location else None,
            location_lon=location[1] if location else None,
            requires_corroboration=comp.get("requires_corroboration", False)
        )

    def decode_remote_id(self, ble_signal: ObservedSignal) -> Optional[RemoteIDPayload]:
        """
        Decode ASTM F3411-22a Remote ID payload from a BLE advertisement.
        CASA-mandated broadcast — legally required public transmission.
        """
        if not ble_signal.payload_type:
            return None
        if "f3411" not in ble_signal.payload_type.lower() and \
           "remote_id" not in ble_signal.payload_type.lower():
            return None

        raw = ble_signal.raw_metadata.get("remote_id_payload", {})
        return RemoteIDPayload(
            serial_number=raw.get("serial_number"),
            operator_registration=raw.get("operator_id"),
            gps_latitude=raw.get("lat"),
            gps_longitude=raw.get("lon"),
            altitude_m_agl=raw.get("altitude_m"),
            velocity_ms=raw.get("velocity_ms"),
            timestamp_utc=raw.get("timestamp"),
            manufacturer_id=ble_signal.manufacturer_id
        )

    def analyze(
        self,
        observed_signals: list[ObservedSignal],
        location: tuple = None,
        min_confidence: float = 0.50
    ) -> list[DetectionResult]:
        """
        Main analysis entry point.

        Args:
            observed_signals: List of passively observed signals
            location: Optional (lat, lon) tuple
            min_confidence: Minimum confidence threshold (default 0.50)

        Returns:
            List of DetectionResults sorted by confidence descending
        """
        results = {}

        for sid, sig in self.signatures.items():
            result = self._evaluate_base_signature(sig, observed_signals, location)
            if result and result.confidence >= min_confidence:
                results[sid] = result

        for cid, comp in self.composite_signatures.items():
            result = self._evaluate_composite(comp, results, observed_signals, location)
            if result and result.confidence >= min_confidence:
                results[cid] = result

        for result in results.values():
            for obs in observed_signals:
                remote_id = self.decode_remote_id(obs)
                if remote_id:
                    result.remote_id = remote_id
                    break

        sorted_results = sorted(
            results.values(),
            key=lambda r: r.confidence,
            reverse=True
        )

        high_alerts = [r for r in sorted_results if r.alert_level in
                       (AlertLevel.WARNING, AlertLevel.HIGH)]
        if high_alerts:
            logger.warning(
                f"FLEET DETECTOR: {len(high_alerts)} elevated alert(s) — "
                f"{[r.label for r in high_alerts]}"
            )

        return sorted_results

    def format_report(self, results: list[DetectionResult]) -> str:
        """Format results as a human-readable report."""
        if not results:
            return "No fleet signatures detected above threshold."

        lines = [
            "=" * 60,
            "AU RF SIGNATURE LIBRARY — DETECTION REPORT",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            f"Profiles matched: {len(results)}",
            "=" * 60
        ]

        for r in results:
            alert_marker = {
                "info":    "[ INFO ]",
                "flag":    "[ FLAG ]",
                "warning": "[  !!  ]",
                "high":    "[ HIGH ]"
            }.get(r.alert_level, "[  ?  ]")

            lines.append(f"\n{alert_marker} {r.label}")
            lines.append(f"  ID:         {r.signature_id}")
            lines.append(f"  Category:   {r.category} / {r.subcategory}")
            lines.append(f"  Confidence: {r.confidence:.1%}")
            if r.location_lat:
                lines.append(f"  Location:   {r.location_lat:.6f}, {r.location_lon:.6f}")
            if r.matched_signals:
                lines.append(f"  Matched:    {r.matched_signals}")
            if r.missing_signals:
                lines.append(f"  Missing:    {r.missing_signals}")
            if r.booster_signals:
                lines.append(f"  Boosters:   {r.booster_signals}")
            if r.notes:
                lines.append(f"  Notes:      {r.notes[:120]}")
            if r.forensic_note:
                lines.append(f"  FORENSIC:   {r.forensic_note[:120]}")
            if r.requires_corroboration:
                lines.append("  ** Requires corroborating evidence before actioning **")
            if r.remote_id:
                rid = r.remote_id
                lines.append(f"  Remote ID:  Serial={rid.serial_number} "
                              f"Operator={rid.operator_registration} "
                              f"Pos=({rid.gps_latitude},{rid.gps_longitude})")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def to_castnet_json(self, results: list[DetectionResult]) -> str:
        """
        Serialize results as JSON for CASTNET aggregation server.
        Compatible with CASTNET v0.5 aggregation API.
        """
        payload = []
        for r in results:
            payload.append({
                "signature_id": r.signature_id,
                "label": r.label,
                "category": r.category,
                "subcategory": r.subcategory,
                "confidence": r.confidence,
                "alert_level": r.alert_level,
                "display_color": r.display_color,
                "map_icon": r.map_icon,
                "timestamp": r.timestamp.isoformat() + "Z",
                "location": {
                    "lat": r.location_lat,
                    "lon": r.location_lon
                } if r.location_lat else None,
                "matched_signals": [
                    m if isinstance(m, str) else
                    {k: v for k, v in m.items() if k != "observed"}
                    for m in r.matched_signals
                ],
                "missing_signals": r.missing_signals,
                "requires_corroboration": r.requires_corroboration,
                "forensic_note": r.forensic_note or None,
                "remote_id": {
                    "serial_number": r.remote_id.serial_number,
                    "operator_registration": r.remote_id.operator_registration,
                    "lat": r.remote_id.gps_latitude,
                    "lon": r.remote_id.gps_longitude,
                    "altitude_m": r.remote_id.altitude_m_agl,
                    "velocity_ms": r.remote_id.velocity_ms
                } if r.remote_id else None
            })
        return json.dumps(payload, indent=2)
