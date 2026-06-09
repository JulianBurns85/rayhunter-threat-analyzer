"""
FleetDetectorModule — main.py integration
Slots into the rayhunter-threat-analyzer detector pipeline.

Runs after existing 57 detectors, consuming:
  - bladeRF capture files (via BladeRFBridge)
  - CASTNET node JSON observations
  - Manual signal dicts

Appends fleet contact findings to the existing report output.

Version: 1.0 | June 2026
"""

import os
import json
import logging
import glob
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from .fleet_signature_detector import FleetSignatureDetector, ObservedSignal, AlertLevel
from .bladerf_bridge import BladeRFBridge

logger = logging.getLogger(__name__)

# Default path — relative to analyzer root
DEFAULT_LIBRARY_DIR = os.path.join(
    os.path.dirname(__file__), "..", "intelligence"
)


class FleetDetectorModule:
    """
    Drop-in module for rayhunter-threat-analyzer main.py pipeline.

    Usage in main.py:
        from detectors.fleet_detector_module import FleetDetectorModule

        fleet = FleetDetectorModule(capture_dir=args.dir)
        fleet_findings = fleet.run()
        report.add_section("Fleet Contacts", fleet_findings)
    """

    def __init__(
        self,
        capture_dir: str,
        library_dir: str = DEFAULT_LIBRARY_DIR,
        location: tuple = None,
        min_confidence: float = 0.50,
        noise_floor_dbm: float = -100.0,
        castnet_obs_file: str = None
    ):
        self.capture_dir = Path(capture_dir)
        self.library_dir = library_dir
        self.location = location
        self.min_confidence = min_confidence
        self.castnet_obs_file = castnet_obs_file

        self.detector = FleetSignatureDetector(library_dir)
        self.bridge = BladeRFBridge(noise_floor_dbm=noise_floor_dbm)

        logger.info(
            f"FleetDetectorModule ready — "
            f"{len(self.detector.signatures)} base + "
            f"{len(self.detector.composite_signatures)} composite signatures"
        )

    # ─── MAIN ENTRY POINT ────────────────────────────────────────────

    def run(self) -> dict:
        """
        Run fleet detection across all available data sources.
        Returns a structured findings dict compatible with existing reporter.
        """
        all_signals = []
        sources_used = []

        # 1. bladeRF captures in the capture directory
        bladerf_signals, bladerf_sources = self._ingest_bladerf_captures()
        all_signals.extend(bladerf_signals)
        sources_used.extend(bladerf_sources)

        # 2. CASTNET observation JSON if provided
        if self.castnet_obs_file and Path(self.castnet_obs_file).exists():
            castnet_signals = self._ingest_castnet_observations(self.castnet_obs_file)
            all_signals.extend(castnet_signals)
            sources_used.append(f"CASTNET: {self.castnet_obs_file}")

        if not all_signals:
            logger.info("FleetDetector: no signals to analyse — no RF captures found")
            return self._empty_result(sources_used)

        logger.info(
            f"FleetDetector: analysing {len(all_signals)} signals "
            f"from {len(sources_used)} source(s)"
        )

        results = self.detector.analyze(
            all_signals,
            location=self.location,
            min_confidence=self.min_confidence
        )

        return self._format_findings(results, sources_used, len(all_signals))

    # ─── DATA INGESTION ───────────────────────────────────────────────

    def _ingest_bladerf_captures(self) -> tuple[list[ObservedSignal], list[str]]:
        """Scan capture directory for bladeRF files and parse them all."""
        signals = []
        sources = []

        if not self.capture_dir.exists():
            logger.warning(f"Capture dir not found: {self.capture_dir}")
            return signals, sources

        # SigMF captures
        for meta_file in self.capture_dir.rglob("*.sigmf-meta"):
            try:
                sigs = self.bridge.from_sigmf(str(meta_file))
                signals.extend(sigs)
                sources.append(f"SigMF: {meta_file.name}")
                logger.info(f"  SigMF {meta_file.name}: {len(sigs)} signals")
            except Exception as e:
                logger.warning(f"  SigMF parse failed {meta_file.name}: {e}")

        # bladeRF CSV scan exports
        for csv_file in self.capture_dir.rglob("*.csv"):
            if self._looks_like_spectrum_csv(csv_file):
                try:
                    sigs = self.bridge.from_bladerf_csv(str(csv_file))
                    signals.extend(sigs)
                    sources.append(f"CSV: {csv_file.name}")
                    logger.info(f"  CSV {csv_file.name}: {len(sigs)} signals")
                except Exception as e:
                    logger.warning(f"  CSV parse failed {csv_file.name}: {e}")

        # Raw IQ binary files — need freq/rate from filename convention
        for bin_file in self.capture_dir.rglob("*.bin"):
            parsed = self._parse_iq_filename(bin_file)
            if parsed:
                center_mhz, rate_mhz, datatype = parsed
                try:
                    sigs = self.bridge.from_raw_iq(
                        str(bin_file), center_mhz, rate_mhz, datatype
                    )
                    signals.extend(sigs)
                    sources.append(f"IQ: {bin_file.name}")
                    logger.info(f"  IQ {bin_file.name}: {len(sigs)} signals")
                except Exception as e:
                    logger.warning(f"  IQ parse failed {bin_file.name}: {e}")

        # sc16 / cs16 files (bladeRF native)
        for sc16_file in list(self.capture_dir.rglob("*.sc16q11")) + \
                         list(self.capture_dir.rglob("*.cs16")):
            parsed = self._parse_iq_filename(sc16_file)
            if parsed:
                center_mhz, rate_mhz, _ = parsed
                try:
                    sigs = self.bridge.from_raw_iq(
                        str(sc16_file), center_mhz, rate_mhz, "ci16_le"
                    )
                    signals.extend(sigs)
                    sources.append(f"SC16: {sc16_file.name}")
                except Exception as e:
                    logger.warning(f"  SC16 parse failed {sc16_file.name}: {e}")

        return signals, sources

    def _ingest_castnet_observations(self, obs_file: str) -> list[ObservedSignal]:
        """Load CASTNET node JSON observation file."""
        try:
            with open(obs_file) as f:
                obs_list = json.load(f)
            signals = self.bridge.from_manual(obs_list)
            logger.info(f"CASTNET: {len(signals)} observations from {obs_file}")
            return signals
        except Exception as e:
            logger.warning(f"CASTNET observations parse failed: {e}")
            return []

    def _looks_like_spectrum_csv(self, path: Path) -> bool:
        """Quick heuristic — does this CSV look like spectrum data?"""
        try:
            with open(path, "r", errors="ignore") as f:
                first_lines = [f.readline() for _ in range(3)]
            content = " ".join(first_lines).lower()
            keywords = ["freq", "power", "dbm", "hz", "rssi", "level", "scan"]
            return any(kw in content for kw in keywords)
        except Exception:
            return False

    def _parse_iq_filename(self, path: Path) -> Optional[tuple]:
        """
        Parse bladeRF IQ filename convention to extract parameters.

        Convention (use this when capturing):
          bladerf_{center_mhz}mhz_{rate_mhz}msps[_{datatype}].bin

        Examples:
          bladerf_700mhz_20msps.bin          → 700MHz, 20Msps, ci16_le
          bladerf_390mhz_5msps_ci16.bin      → 390MHz, 5Msps, ci16_le
          bladerf_2400mhz_40msps_cf32.bin    → 2400MHz, 40Msps, cf32_le
          capture_700_20.bin                 → 700MHz, 20Msps (positional)
        """
        name = path.stem.lower()
        parts = name.replace("-", "_").split("_")

        center_mhz = None
        rate_mhz = None
        datatype = "ci16_le"

        for part in parts:
            if part.endswith("mhz") and center_mhz is None:
                try:
                    center_mhz = float(part[:-3])
                except ValueError:
                    pass
            elif part.endswith("msps") or part.endswith("mhzsps"):
                try:
                    rate_mhz = float(part.replace("msps", "").replace("mhzsps", ""))
                except ValueError:
                    pass
            elif "cf32" in part:
                datatype = "cf32_le"
            elif "cu8" in part:
                datatype = "cu8"

        # Positional fallback — two numbers in filename
        if center_mhz is None or rate_mhz is None:
            nums = []
            for part in parts:
                try:
                    nums.append(float(part))
                except ValueError:
                    pass
            if len(nums) >= 2:
                center_mhz = nums[0] if nums[0] > 100 else nums[0] * 1000
                rate_mhz = nums[1]

        if center_mhz and rate_mhz:
            return center_mhz, rate_mhz, datatype

        logger.debug(
            f"Could not parse IQ params from filename: {path.name} — "
            f"rename to bladerf_{{freq}}mhz_{{rate}}msps.bin"
        )
        return None

    # ─── REPORT FORMATTING ────────────────────────────────────────────

    def _format_findings(self, results, sources_used, signal_count) -> dict:
        """
        Format results as a findings dict compatible with existing reporter.py
        """
        elevated = [r for r in results
                    if r.alert_level in (AlertLevel.WARNING, AlertLevel.HIGH, AlertLevel.FLAG)]

        findings = {
            "module": "FleetDetectorModule",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": sources_used,
            "signal_count": signal_count,
            "detection_count": len(results),
            "elevated_count": len(elevated),
            "detections": [],
            "summary_text": "",
            "forensic_flags": []
        }

        for r in results:
            det = {
                "id": r.signature_id,
                "label": r.label,
                "category": r.category,
                "subcategory": r.subcategory,
                "confidence": r.confidence,
                "confidence_pct": f"{r.confidence:.1%}",
                "alert_level": r.alert_level,
                "display_color": r.display_color,
                "map_icon": r.map_icon,
                "matched_signals": r.matched_signals,
                "missing_signals": r.missing_signals,
                "timestamp": r.timestamp.isoformat(),
                "location": {
                    "lat": r.location_lat,
                    "lon": r.location_lon
                } if r.location_lat else None,
                "requires_corroboration": r.requires_corroboration,
                "notes": r.notes,
                "forensic_note": r.forensic_note or None,
                "remote_id": {
                    "serial_number": r.remote_id.serial_number,
                    "operator_registration": r.remote_id.operator_registration,
                    "lat": r.remote_id.gps_latitude,
                    "lon": r.remote_id.gps_longitude,
                    "altitude_m": r.remote_id.altitude_m_agl,
                    "velocity_ms": r.remote_id.velocity_ms,
                } if r.remote_id else None
            }
            findings["detections"].append(det)

            if r.forensic_note:
                findings["forensic_flags"].append({
                    "id": r.signature_id,
                    "label": r.label,
                    "note": r.forensic_note,
                    "confidence": r.confidence
                })

        # Summary text for existing reporter
        if results:
            top = results[0]
            findings["summary_text"] = (
                f"Fleet detector: {len(results)} profile(s) matched "
                f"({len(elevated)} elevated). "
                f"Top: {top.label} @ {top.confidence:.1%}. "
                f"Forensic flags: {len(findings['forensic_flags'])}."
            )
        else:
            findings["summary_text"] = (
                f"Fleet detector: no profiles matched above "
                f"{self.min_confidence:.0%} threshold "
                f"({signal_count} signals analysed)."
            )

        return findings

    def _empty_result(self, sources_used) -> dict:
        return {
            "module": "FleetDetectorModule",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": sources_used,
            "signal_count": 0,
            "detection_count": 0,
            "elevated_count": 0,
            "detections": [],
            "summary_text": "Fleet detector: no RF capture files found in capture directory.",
            "forensic_flags": []
        }

    def format_report_section(self, findings: dict) -> str:
        """
        Format findings dict as a text report section.
        Compatible with existing reporter.py text output style.
        """
        lines = [
            "",
            "=" * 60,
            "FLEET SIGNATURE DETECTOR — RF CONTACT REPORT",
            f"Generated: {findings['timestamp']}",
            f"Sources:   {len(findings['sources'])} capture source(s)",
            f"Signals:   {findings['signal_count']} observed",
            f"Matched:   {findings['detection_count']} profiles",
            f"Elevated:  {findings['elevated_count']} alerts",
            "=" * 60,
        ]

        if not findings["detections"]:
            lines.append(findings["summary_text"])
            return "\n".join(lines)

        for det in findings["detections"]:
            marker = {
                "info":    "[ INFO ]",
                "flag":    "[ FLAG ]",
                "warning": "[  !!  ]",
                "high":    "[ HIGH ]"
            }.get(det["alert_level"], "[  ?  ]")

            lines.append(f"\n{marker} {det['label']}")
            lines.append(f"  Confidence: {det['confidence_pct']}")
            lines.append(f"  Category:   {det['category']} / {det['subcategory']}")

            if det.get("location"):
                loc = det["location"]
                lines.append(f"  Location:   {loc['lat']:.6f}, {loc['lon']:.6f}")

            if det.get("matched_signals"):
                matched_str = ", ".join(
                    m["spec"] if isinstance(m, dict) else str(m)
                    for m in det["matched_signals"]
                )
                lines.append(f"  Matched:    {matched_str}")

            if det.get("missing_signals"):
                lines.append(f"  Missing:    {', '.join(det['missing_signals'])}")

            if det.get("forensic_note"):
                lines.append(f"  FORENSIC:   {det['forensic_note'][:120]}")

            if det.get("requires_corroboration"):
                lines.append("  ** Requires corroborating evidence **")

            if det.get("remote_id"):
                rid = det["remote_id"]
                lines.append(
                    f"  Remote ID:  Serial={rid['serial_number']} "
                    f"Op={rid['operator_registration']} "
                    f"Alt={rid['altitude_m']}m"
                )

        if findings.get("forensic_flags"):
            lines.append("\n--- FORENSIC FLAGS FOR INVESTIGATION RECORD ---")
            for flag in findings["forensic_flags"]:
                lines.append(f"  [{flag['confidence']:.0%}] {flag['label']}")
                lines.append(f"         {flag['note'][:100]}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
