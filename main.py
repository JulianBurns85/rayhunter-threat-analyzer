# --- Python 3.14 asyncio fix for pyshark ---
import asyncio
try:
    import nest_asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    nest_asyncio.apply(loop)
except ImportError:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
# --- End asyncio fix ---

# #!/usr/bin/env python3
"""
Rayhunter Threat Analyzer v4.3
Analyses Rayhunter output files (NDJSON, PCAP, QMDL) for cellular
surveillance threats: IMSI catchers, rogue towers, null-cipher attacks,
metronomic timing signatures, cross-carrier anomalies, targeted paging,
CID rotation evasion, FlashCatch attacks, and authentication absence.

Produces terminal output, JSON report, and optional HTML report.

Usage:
    python main.py --file capture.ndjson
    python main.py --dir C:\\RH\\captures --output report.json
    python main.py --dir C:\\RH\\captures --html --manifest --verbose
    python main.py --dir C:\\RH\\captures --mnc 003  # Vodafone AU
    python main.py --dir D:\\MAY_2026_CAPTURES --gps-lat -38.1100 --gps-lon 145.2780
    python main.py --dir D:\\MAY_2026_CAPTURES --castnet-obs C:\\CASTNET\\obs.json

v4.1 changes:
    - FleetDetectorModule integrated: passive RF fleet/vehicle/tracker detection
    - BladeRFBridge: auto-ingests bladeRF SigMF, CSV, and raw IQ captures
    - CASTNET observation JSON ingestion via --castnet-obs
    - GPS location stamping via --gps-lat / --gps-lon
    - Fleet findings appended to terminal report and JSON output
    - AU RF Signature Library: 37 base + 5 composite profiles
      (emergency services, government/regulatory, infrastructure,
       commercial fleets, personal trackers, drones/UAV)

v3.5 changes:
    - PlatformFusionEngine: cross-detector correlation, 95% confidence
    - Hypothesis Defeater scoring
    - 25 contributing detectors

v3.3 changes:
    - PagingCycleDetector, FlashCatchDetector, AuthenticationAbsenceDetector
    - RRCReconfigurationPeriodicityDetector, MeasurementReportRateDetector

v3.2 changes:
    - PagingTargetDetector, CIDRotationDetector
    - corrected base_quantum_seconds, full rogue CID list

v2.3 changes:
    - NovelCidDetector, EncryptedTrafficRatioDetector
    - SessionOverlapCorrelator, CrossCarrierEvidencePatcher
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

# -- Parsers ------------------------------------------------------------------
from parsers.ndjson_parser import NdjsonParser
from parsers.pcap_parser    import PcapParser
from parsers.qmdl_parser    import QmdlParser

# -- Primary detectors --------------------------------------------------------
from detectors.identity_harvest  import IdentityHarvestDetector
from detectors.imsi_harvest_chain_sequencer import IMSIHarvestChainSequencer
from detectors.dual_device_temporal_segregator import DualDeviceTemporalSegregator
from detectors.cross_carrier_timer_correlator import CrossCarrierTimerCorrelator
from detectors.regulatory_escalation_scorer import RegulatoryEscalationScorer
from detectors.behavioral_rhythm_fingerprinter import BehavioralRhythmFingerprinter
from detectors.jitter_dna_tracker import JitterDNATracker
from detectors.cipher_downgrade  import CipherDowngradeDetector
from detectors.rogue_tower       import RogueTowerDetector
from detectors.handover_inject   import HandoverInjectDetector
from detectors.proximity_track   import ProximityTrackDetector
from detectors.paging_anomaly    import PagingAnomalyDetector
from detectors.earfcn_anomaly    import EarfcnAnomalyDetector

# -- Fleet / RF Signature Detector (AU) --------------------------------------
try:
    from detectors.fleet_detector_module import FleetDetectorModule
    _HAS_FLEET = True
except ImportError:
    _HAS_FLEET = False
    print("[WARN] detectors/fleet_detector_module.py not found ? Fleet Detector disabled.")

# -- RRC periodicity ----------------------------------------------------------
try:
    from detectors.rrc_periodicity import RRCPeriodicityDetector
    _HAS_RRC = True
except ImportError:
    _HAS_RRC = False
    print("[WARN] detectors/rrc_periodicity.py not found ? RRC periodicity disabled.")

# -- v2.3 detectors -----------------------------------------------------------
try:
    from detectors.novel_cid_detector import NovelCidDetector
    _HAS_NOVEL_CID = True
except ImportError:
    _HAS_NOVEL_CID = False
    print("[WARN] detectors/novel_cid_detector.py not found ? Novel CID disabled.")

try:
    from detectors.encrypted_traffic_ratio_detector import EncryptedTrafficRatioDetector
    _HAS_ENCRYPTED_RATIO = True
except ImportError:
    _HAS_ENCRYPTED_RATIO = False
    print("[WARN] detectors/encrypted_traffic_ratio_detector.py not found ? Encrypted Ratio disabled.")

# -- v3.2 detectors -----------------------------------------------------------
try:
    from detectors.paging_target import PagingTargetDetector
    _HAS_PAGING_TARGET = True
except ImportError:
    _HAS_PAGING_TARGET = False
    print("[WARN] detectors/paging_target.py not found ? Paging Target disabled.")

try:
    from detectors.cid_rotation import CIDRotationDetector
    _HAS_CID_ROTATION = True
except ImportError:
    _HAS_CID_ROTATION = False
    print("[WARN] detectors/cid_rotation.py not found ? CID Rotation disabled.")

# -- v3.3 detectors -----------------------------------------------------------
try:
    from detectors.paging_cycle import PagingCycleDetector
    _HAS_PAGING_CYCLE = True
except ImportError:
    _HAS_PAGING_CYCLE = False
    print("[WARN] detectors/paging_cycle.py not found ? Paging Cycle disabled.")

try:
    from detectors.flash_catch import FlashCatchDetector
    _HAS_FLASH_CATCH = True
except ImportError:
    _HAS_FLASH_CATCH = False
    print("[WARN] detectors/flash_catch.py not found ? FlashCatch disabled.")

try:
    from detectors.auth_absence import AuthenticationAbsenceDetector
    _HAS_AUTH_ABSENCE = True
except ImportError:
    _HAS_AUTH_ABSENCE = False
    print("[WARN] detectors/auth_absence.py not found ? Auth Absence disabled.")

try:
    from detectors.rrc_reconfig_periodicity import RRCReconfigurationPeriodicityDetector
    _HAS_RRC_RECONFIG = True
except ImportError:
    _HAS_RRC_RECONFIG = False
    print("[WARN] detectors/rrc_reconfig_periodicity.py not found ? RRC Reconfig Periodicity disabled.")

try:
    from detectors.measurement_report_rate import MeasurementReportRateDetector
    _HAS_MEAS_RATE = True
except ImportError:
    _HAS_MEAS_RATE = False
    print("[WARN] detectors/measurement_report_rate.py not found ? Measurement Report Rate disabled.")

# -- v3.4 detectors -----------------------------------------------------------
try:
    from detectors.operator_rhythm import OperatorRhythmProfiler
    _HAS_OPERATOR_RHYTHM = True
except ImportError:
    _HAS_OPERATOR_RHYTHM = False
    print("[WARN] detectors/operator_rhythm.py not found - Operator Rhythm disabled.")

try:
    from detectors.wallet_inspector import WalletInspectorDetector
    _HAS_WALLET_INSPECTOR = True
except ImportError:
    _HAS_WALLET_INSPECTOR = False
    print("[WARN] detectors/wallet_inspector.py not found - Wallet Inspector disabled.")

try:
    from detectors.jitter_profiler import RRCJitterProfiler
    _HAS_JITTER_PROFILER = True
except ImportError:
    _HAS_JITTER_PROFILER = False
    print("[WARN] detectors/jitter_profiler.py not found - Jitter Profiler disabled.")

try:
    from detectors.neighbour_list_auditor import NeighbourListAuditor
    _HAS_NEIGHBOUR_AUDITOR = True
except ImportError:
    _HAS_NEIGHBOUR_AUDITOR = False
    print("[WARN] detectors/neighbour_list_auditor.py not found - Neighbour Auditor disabled.")

# -- v3.5 detectors -----------------------------------------------------------
try:
    from detectors.regulatory_correlator import RegulatoryEventCorrelator
    _HAS_REG_CORRELATOR = True
except ImportError:
    _HAS_REG_CORRELATOR = False

try:
    from detectors.attack_intensity_scorer import AttackIntensityScorer
    _HAS_INTENSITY = True
except ImportError:
    _HAS_INTENSITY = False

try:
    from detectors.persistence_tracker import CrossSessionPersistenceTracker
    _HAS_PERSISTENCE = True
except ImportError:
    _HAS_PERSISTENCE = False

try:
    from detectors.crnti_profiler import CRNTITargetProfiler
    _HAS_CRNTI = True
except ImportError:
    _HAS_CRNTI = False

try:
    from detectors.kml_exporter import KMLExporter
    _HAS_KML = True
except ImportError:
    _HAS_KML = False

try:
    from detectors.silent_period_detector import SilentPeriodDetector
    _HAS_SILENT = True
except ImportError:
    _HAS_SILENT = False

try:
    from detectors.cross_carrier_sync_scorer import CrossCarrierSyncScorer
    _HAS_CC_SYNC = True
except ImportError:
    _HAS_CC_SYNC = False

try:
    from detectors.protocol_sequence_validator import ProtocolSequenceValidator
    _HAS_PROTO_SEQ = True
except ImportError:
    _HAS_PROTO_SEQ = False

try:
    from detectors.frequency_hopping_detector import FrequencyHoppingDetector
    _HAS_FREQ_HOP = True
except ImportError:
    _HAS_FREQ_HOP = False

try:
    from detectors.measurement_report_suppression import MeasurementReportSuppressionDetector
    _HAS_MEAS_SUPPRESS = True
except ImportError:
    _HAS_MEAS_SUPPRESS = False

try:
    from detectors.nas_entropy_scorer import NASEntropyScorer
    _HAS_ENTROPY = True
except ImportError:
    _HAS_ENTROPY = False

try:
    from detectors.baseline_deviation_scorer import BaselineDeviationScorer
    _HAS_BASELINE = True
except ImportError:
    _HAS_BASELINE = False

try:
    from detectors.intercell_correlation_detector import InterCellCorrelationDetector
    _HAS_INTERCELL = True
except ImportError:
    _HAS_INTERCELL = False

try:
    from detectors.paging_volume_anomaly import PagingVolumeAnomalyDetector
    _HAS_PAGING_VOL = True
except ImportError:
    _HAS_PAGING_VOL = False

try:
    from detectors.rsrp_consistency_scorer import RSRPConsistencyScorer
    _HAS_RSRP = True
except ImportError:
    _HAS_RSRP = False

try:
    from detectors.attach_detach_analyser import AttachDetachCycleAnalyser
    _HAS_ATTACH = True
except ImportError:
    _HAS_ATTACH = False

# -- v3.5 Tier 2 detectors ---------------------------------------------------
try:
    from detectors.tucker_taxonomy_scorer import TuckerTaxonomyScorer
    _HAS_TUCKER = True
except ImportError:
    _HAS_TUCKER = False

try:
    from detectors.dual_unit_triangulator import DualUnitTriangulator
    _HAS_DUAL_TA = True
except ImportError:
    _HAS_DUAL_TA = False

try:
    from detectors.temporal_fingerprint_evolution import TemporalFingerprintEvolutionTracker
    _HAS_TEMP_FP = True
except ImportError:
    _HAS_TEMP_FP = False

try:
    from detectors.eea0_session_analyser import EEA0SessionDurationAnalyser
    _HAS_EEA0_SESSION = True
except ImportError:
    _HAS_EEA0_SESSION = False

try:
    from detectors.cell_reselection_analyser import CellReselectionManipulationDetector
    _HAS_RESEL = True
except ImportError:
    _HAS_RESEL = False

try:
    from detectors.nas_timer_anomaly import NASTimerAnomalyDetector
    _HAS_NAS_TIMER = True
except ImportError:
    _HAS_NAS_TIMER = False

try:
    from detectors.attack_campaign_segmenter import AttackCampaignSegmenter
    _HAS_CAMPAIGN = True
except ImportError:
    _HAS_CAMPAIGN = False

try:
    from detectors.cipher_negotiation_analyser import CipherNegotiationSequenceAnalyser
    _HAS_CIPHER_NEG = True
except ImportError:
    _HAS_CIPHER_NEG = False

try:
    from detectors.multi_carrier_ta_comparator import MultiCarrierTAComparator
    _HAS_MULTI_TA = True
except ImportError:
    _HAS_MULTI_TA = False

try:
    from detectors.operational_profile_synthesiser import OperationalProfileSynthesiser
    _HAS_OP_PROFILE = True
except ImportError:
    _HAS_OP_PROFILE = False

# -- Post-processing ----------------------------------------------------------
from detectors.heuristic_scorer import HeuristicScorerDetector
from detectors.cfo_drift_analyser import CFODriftAnalyser
from detectors.beacon_periodicity_scorer_v2 import BeaconPeriodicityScorerV2
from detectors.simultaneous_cid_discriminator import SimultaneousCIDDiscriminator
from detectors.hardware_attribution_engine_v2 import HardwareAttributionEngineV2

# -- Intelligence / reporting -------------------------------------------------
from intelligence.hardware_fingerprint import HardwareFingerprinter
from rf_signature_lookup import rf_lib
from reporter import ThreatReporter
import config_loader

BANNER = r"""
+---------------------------------------------------------------+
?  RAYHUNTER THREAT ANALYZER v4.3                               ?
?  Cellular Surveillance Detection & Forensic Analysis         ?
?  Targets: NDJSON ? PCAP ? QMDL ? bladeRF IQ/SigMF/CSV       ?
?  10-Heuristic Framework + YAICD + AU Fleet RF Signatures     ?
+---------------------------------------------------------------+
"""

SKIP_DIRS = {
    "windows", "system32", "syswow64", "winsxs",
    "program files", "program files (x86)", "programdata",
    "appdata", "packages", "windowsapps", "$recycle.bin",
    "system volume information", "recovery", "boot",
    "perflogs", "msocache", "intel", "amd", "nvidia",
}

# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------
def collect_files(paths: List[str], directory: str) -> Dict[str, List[str]]:
    files: Dict[str, List[str]] = {"ndjson": [], "pcap": [], "qmdl": []}
    all_paths = list(paths or [])
    if directory:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"[ERROR] Directory not found: {directory}")
            sys.exit(1)
        print(f"  Scanning: {directory}")
        for ext in ("*.ndjson", "*.pcap", "*.pcapng", "*.qmdl", "*.bin"):
            for p in dir_path.rglob(ext):
                try:
                    parts_lower = {part.lower() for part in p.parts}
                    if parts_lower & SKIP_DIRS:
                        continue
                    all_paths.append(str(p))
                except (PermissionError, OSError):
                    continue
    for path in all_paths:
        p = Path(path)
        if not p.exists():
            print(f"[WARN] File not found, skipping: {path}")
            continue
        ext = p.suffix.lower()
        if ext == ".ndjson":
            files["ndjson"].append(str(p))
        elif ext in (".pcap", ".pcapng"):
            files["pcap"].append(str(p))
        elif ext in (".qmdl", ".bin"):
            files["qmdl"].append(str(p))
        else:
            print(f"[WARN] Unknown extension for {p.name}, skipping.")

    # --- SHA-256 deduplication ---
    import hashlib as _hashlib
    seen_hashes: set = set()
    deduped: dict = {"ndjson": [], "pcap": [], "qmdl": []}
    dropped = 0
    for ftype, flist in files.items():
        for fpath in flist:
            try:
                h = _hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                if h in seen_hashes:
                    dropped += 1
                    continue
                seen_hashes.add(h)
                deduped[ftype].append(fpath)
            except (OSError, PermissionError):
                deduped[ftype].append(fpath)
    if dropped:
        print(f"  [DEDUP] {dropped} duplicate file(s) removed by SHA-256 hash check.")
    return deduped

# ---------------------------------------------------------------------------
# Session grouping
# ---------------------------------------------------------------------------
def group_events_by_session(all_events: list) -> dict:
    sessions: dict = defaultdict(list)
    for evt in all_events:
        sid = (evt.get("session_id") or evt.get("source", "unknown"))
        if "/" in str(sid) or "\\" in str(sid):
            sid = Path(sid).stem
        if "." in str(sid):
            sid = str(sid).rsplit(".", 1)[0]
        sessions[sid].append(evt)
    return dict(sessions)

# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------
def run_analysis(files: Dict[str, List[str]], cfg: dict, verbose: bool) -> dict:
    all_events: list = []

    parsers = [
        ("NDJSON", NdjsonParser(cfg), files["ndjson"]),
        ("PCAP",   PcapParser(cfg),   files["pcap"]),
        ("QMDL",   QmdlParser(cfg),   files["qmdl"]),
    ]
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _parse_one(label, parser, f):
        try:
            events = parser.parse(f)
            return (f, label, events, None)
        except Exception as exc:
            return (f, label, [], exc)

    for label, parser, flist in parsers:
        if label == "QMDL" and len(flist) > 4:
            workers = min(4, len(flist))
            print(f"  [PARALLEL] QMDL: {len(flist)} files, {workers} workers")
            futures = {}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for f in flist:
                    fut = pool.submit(_parse_one, label, parser, f)
                    futures[fut] = f
                for fut in as_completed(futures):
                    f, lbl, events, exc = fut.result()
                    if exc:
                        print(f"  [WARN] Parse error in {Path(f).name}: {exc}")
                    else:
                        print(f"  -> {len(events):,} events from {Path(f).name}")
                        all_events.extend(events)
        else:
            for f in flist:
                if verbose:
                    print(f"  [{label}] Parsing {f}")
                try:
                    events = parser.parse(f)
                    print(f"  -> {len(events):,} events from {Path(f).name}")
                    all_events.extend(events)
                except Exception as exc:
                    print(f"  [WARN] Parse error in {Path(f).name}: {exc}")

    if not all_events:
        print("\n[WARN] No events extracted. Check file formats and paths.")
        return {
            "events": [], "findings": [], "hardware": [],
            "heuristics": None, "sessions": {}
        }

    print(f"\n  Total events: {len(all_events):,}")

    sessions = group_events_by_session(all_events)
    if verbose:
        print(f"  [SESSION] {len(sessions)} session(s): "
              f"{', '.join(sorted(sessions.keys()))}")

    # -- Build detector list --------------------------------------------------
    primary_detectors = [
        IdentityHarvestDetector(cfg),
        IMSIHarvestChainSequencer(cfg),
        DualDeviceTemporalSegregator(cfg),
        CrossCarrierTimerCorrelator(cfg),
        RegulatoryEscalationScorer(cfg),
        BehavioralRhythmFingerprinter(cfg),
        JitterDNATracker(cfg),
        CipherDowngradeDetector(cfg),
        RogueTowerDetector(cfg),
        HandoverInjectDetector(cfg),
        ProximityTrackDetector(cfg),
        PagingAnomalyDetector(cfg),
        EarfcnAnomalyDetector(cfg),
    ]

    if _HAS_RRC:             primary_detectors.append(RRCPeriodicityDetector(cfg))
    if _HAS_NOVEL_CID:       primary_detectors.append(NovelCidDetector(cfg))
    if _HAS_ENCRYPTED_RATIO: primary_detectors.append(EncryptedTrafficRatioDetector(cfg))
    if _HAS_PAGING_TARGET:   primary_detectors.append(PagingTargetDetector(cfg))
    if _HAS_CID_ROTATION:    primary_detectors.append(CIDRotationDetector(cfg))
    if _HAS_PAGING_CYCLE:    primary_detectors.append(PagingCycleDetector(cfg))
    if _HAS_FLASH_CATCH:     primary_detectors.append(FlashCatchDetector(cfg))
    if _HAS_AUTH_ABSENCE:    primary_detectors.append(AuthenticationAbsenceDetector(cfg))
    if _HAS_RRC_RECONFIG:    primary_detectors.append(RRCReconfigurationPeriodicityDetector(cfg))
    if _HAS_MEAS_RATE:       primary_detectors.append(MeasurementReportRateDetector(cfg))
    if _HAS_OPERATOR_RHYTHM:    primary_detectors.append(OperatorRhythmProfiler(cfg))
    if _HAS_WALLET_INSPECTOR:   primary_detectors.append(WalletInspectorDetector(cfg))
    if _HAS_JITTER_PROFILER:    primary_detectors.append(RRCJitterProfiler(cfg))
    if _HAS_NEIGHBOUR_AUDITOR:  primary_detectors.append(NeighbourListAuditor(cfg))
    if _HAS_REG_CORRELATOR:     primary_detectors.append(RegulatoryEventCorrelator(cfg))
    if _HAS_INTENSITY:          primary_detectors.append(AttackIntensityScorer(cfg))
    if _HAS_PERSISTENCE:        primary_detectors.append(CrossSessionPersistenceTracker(cfg))
    if _HAS_CRNTI:              primary_detectors.append(CRNTITargetProfiler(cfg))
    if _HAS_KML:                primary_detectors.append(KMLExporter(cfg))
    if _HAS_SILENT:             primary_detectors.append(SilentPeriodDetector(cfg))
    if _HAS_CC_SYNC:            primary_detectors.append(CrossCarrierSyncScorer(cfg))
    if _HAS_PROTO_SEQ:          primary_detectors.append(ProtocolSequenceValidator(cfg))
    if _HAS_FREQ_HOP:           primary_detectors.append(FrequencyHoppingDetector(cfg))
    if _HAS_MEAS_SUPPRESS:      primary_detectors.append(MeasurementReportSuppressionDetector(cfg))
    if _HAS_ENTROPY:            primary_detectors.append(NASEntropyScorer(cfg))
    if _HAS_BASELINE:           primary_detectors.append(BaselineDeviationScorer(cfg))
    if _HAS_INTERCELL:          primary_detectors.append(InterCellCorrelationDetector(cfg))
    if _HAS_PAGING_VOL:         primary_detectors.append(PagingVolumeAnomalyDetector(cfg))
    if _HAS_RSRP:               primary_detectors.append(RSRPConsistencyScorer(cfg))
    if _HAS_ATTACH:             primary_detectors.append(AttachDetachCycleAnalyser(cfg))
    if _HAS_TUCKER:             primary_detectors.append(TuckerTaxonomyScorer(cfg))
    if _HAS_DUAL_TA:            primary_detectors.append(DualUnitTriangulator(cfg))
    if _HAS_TEMP_FP:            primary_detectors.append(TemporalFingerprintEvolutionTracker(cfg))
    if _HAS_EEA0_SESSION:       primary_detectors.append(EEA0SessionDurationAnalyser(cfg))
    if _HAS_RESEL:              primary_detectors.append(CellReselectionManipulationDetector(cfg))
    if _HAS_NAS_TIMER:          primary_detectors.append(NASTimerAnomalyDetector(cfg))
    if _HAS_CAMPAIGN:           primary_detectors.append(AttackCampaignSegmenter(cfg))
    if _HAS_CIPHER_NEG:         primary_detectors.append(CipherNegotiationSequenceAnalyser(cfg))
    if _HAS_MULTI_TA:           primary_detectors.append(MultiCarrierTAComparator(cfg))
    if _HAS_OP_PROFILE:         primary_detectors.append(OperationalProfileSynthesiser(cfg))
    primary_detectors.append(CFODriftAnalyser(cfg))
    primary_detectors.append(BeaconPeriodicityScorerV2(cfg))
    primary_detectors.append(SimultaneousCIDDiscriminator(cfg))
    primary_detectors.append(HardwareAttributionEngineV2(cfg))

    all_findings: list = []
    for detector in primary_detectors:
        if verbose:
            print(f"  [DETECT] Running {detector.name}...")
        try:
            findings = detector.analyze(all_events)
            if findings:
                print(f"  -> {len(findings)} finding(s): {detector.name}")
            all_findings.extend(findings)
        except Exception as exc:
            print(f"  [WARN] {detector.name} error: {exc}")

    # -- Hardware fingerprinting ----------------------------------------------
    try:
        fp = HardwareFingerprinter(
            cfg.get("intelligence", {}).get("db_path", "intelligence/db"), cfg=cfg,
        )
        fingerprints = fp.analyze(all_events, all_findings)
        if fingerprints:
            print(f"  [HWFP] {len(fingerprints)} hardware candidate(s) identified")
    except Exception as exc:
        print(f"  [WARN] HardwareFingerprinter error: {exc}")
        fingerprints = []

    # -- Heuristic scorer -----------------------------------------------------
    print()
    print("  Running 10-Heuristic IMSI Catcher Detection Framework...")
    try:
        hscorer = HeuristicScorerDetector(cfg)
        heuristic_result = hscorer.analyze(all_events, all_findings)
        print(f"  [HEURISTIC] {heuristic_result.summary}")
        if verbose:
            for h in heuristic_result.heuristics:
                icon = {
                    "CONFIRMED":      "[+]",
                    "PARTIAL":        "[~]",
                    "NOT_DETECTED":   "[ ]",
                    "NOT_APPLICABLE": "[N/A]"
                }.get(h.status, "[?]")
                print(f"    {icon} {h.heuristic_id} {h.label}: {h.status}")
    except Exception as exc:
        print(f"  [WARN] HeuristicScorerDetector error: {exc}")
        heuristic_result = None

    return {
        "events":     all_events,
        "findings":   all_findings,
        "hardware":   fingerprints,
        "heuristics": heuristic_result,
        "sessions":   sessions,
    }

# ---------------------------------------------------------------------------
# GPS location helper
# ---------------------------------------------------------------------------
def _get_location(args) -> tuple:
    """Return (lat, lon) tuple from CLI args, or None if not provided."""
    lat = getattr(args, "gps_lat", None)
    lon = getattr(args, "gps_lon", None)
    if lat is not None and lon is not None:
        return (lat, lon)
    return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print(BANNER)

    ap = argparse.ArgumentParser(description="Rayhunter Threat Analyzer v4.3")
    ap.add_argument("--file", "-f", action="append", metavar="FILE")
    ap.add_argument("--dir",  "-d", metavar="DIR")
    ap.add_argument("--output", "-o", metavar="FILE")
    ap.add_argument("--format", choices=["terminal", "json", "both"], default="both")
    ap.add_argument("--config", "-c", metavar="FILE", default="config.yaml")
    ap.add_argument("--mcc", type=str)
    ap.add_argument("--mnc", type=str)
    ap.add_argument("--no-opencellid", action="store_true")
    ap.add_argument("--manifest", action="store_true")
    ap.add_argument("--html", action="store_true")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    # -- Fleet detector args --------------------------------------------------
    ap.add_argument(
        "--castnet-obs", default=None, metavar="FILE",
        help="Path to CASTNET node observations JSON (from Android node)"
    )
    ap.add_argument(
        "--gps-lat", type=float, default=None, metavar="LAT",
        help="GPS latitude for location-stamped fleet detections"
    )
    ap.add_argument(
        "--gps-lon", type=float, default=None, metavar="LON",
        help="GPS longitude for location-stamped fleet detections"
    )
    ap.add_argument(
        "--fleet-min-confidence", type=float, default=0.50, metavar="CONF",
        help="Minimum confidence threshold for fleet detections (default: 0.50)"
    )
    ap.add_argument(
        "--no-fleet", action="store_true",
        help="Disable fleet RF signature detector for this run"
    )
    args = ap.parse_args()

    if not args.file and not args.dir:
        ap.print_help()
        sys.exit(1)

    cfg = config_loader.load(args.config)
    if args.mcc:           cfg["network"]["mcc"]        = args.mcc
    if args.mnc:           cfg["network"]["mnc"]        = args.mnc
    if args.no_opencellid: cfg["opencellid"]["enabled"] = False

    # -- Status block ---------------------------------------------------------
    location = _get_location(args)

    print(f"  Network:    MCC={cfg['network']['mcc']} MNC={cfg['network']['mnc']}")
    print(f"  OpenCelliD: {'enabled' if cfg['opencellid']['enabled'] else 'OFFLINE'}")
    print(f"  RRC Detector:                {'enabled (210.2s + 610.6s)' if _HAS_RRC else 'MISSING'}")
    print(f"  Novel CID Detector:          {'enabled' if _HAS_NOVEL_CID else 'MISSING'}")
    print(f"  Encrypted Ratio Detector:    {'enabled' if _HAS_ENCRYPTED_RATIO else 'MISSING'}")
    print(f"  Paging Target Detector:      {'enabled' if _HAS_PAGING_TARGET else 'MISSING'}")
    print(f"  CID Rotation Detector:       {'enabled' if _HAS_CID_ROTATION else 'MISSING'}")
    print(f"  Paging Cycle Detector:       {'enabled' if _HAS_PAGING_CYCLE else 'MISSING'}")
    print(f"  FlashCatch Detector:         {'enabled' if _HAS_FLASH_CATCH else 'MISSING'}")
    print(f"  Auth Absence Detector:       {'enabled' if _HAS_AUTH_ABSENCE else 'MISSING'}")
    print(f"  RRC Reconfig Periodicity:    {'enabled' if _HAS_RRC_RECONFIG else 'MISSING'}")
    print(f"  Measurement Report Rate:     {'enabled' if _HAS_MEAS_RATE else 'MISSING'}")
    fleet_status = (
        "DISABLED (--no-fleet)" if args.no_fleet else
        "enabled" if _HAS_FLEET else
        "MISSING"
    )
    print(f"  Fleet RF Signature Detector: {fleet_status}")
    if location:
        print(f"  GPS Location:                {location[0]:.4f}, {location[1]:.4f}")
    if args.castnet_obs:
        print(f"  CASTNET obs:                 {args.castnet_obs}")
    print()

    files = collect_files(args.file or [], args.dir or "")
    total = sum(len(v) for v in files.values())
    if total == 0:
        print("[ERROR] No valid files found.")
        sys.exit(1)

    print(f"  Files queued: "
          f"{len(files['ndjson'])} NDJSON | "
          f"{len(files['pcap'])} PCAP | "
          f"{len(files['qmdl'])} QMDL\n")

    print("##" + "-" * 62)
    print("## PHASE 1 -- PARSING & DETECTION")
    print("##" + "-" * 62)

    start   = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    print()
    print("-" * 64)
    print("PHASE 2 -- REPORTING")
    print("-" * 64)

    reporter = ThreatReporter(cfg)
    report   = reporter.build_report(results, elapsed)

    # -- Platform Fusion Engine -----------------------------------------------
    try:
        from detectors.fusion_engine import PlatformFusionEngine
        fusion = PlatformFusionEngine()
        platforms = fusion.ingest_findings(results.get("findings", []))
        report["platform_fusion"] = {
            pid: {
                "confidence":            p.confidence,
                "hypothesis_scores":     p.hypothesis_scores,
                "persistence_days":      p.persistence_days,
                "handover_inject_count": p.handover_inject_count,
                "imsi_harvest_count":    p.imsi_harvest_count,
                "prose_tracking":        p.prose_tracking,
                "flashcatch":            p.flashcatch,
                "wallet_inspector":      p.wallet_inspector,
                "regulatory_response":   p.regulatory_response,
            }
            for pid, p in platforms.items()
        }
        print()
        print(fusion.format_summary())
    except Exception as exc:
        print(f"  [WARN] PlatformFusionEngine error: {exc}")

    # -- Fleet RF Signature Detector ------------------------------------------
    fleet_findings = None
    if _HAS_FLEET and not args.no_fleet:
        print()
        print("-" * 64)
        print("PHASE 2b -- FLEET RF SIGNATURE DETECTION")
        print("-" * 64)
        try:
            fleet = FleetDetectorModule(
                capture_dir=args.dir or ".",
                location=location,
                min_confidence=args.fleet_min_confidence,
                castnet_obs_file=args.castnet_obs,
            )
            fleet_findings = fleet.run()
            fleet_report_section = fleet.format_report_section(fleet_findings)
            print(fleet_report_section)
            report["fleet_detections"] = fleet_findings

            # Promote forensic flags to top-level report for chain-of-custody
            if fleet_findings.get("forensic_flags"):
                report.setdefault("forensic_flags", [])
                report["forensic_flags"].extend(fleet_findings["forensic_flags"])
                print(
                    f"\n  [FLEET] {len(fleet_findings['forensic_flags'])} "
                    f"forensic flag(s) added to investigation record."
                )
        except Exception as exc:
            print(f"  [WARN] FleetDetectorModule error: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    # -- Heuristics -----------------------------------------------------------
    hr = results.get("heuristics")
    if hr:
        report["heuristic_analysis"] = hr.to_dict()

    if args.format in ("terminal", "both"):
        reporter.print_terminal(report)
        if hr:
            confirmed = [h for h in hr.heuristics if h.status == "CONFIRMED"]
            partial   = [h for h in hr.heuristics if h.status == "PARTIAL"]
            print()
            print("=" * 64)
            print("# YAICD FORMAL DETECTION SCORE (Ziayi et al. 2021)")
            print("#" + "=" * 63)
            print(f"#   Confirmed heuristics : {hr.confirmed_count}")
            print(f"  Partial heuristics   : {hr.partial_count}")
            print(f"  YAICD score          : {hr.yaicd_formal_score:.2f} (threshold: 2.6)")
            print(f"  Triggered params     : {', '.join(hr.triggered_params) or 'none'}")
            verdict = ("*** FORMAL POSITIVE DETECTION ***"
                       if hr.yaicd_detected else "Below threshold")
            print(f"  Verdict              : {verdict}")
            print(f"  Severity             : {hr.severity}")
            if confirmed:
                print()
                print("  Confirmed indicators:")
                for h in confirmed:
                    print(f"    [+] {h.heuristic_id} {h.label}")
            if partial:
                print("  Partial indicators:")
                for h in partial:
                    print(f"    [~] {h.heuristic_id} {h.label}")
            print("=" * 64)

        # -- Fleet summary in terminal output ---------------------------------
        if fleet_findings and fleet_findings.get("detection_count", 0) > 0:
            print()
            print("=" * 64)
            print("# FLEET RF SIGNATURE SUMMARY")
            print("=" * 64)
            print(f"  {fleet_findings['summary_text']}")
            elevated = [
                d for d in fleet_findings.get("detections", [])
                if d.get("alert_level") in ("warning", "high", "flag")
            ]
            if elevated:
                print()
                print("  Elevated contacts:")
                for det in elevated:
                    marker = {
                        "warning": "[  !!  ]",
                        "high":    "[ HIGH ]",
                        "flag":    "[ FLAG ]"
                    }.get(det["alert_level"], "[  ?  ]")
                    print(f"    {marker} {det['label']} ({det['confidence_pct']})")
            print("=" * 64)

    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {args.output}")
        else:
            out_path = f"rayhunter_report_{int(time.time())}.json"
            Path(out_path).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {out_path}")

    if args.html:
        try:
            from html_reporter_v2 import HTMLReporterV2
            html_path = (Path(args.output).with_suffix(".html") if args.output
                         else Path(f"rayhunter_report_{int(time.time())}.html"))
            HTMLReporterV2(cfg).generate(report, str(html_path))
            print(f"[OK] HTML report saved to: {html_path}")
        except ImportError:
            print("[WARN] html_reporter_v2.py not found ? HTML skipped.")

    if args.manifest:
        try:
            from manifest_generator import ManifestGenerator
            ManifestGenerator(cfg).generate(
                files["ndjson"] + files["pcap"] + files["qmdl"]
            )
            print("[OK] SHA-256 forensic manifest generated.")
        except ImportError:
            print("[WARN] manifest_generator.py not found ? manifest skipped.")

if __name__ == "__main__":
    main()
