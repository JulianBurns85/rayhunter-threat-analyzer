#!/usr/bin/env python3
"""
test_synthetic.py — Self-contained test using synthetic event data.
Verifies all detectors fire correctly without needing real capture files.

Run:  python test_synthetic.py
"""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config_loader
from detectors.identity_harvest import IdentityHarvestDetector
from detectors.cipher_downgrade import CipherDowngradeDetector
from detectors.handover_inject import HandoverInjectDetector
from detectors.paging_anomaly import PagingAnomalyDetector
from detectors.earfcn_anomaly import EarfcnAnomalyDetector
from detectors.rogue_tower import RogueTowerDetector
from intelligence.hardware_fingerprint import HardwareFingerprinter
from reporter import ThreatReporter


def make_event(**kwargs) -> dict:
    """Helper to build a synthetic normalised event."""
    defaults = {
        "source_file": "synthetic_test.ndjson",
        "source_type": "ndjson",
        "line": 0,
        "timestamp": "2026-03-31T14:00:00+00:00",
        "raw": {},
        "cell_id": "98765",
        "earfcn": 9350,
        "mcc": "505",
        "mnc": "001",
        "tac": "1234",
        "pci": 42,
        "rsrp": -72.0,
        "rat": "LTE",
        "msg_type": None,
        "msg_subtype": None,
        "layer": "NAS",
        "cipher_alg": None,
        "integrity_alg": None,
        "identity_type": None,
        "has_mobility_control": False,
        "has_geran_redirect": False,
        "has_measreport": False,
        "has_prose": False,
        "paging_type": None,
        "harness_alerts": [],
    }
    defaults.update(kwargs)
    return defaults


def build_test_events() -> list:
    """
    Build a synthetic event timeline representing a full IMSI catcher attack:
      T+0s   : Identity Request (IMSI)
      T+5s   : Identity Request (IMSI)   ← second request = flood
      T+10s  : Identity Request (IMSI)   ← third = CRITICAL
      T+12s  : Security Mode Command EEA0 + EIA0   ← full null cipher
      T+15s  : RRC Reconfig with mobilityControlInfo (no prior MeasReport)
      T+20s  : RRC Connection Release with GERAN redirect
      T+35s  : Paging (IMSI-targeted)
      T+40s  : Authentication Reject
      T+42s  : Identity Request (IMEI) after auth reject
      T+50s  : RRC Reconfig with ProSe proximity config
      — Plus same cell_id on different EARFCN (multi-EARFCN anomaly)
    """

    base_ts = "2026-03-31T14:{}:{}+00:00"

    events = [
        # 1. Identity Request flood (3 IMSI requests)
        make_event(
            timestamp=base_ts.format("00", "00"),
            msg_type="Identity Request",
            identity_type="IMSI",
        ),
        make_event(
            timestamp=base_ts.format("00", "05"),
            msg_type="Identity Request",
            identity_type="IMSI",
        ),
        make_event(
            timestamp=base_ts.format("00", "10"),
            msg_type="Identity Request",
            identity_type="IMSI",
        ),

        # 2. Full null cipher (EEA0 + EIA0)
        make_event(
            timestamp=base_ts.format("00", "12"),
            msg_type="Security Mode Command",
            cipher_alg="EEA0",
            integrity_alg="EIA0",
        ),

        # 3. Injected handover (mobilityControlInfo, no MeasReport)
        make_event(
            timestamp=base_ts.format("00", "15"),
            msg_type="RRC Connection Reconfiguration",
            has_mobility_control=True,
            has_measreport=False,
            layer="RRC",
        ),
        make_event(
            timestamp=base_ts.format("00", "16"),
            msg_type="RRC Connection Reconfiguration",
            has_mobility_control=True,
            has_measreport=False,
            layer="RRC",
        ),
        make_event(
            timestamp=base_ts.format("00", "17"),
            msg_type="RRC Connection Reconfiguration",
            has_mobility_control=True,
            has_measreport=False,
            layer="RRC",
        ),

        # 4. GERAN redirect (forced 2G downgrade)
        make_event(
            timestamp=base_ts.format("00", "20"),
            msg_type="RRC Connection Release",
            has_geran_redirect=True,
            layer="RRC",
        ),

        # 5. IMSI-targeted paging
        make_event(
            timestamp=base_ts.format("00", "35"),
            msg_type="Paging",
            paging_type="IMSI",
        ),
        make_event(
            timestamp=base_ts.format("00", "38"),
            msg_type="Paging",
            paging_type="IMSI",
        ),
        make_event(
            timestamp=base_ts.format("00", "39"),
            msg_type="Paging",
            paging_type="IMSI",
        ),

        # 6. Auth Reject → IMEI request
        make_event(
            timestamp=base_ts.format("00", "40"),
            msg_type="Authentication Reject",
        ),
        make_event(
            timestamp=base_ts.format("00", "42"),
            msg_type="Identity Request",
            identity_type="IMEI/IMEISV",
        ),

        # 7. ProSe proximity tracking config
        make_event(
            timestamp=base_ts.format("00", "50"),
            msg_type="RRC Connection Reconfiguration",
            has_prose=True,
            layer="RRC",
            harness_alerts=["reportProximityConfig-r9 detected"],
        ),

        # 8. Multi-EARFCN anomaly (same cell_id, different EARFCN)
        make_event(
            timestamp=base_ts.format("01", "00"),
            msg_type="MIB",
            earfcn=1450,   # ← Different EARFCN, same cell_id=98765
            cell_id="98765",
        ),

        # 9. Harness alert from Rayhunter itself
        make_event(
            timestamp=base_ts.format("01", "05"),
            harness_alerts=["imsi catcher suspected", "eea0 null cipher"],
            msg_type="Security Mode Command",
            cipher_alg="EEA0",
        ),
    ]

    return events


def run_tests():
    print("\n" + "="*62)
    print("  RAYHUNTER THREAT ANALYZER — SYNTHETIC TEST")
    print("  Simulating a full IMSI catcher attack timeline")
    print("="*62 + "\n")

    cfg = config_loader.load("config.yaml")
    cfg["opencellid"]["enabled"] = False  # No API calls in test

    events = build_test_events()
    print(f"  Synthetic events created: {len(events)}")

    detectors = [
        IdentityHarvestDetector(cfg),
        CipherDowngradeDetector(cfg),
        RogueTowerDetector(cfg),
        HandoverInjectDetector(cfg),
        PagingAnomalyDetector(cfg),
        EarfcnAnomalyDetector(cfg),
    ]

    all_findings = []
    print("\n  Running detectors...")
    for detector in detectors:
        findings = detector.analyze(events)
        if findings:
            print(f"    ✓ {detector.name}: {len(findings)} finding(s)")
        else:
            print(f"    - {detector.name}: no findings")
        all_findings.extend(findings)

    fingerprinter = HardwareFingerprinter(cfg)
    hardware = fingerprinter.analyze(events, all_findings)
    if hardware:
        print(f"    ✓ HardwareFingerprinter: {len(hardware)} candidate(s)")

    print(f"\n  Total findings: {len(all_findings)}")
    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    print(f"  Critical: {critical}")

    reporter = ThreatReporter(cfg)
    report = reporter.build_report(
        {"events": events, "findings": all_findings, "hardware": hardware},
        elapsed=0.1
    )

    print("\n")
    reporter.print_terminal(report)

    # Save report
    out_path = "test_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  JSON report saved: {out_path}")

    # Verify expected detections
    print("\n" + "="*62)
    print("  ASSERTION CHECKS")
    print("="*62)
    checks = [
        ("CRITICAL findings present", critical > 0),
        ("Identity harvest detected", any(
            "Identity" in f.get("title","") for f in all_findings
        )),
        ("Null cipher detected", any(
            "Null" in f.get("title","") or "EEA0" in f.get("title","")
            for f in all_findings
        )),
        ("GERAN redirect detected", any(
            "2G" in f.get("title","") or "GERAN" in f.get("title","")
            for f in all_findings
        )),
        ("Handover inject detected", any(
            "Handover" in f.get("title","") for f in all_findings
        )),
        ("ProSe tracking detected", any(
            "ProSe" in f.get("title","") or "Proximity" in f.get("title","")
            for f in all_findings
        )),
        ("IMSI paging detected", any(
            "Paging" in f.get("title","") for f in all_findings
        )),
        ("Multi-EARFCN detected", any(
            "EARFCN" in f.get("title","") for f in all_findings
        )),
        ("Hardware candidates identified", len(hardware) > 0),
    ]

    all_pass = True
    for name, result in checks:
        status = "✅ PASS" if result else "❌ FAIL"
        if not result:
            all_pass = False
        print(f"  {status}: {name}")

    print()
    if all_pass:
        print("  All checks passed. Tool is working correctly.")
    else:
        print("  Some checks failed — review output above.")
    print()
    return all_pass


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
