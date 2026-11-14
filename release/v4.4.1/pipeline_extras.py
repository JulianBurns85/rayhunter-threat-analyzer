#!/usr/bin/env python3
"""
pipeline_extras.py — v4.4.1 helpers for main.py

- finding_attr: read fields from dict or object findings (Argus-DB input fix)
- run_specialized_detectors: wire P7 auth-reject and RRC redirect detectors
- report_output_dir: resolve config output_dir for JSON/HTML/KML writers
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Union

Finding = Union[Dict[str, Any], Any]


def finding_attr(finding: Finding, key: str, default: str = "") -> str:
    """Read a field from a finding dict or object."""
    if isinstance(finding, dict):
        val = finding.get(key, default)
    else:
        val = getattr(finding, key, default)
    return val if val is not None else default


def report_output_dir(cfg: Mapping[str, Any]) -> Path:
    """Return configured report directory, creating it if needed."""
    out = Path(cfg.get("output_dir", ".")).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    return out


def run_specialized_detectors(files: Dict[str, List[str]]) -> List[Dict]:
    """
    PCAP/NDJSON-native detectors that do not use BaseDetector.analyze(events).

    - auth_reject_imeisv_detector (YAICD P7)
    - rrc_redirect_detector (Arrowhead DF redirect)
    """
    from detectors.base import make_finding

    extra: List[Dict] = []

    try:
        from detectors.auth_reject_imeisv_detector import (
            AuthRejectImeisvDetector,
            extract_nas_events_from_ndjson,
            extract_nas_events_from_pcap,
        )

        p7 = AuthRejectImeisvDetector()
        for fp in files.get("pcap", []):
            p7.ingest_events(extract_nas_events_from_pcap(Path(fp)))
        for fp in files.get("ndjson", []):
            p7.ingest_events(extract_nas_events_from_ndjson(Path(fp)))
        p7_result = p7.findings()
        if p7_result.get("triggered"):
            sev = p7_result.get("severity", "HIGH")
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                sev = "HIGH"
            extra.append(
                make_finding(
                    detector="auth_reject_imeisv",
                    title="Auth Reject -> Identity Request (YAICD P7)",
                    description=p7_result.get("summary", ""),
                    severity=sev,
                    confidence="CONFIRMED",
                    technique=(
                        "Harris HailStorm P7: Authentication Reject immediately followed "
                        "by Identity Request (IMEISV/IMSI)"
                    ),
                    evidence=[
                        json.dumps(seq, default=str)
                        for seq in p7_result.get("sequences", [])
                    ],
                    spec_ref="Gemini QSG 4-2; Kareem 2023 IJRITCC; YAICD P7",
                )
            )
            print("  -> 1 finding(s): auth_reject_imeisv (P7)")
    except Exception as exc:
        print(f"  [WARN] auth_reject_imeisv_detector: {exc}")

    try:
        from detectors.rrc_redirect_detector import (
            RrcRedirectDetector,
            extract_redirects_from_pcap,
        )

        rrc = RrcRedirectDetector()
        for fp in files.get("pcap", []):
            rrc.ingest_events(extract_redirects_from_pcap(Path(fp)))
        rrc_result = rrc.analyse()
        if rrc_result.get("triggered"):
            sev = rrc_result.get("severity", "HIGH")
            if sev == "NOT_TRIGGERED":
                sev = "HIGH"
            conf = "CONFIRMED" if sev == "CRITICAL" else "PROBABLE"
            extra.append(
                make_finding(
                    detector="rrc_redirect_anomaly",
                    title=f"RRC Redirect Anomaly - {sev}",
                    description=rrc_result.get("summary", ""),
                    severity=sev,
                    confidence=conf,
                    technique=(
                        "Harris Arrowhead DF: RRCConnectionRelease with "
                        "redirectedCarrierInfo toward anomalous EARFCN"
                    ),
                    evidence=[
                        json.dumps(evt, default=str)
                        for evt in rrc_result.get("events", [])[:25]
                    ],
                    spec_ref="Gemini QSG 6 LTE Redirect MS DF; Arrowhead 1.0.1",
                )
            )
            print("  -> 1 finding(s): rrc_redirect_anomaly")
    except Exception as exc:
        print(f"  [WARN] rrc_redirect_detector: {exc}")

    return extra
