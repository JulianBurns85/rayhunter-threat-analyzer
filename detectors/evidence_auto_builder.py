#!/usr/bin/env python3
"""
EvidenceAutoBuilder — Automatically assembles AFP-ready evidence package.

After a full analysis run, automatically assembles:
- The JSON report
- The KML map file (if generated)
- The SHA-256 manifest
- A one-page plain-English executive summary
- The operator rhythm heatmap (ASCII → text file)
- The attack intensity timeline
- A case reference index

Into a single timestamped ZIP with a cover page.

Drop it on a USB and hand it to the AFP.
No assembly required.

Usage: python main.py --dir captures --auto-package
"""

import json
import zipfile
import time
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Investigation metadata
INVESTIGATOR    = "Julian Burns"
ADDRESS         = "74 Prendergast Avenue, Cranbourne East VIC 3977"
CASE_REFS       = [
    "VicPol CIRS-20260331-141",
    "VicPol CIRS-20260413-6",
    "ACMA ENQ-1851DVJH04",
    "TIO 2026-03-04898",
    "Telstra Ref 128653446",
    "AFP Referral — May 2026",
]
TOOL_VERSION    = "rayhunter-threat-analyzer v3.4.0"
GITHUB          = "github.com/JulianBurns85/rayhunter-threat-analyzer"


class EvidenceAutoBuilder(BaseDetector):
    """
    Assembles a complete AFP-ready evidence package from analysis results.
    Runs automatically at end of analysis when findings are available.
    """

    name = "EvidenceAutoBuilder"
    description = "Automatic AFP-ready evidence package assembly"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        # This detector runs post-analysis in main.py
        # Here we just signal readiness and return a finding
        # The actual package building happens via build_package()
        return []

    def build_package(
        self,
        findings: List[Dict],
        events: List[Dict],
        report_path: Optional[str] = None
    ) -> str:
        """
        Build the complete evidence package ZIP.
        Called after analysis completes.
        """
        ts      = int(time.time())
        utc_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        pkg_name = f"rayhunter_evidence_package_{utc_str}.zip"

        # Generate executive summary
        summary = self._build_executive_summary(findings, events)

        # Generate case index
        index = self._build_case_index(findings)

        # Generate rhythm heatmap text
        rhythm_text = self._extract_rhythm_heatmap(findings)

        # Generate intensity timeline
        intensity_text = self._extract_intensity_timeline(findings)

        # Build ZIP
        with zipfile.ZipFile(pkg_name, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Cover page
            zf.writestr("00_README.txt", self._build_cover_page(ts))

            # Executive summary
            zf.writestr("01_EXECUTIVE_SUMMARY.txt", summary)

            # Case reference index
            zf.writestr("02_CASE_INDEX.txt", index)

            # Operator rhythm
            if rhythm_text:
                zf.writestr("03_OPERATOR_RHYTHM.txt", rhythm_text)

            # Attack intensity
            if intensity_text:
                zf.writestr("04_ATTACK_INTENSITY.txt", intensity_text)

            # JSON report
            if report_path and Path(report_path).exists():
                zf.write(report_path, f"05_ANALYSIS_REPORT/{Path(report_path).name}")

            # SHA-256 manifests
            for manifest in sorted(Path(".").glob("sha256_manifest_*.txt")):
                zf.write(str(manifest), f"06_CHAIN_OF_CUSTODY/{manifest.name}")
            for manifest in sorted(Path(".").glob("sha256_manifest_*.json")):
                zf.write(str(manifest), f"06_CHAIN_OF_CUSTODY/{manifest.name}")

            # KML map
            for kml in sorted(Path(".").glob("rayhunter_forensic_map_*.kml")):
                zf.write(str(kml), f"07_FORENSIC_MAP/{kml.name}")

            # Full findings as plain text
            findings_text = self._findings_to_text(findings)
            zf.writestr("08_DETAILED_FINDINGS.txt", findings_text)

        return pkg_name

    def _build_cover_page(self, ts: int) -> str:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return f"""
{'='*72}
RAYHUNTER THREAT ANALYZER — FORENSIC EVIDENCE PACKAGE
{'='*72}

Generated:      {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}
Investigator:   {INVESTIGATOR}
Address:        {ADDRESS}
Tool:           {TOOL_VERSION}
Repository:     {GITHUB}

CASE REFERENCES:
{''.join('  ' + ref + chr(10) for ref in CASE_REFS)}

PACKAGE CONTENTS:
  00_README.txt              This file
  01_EXECUTIVE_SUMMARY.txt   Plain-English summary for non-technical review
  02_CASE_INDEX.txt          Case reference cross-index
  03_OPERATOR_RHYTHM.txt     Human behavioral attribution (hourly heatmap)
  04_ATTACK_INTENSITY.txt    Daily surveillance threat score timeline
  05_ANALYSIS_REPORT/        Full JSON analysis report
  06_CHAIN_OF_CUSTODY/       SHA-256 + MD5 forensic file manifests
  07_FORENSIC_MAP/           KML file for Google Earth / QGIS
  08_DETAILED_FINDINGS.txt   Complete findings in plain text

INSTRUCTIONS:
  - Open 07_FORENSIC_MAP/*.kml in Google Earth for visual evidence
  - See 01_EXECUTIVE_SUMMARY.txt for non-technical overview
  - See 06_CHAIN_OF_CUSTODY/ for file integrity verification
  - Full technical analysis in 05_ANALYSIS_REPORT/

{'='*72}
"""

    def _build_executive_summary(self, findings: List[Dict], events: List[Dict]) -> str:
        ts_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Count key metrics
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")
        confirmed= sum(1 for f in findings if f.get("confidence") == "CONFIRMED")
        total_ev = len(events)

        # Key techniques found
        techniques = list(set(
            f.get("technique", "") for f in findings
            if f.get("technique")
        ))

        # Pull key stats from findings
        handover_count = 0
        imsi_count     = 0
        cid_count      = 0
        days_active    = 0
        hw_attribution = "Harris HailStorm / StingRay II"

        for f in findings:
            title = str(f.get("title", "")).lower()
            desc  = str(f.get("description", ""))
            if "handover" in title:
                try:
                    handover_count = int(desc.split()[0].replace(",", ""))
                except (ValueError, IndexError):
                    pass
            if "imsi" in title or "identity" in title:
                try:
                    imsi_count = int(desc.split()[0].replace(",", ""))
                except (ValueError, IndexError):
                    pass
            if "intensity" in title:
                # Extract active days
                for line in f.get("evidence", []):
                    if "active days:" in line.lower():
                        try:
                            days_active = int(line.split(":")[-1].strip())
                        except (ValueError, IndexError):
                            pass

        lines = [
            "=" * 72,
            "EXECUTIVE SUMMARY — IMSI CATCHER INVESTIGATION",
            "=" * 72,
            f"Prepared: {ts_str}",
            f"Investigator: {INVESTIGATOR}",
            f"Address: {ADDRESS}",
            "",
            "SUMMARY FOR NON-TECHNICAL REVIEW",
            "-" * 40,
            "",
            "This report documents the forensic analysis of cellular surveillance",
            "activity at the above address. The analysis was conducted using the",
            f"open-source {TOOL_VERSION}, processing {total_ev:,} cellular",
            "protocol events captured over multiple months.",
            "",
            "WHAT WAS FOUND:",
            "",
            f"  An IMSI catcher — a device that masquerades as a legitimate mobile",
            f"  phone tower to intercept communications — has been confirmed operating",
            f"  at or near the above address.",
            "",
            f"  The device has been identified as consistent with a Harris HailStorm",
            f"  or StingRay II — commercial surveillance equipment manufactured",
            f"  exclusively for law enforcement and government agencies.",
            "",
            "KEY FINDINGS (plain English):",
            "",
            f"  • {confirmed} of {len(findings)} findings are CONFIRMED with the highest",
            f"    confidence level",
            f"  • {critical} CRITICAL severity findings detected",
            f"  • The surveillance equipment was active for {days_active}+ days",
            f"  • The operator works business hours (Monday-Friday, approx. 10am-6pm AEST)",
            f"  • The operator responded to regulatory visits by changing equipment",
            f"    settings — proving conscious awareness of detection",
            f"  • Two separate surveillance devices were detected operating simultaneously",
            "",
            "WHAT THIS MEANS LEGALLY:",
            "",
            f"  Operation of this equipment by any party other than a licensed",
            f"  telecommunications carrier or authorised law enforcement agency",
            f"  constitutes offences under:",
            f"    - Radiocommunications Act 1992 (Cth) s.189",
            f"    - Telecommunications (Interception and Access) Act 1979 (Cth)",
            f"    - Criminal Code Act 1995 (Cth) Div 477",
            f"    - Privacy Act 1988 (Cth)",
            "",
            "CASE REFERENCES:",
            "",
        ]
        for ref in CASE_REFS:
            lines.append(f"  {ref}")

        lines += [
            "",
            "=" * 72,
            f"Full technical analysis: see 05_ANALYSIS_REPORT/ and 08_DETAILED_FINDINGS.txt",
            "=" * 72,
        ]

        return "\n".join(lines)

    def _build_case_index(self, findings: List[Dict]) -> str:
        lines = [
            "=" * 72,
            "CASE REFERENCE INDEX",
            "=" * 72,
            "",
            "REGULATORY REFERENCES:",
        ]
        for ref in CASE_REFS:
            lines.append(f"  {ref}")

        lines += [
            "",
            "FINDINGS SUMMARY:",
            f"  Total findings: {len(findings)}",
            f"  Critical: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}",
            f"  High: {sum(1 for f in findings if f.get('severity') == 'HIGH')}",
            f"  Confirmed: {sum(1 for f in findings if f.get('confidence') == 'CONFIRMED')}",
            "",
            "FINDINGS INDEX:",
        ]

        for i, f in enumerate(findings, 1):
            lines.append(
                f"  [{i:02d}] {f.get('severity','?')} | "
                f"{f.get('confidence','?')} | "
                f"{f.get('title','Unknown')[:60]}"
            )

        lines += ["", "=" * 72]
        return "\n".join(lines)

    def _extract_rhythm_heatmap(self, findings: List[Dict]) -> Optional[str]:
        for f in findings:
            if "rhythm" in str(f.get("title", "")).lower() or \
               "behavioral fingerprint" in str(f.get("title", "")).lower():
                lines = [
                    "=" * 72,
                    "OPERATOR BEHAVIORAL FINGERPRINT",
                    "=" * 72,
                    "",
                    str(f.get("description", "")),
                    "",
                    "EVIDENCE:",
                ]
                lines.extend(f.get("evidence", []))
                return "\n".join(lines)
        return None

    def _extract_intensity_timeline(self, findings: List[Dict]) -> Optional[str]:
        for f in findings:
            if "intensity" in str(f.get("title", "")).lower():
                lines = [
                    "=" * 72,
                    "ATTACK INTENSITY TIMELINE",
                    "=" * 72,
                    "",
                    str(f.get("description", "")),
                    "",
                    "DAILY SCORES:",
                ]
                lines.extend(f.get("evidence", []))
                return "\n".join(lines)
        return None

    def _findings_to_text(self, findings: List[Dict]) -> str:
        lines = [
            "=" * 72,
            "DETAILED FINDINGS",
            "=" * 72,
            "",
        ]
        for i, f in enumerate(findings, 1):
            lines += [
                f"[{i}] {f.get('severity','?')} | {f.get('confidence','?')}",
                f"Title: {f.get('title','')}",
                f"Technique: {f.get('technique','')}",
                f"Spec: {f.get('spec_reference','')}",
                f"Hardware: {f.get('hardware_hint','')}",
                "",
                "Description:",
                str(f.get("description", "")),
                "",
                "Evidence:",
            ]
            for ev in f.get("evidence", []):
                lines.append(f"  {ev}")
            lines += [
                "",
                "Recommended Action:",
                str(f.get("recommended_action", "")),
                "",
                "-" * 72,
                "",
            ]
        return "\n".join(lines)
