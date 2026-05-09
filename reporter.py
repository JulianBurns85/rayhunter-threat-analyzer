#!/usr/bin/env python3
"""
Threat Reporter
===============
Builds and renders structured threat reports from detector findings.
Supports terminal (rich colour) and JSON output formats.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

CONFIDENCE_SYMBOLS = {
    "CONFIRMED": "✅",
    "PROBABLE":  "⚠️ ",
    "SUSPECTED": "🔍",
}

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class ThreatReporter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.console = Console() if RICH_AVAILABLE else None

    def build_report(self, results: dict, elapsed: float) -> dict:
        """Build a structured JSON-serialisable report dict."""
        findings = results.get("findings", [])
        events   = results.get("events", [])
        hardware = results.get("hardware", [])

        # Sort findings: severity desc, confidence desc
        findings_sorted = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.get("severity", "INFO"), 0),
                f.get("confidence_score", 0),
            ),
            reverse=True,
        )

        # Summary stats
        severity_counts = {}
        for f in findings_sorted:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Overall threat level
        if severity_counts.get("CRITICAL", 0) > 0:
            threat_level = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            threat_level = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            threat_level = "MEDIUM"
        elif severity_counts.get("LOW", 0) > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        # Collect unique techniques
        techniques = list(dict.fromkeys(
            f.get("technique", "") for f in findings_sorted if f.get("technique")
        ))

        # Collect confirmed attacks
        confirmed = [
            f for f in findings_sorted
            if f.get("confidence") == "CONFIRMED" and
            f.get("severity") in ("CRITICAL", "HIGH")
        ]

        report = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "analysis_duration_seconds": round(elapsed, 2),
            "summary": {
                "threat_level": threat_level,
                "total_findings": len(findings_sorted),
                "severity_breakdown": severity_counts,
                "total_events_analyzed": len(events),
                "confirmed_attacks": len(confirmed),
                "techniques_detected": techniques,
            },
            "hardware_candidates": hardware,
            "findings": findings_sorted,
            "legal_reference": {
                "investigation_ref": "CIRS-20260331-141",
                "acma_ref": "ACMA-ENQ-1851DVJH04",
                "telstra_complaint": "128653446",
                "tio_ref": "2026-03-04898",
                "applicable_law": [
                    "Radiocommunications Act 1992 (Cth) s.189",
                    "Telecommunications (Interception and Access) Act 1979 (Cth)",
                    "Privacy Act 1988 (Cth)",
                    "Criminal Code Act 1995 (Cth) - Div 477 (Unauthorised access/modification)",
                    "3GPP TS 33.401 (LTE Security Architecture)",
                ],
            },
        }

        return report

    def print_terminal(self, report: dict):
        """Print formatted threat report to terminal."""
        if RICH_AVAILABLE:
            self._print_rich(report)
        else:
            self._print_plain(report)

    def _print_rich(self, report: dict):
        """Rich-formatted terminal output."""
        c = self.console
        summary = report["summary"]
        threat_level = summary["threat_level"]

        # ── Header ────────────────────────────────────────────────────
        level_colour = SEVERITY_COLOURS.get(threat_level, "green")
        c.print()
        c.print(Panel(
            f"[{level_colour}]THREAT LEVEL: {threat_level}[/{level_colour}]\n"
            f"Findings: {summary['total_findings']} | "
            f"Confirmed Attacks: {summary['confirmed_attacks']} | "
            f"Events Analyzed: {summary['total_events_analyzed']}",
            title="[bold]Rayhunter Threat Analysis Report[/bold]",
            border_style=level_colour.replace("bold ", ""),
        ))

        # ── Severity breakdown ────────────────────────────────────────
        if summary["severity_breakdown"]:
            breakdown = " | ".join(
                f"[{SEVERITY_COLOURS.get(k,'white')}]{k}: {v}[/{SEVERITY_COLOURS.get(k,'white')}]"
                for k, v in sorted(
                    summary["severity_breakdown"].items(),
                    key=lambda x: SEVERITY_ORDER.get(x[0], 0),
                    reverse=True,
                )
            )
            c.print(f"  Severity: {breakdown}")

        # ── Hardware candidates ────────────────────────────────────────
        if report.get("hardware_candidates"):
            c.print()
            c.print("[bold yellow]◆ HARDWARE CANDIDATES[/bold yellow]")
            for hw in report["hardware_candidates"]:
                conf = hw.get("confidence", "?")
                c.print(f"  [{SEVERITY_COLOURS.get(hw.get('severity','HIGH'))}]"
                        f"[{conf}] {hw['hardware']}[/{SEVERITY_COLOURS.get(hw.get('severity','HIGH'))}]")
                c.print(f"       {hw['notes'][:120]}")

        # ── Techniques ────────────────────────────────────────────────
        if summary.get("techniques_detected"):
            c.print()
            c.print("[bold]Techniques Detected:[/bold]")
            for t in summary["techniques_detected"][:10]:
                c.print(f"  • {t}")

        # ── Findings ──────────────────────────────────────────────────
        c.print()
        c.print("[bold]" + "═" * 60 + "[/bold]")
        c.print("[bold]DETAILED FINDINGS[/bold]")
        c.print("[bold]" + "═" * 60 + "[/bold]")

        for i, finding in enumerate(report["findings"], 1):
            sev = finding.get("severity", "INFO")
            conf = finding.get("confidence", "SUSPECTED")
            colour = SEVERITY_COLOURS.get(sev, "white")
            symbol = CONFIDENCE_SYMBOLS.get(conf, "?")

            c.print()
            c.print(Panel(
                self._format_finding_rich(finding),
                title=f"[{colour}][{i}] {sev} | {symbol} {conf} — {finding['title']}[/{colour}]",
                border_style=colour.replace("bold ", ""),
                padding=(0, 1),
            ))

        # ── Recommended actions ───────────────────────────────────────
        critical = [f for f in report["findings"] if f.get("severity") == "CRITICAL"]
        if critical:
            c.print()
            c.print(Panel(
                self._format_top_actions(critical),
                title="[bold red]PRIORITY ACTIONS[/bold red]",
                border_style="red",
            ))

        c.print()
        c.print(f"[dim]Report generated: {report['generated_at']} | "
                f"Analysis time: {report['analysis_duration_seconds']}s[/dim]")

    def _format_finding_rich(self, finding: dict) -> str:
        lines = []
        lines.append(finding.get("description", ""))
        if finding.get("technique"):
            lines.append(f"\n[bold]Technique:[/bold] {finding['technique']}")
        if finding.get("spec_reference"):
            lines.append(f"[bold]Spec:[/bold] {finding['spec_reference']}")
        if finding.get("hardware_hint"):
            lines.append(f"[bold]Hardware:[/bold] {finding['hardware_hint']}")
        evidence = finding.get("evidence", [])
        if evidence:
            lines.append("\n[bold]Evidence:[/bold]")
            for e in evidence[:self.cfg.get("output", {}).get("max_evidence_lines", 5)]:
                lines.append(f"  [dim]{e}[/dim]")
        if finding.get("recommended_action"):
            lines.append(f"\n[bold]Action:[/bold]\n{finding['recommended_action']}")
        return "\n".join(lines)

    def _format_top_actions(self, critical_findings: list) -> str:
        lines = ["Take these actions immediately:\n"]
        for i, f in enumerate(critical_findings[:5], 1):
            action = f.get("recommended_action", "Preserve evidence.")
            first_line = action.split("\n")[0]
            lines.append(f"{i}. [{f['title']}]\n   {first_line}")
        return "\n".join(lines)

    def _print_plain(self, report: dict):
        """Plain text fallback (no rich)."""
        summary = report["summary"]
        print(f"\n{'='*62}")
        print(f"THREAT LEVEL: {summary['threat_level']}")
        print(f"Findings: {summary['total_findings']} | Events: {summary['total_events_analyzed']}")
        print(f"{'='*62}")

        for i, finding in enumerate(report["findings"], 1):
            print(f"\n[{i}] {finding.get('severity','?')} | {finding.get('confidence','?')}")
            print(f"    {finding['title']}")
            print(f"    {finding.get('description','')[:200]}")
            for ev in finding.get("evidence", [])[:3]:
                print(f"    EVIDENCE: {ev}")
            if finding.get("recommended_action"):
                print(f"    ACTION: {finding['recommended_action'].split(chr(10))[0]}")

        if report.get("hardware_candidates"):
            print(f"\n{'='*62}")
            print("HARDWARE CANDIDATES:")
            for hw in report["hardware_candidates"]:
                print(f"  [{hw['confidence']}] {hw['hardware']}")

        print(f"\nGenerated: {report['generated_at']}")
