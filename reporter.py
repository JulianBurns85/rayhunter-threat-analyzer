#!/usr/bin/env python3
"""
Threat Reporter
===============
Builds and renders structured threat reports from detector findings.
Supports terminal (rich colour) and JSON output formats.

v2.3 changes
------------
- Integrated SessionOverlapCorrelator: identifies dual-carrier parallel
  capture sessions and outputs overlap windows in both CLI and JSON.
- Integrated CrossCarrierEvidencePatcher: mutates cross-carrier findings
  in-place to inject pinned timestamp pairs (exact UTC timestamps for
  each simultaneous Telstra/Vodafone event pair within a 5-second window).
- New 'session_correlation' top-level key in JSON report output.
- Session correlation rendered as a dedicated CLI section before findings.
- max_evidence_lines cap lifted for cross-carrier evidence blocks so that
  pinned timestamp pairs are never truncated in the terminal output.
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

# ── New v2.3 imports ──────────────────────────────────────────────────────────
try:
    from session_overlap_correlator import SessionOverlapCorrelator
    CORRELATOR_AVAILABLE = True
except ImportError:
    CORRELATOR_AVAILABLE = False

try:
    from cross_carrier_timestamp_patch import CrossCarrierEvidencePatcher
    PATCHER_AVAILABLE = True
except ImportError:
    PATCHER_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────


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

# Gap thresholds for the correlator / patcher
_CORRELATOR_GAP_SECS = 30.0   # session overlap correlator
_PATCHER_GAP_SECS    =  5.0   # definitive simultaneous event pairs


class ThreatReporter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.console = Console() if RICH_AVAILABLE else None

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def build_report(self, results: dict, elapsed: float) -> dict:
        """
        Build a structured JSON-serialisable report dict.

        results must contain:
            findings : list of finding dicts
            events   : flat list of all normalised event dicts
            hardware : list of hardware candidate dicts
            sessions : dict of session_id → list[event_dict]   (NEW v2.3)
        """
        findings = results.get("findings", [])
        events   = results.get("events", [])
        hardware = results.get("hardware", [])
        sessions = results.get("sessions", {})   # v2.3

        # ── Sort findings: severity desc, confidence desc ─────────────
        findings_sorted = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.get("severity", "INFO"), 0),
                f.get("confidence_score", 0),
            ),
            reverse=True,
        )

        # ── Summary stats ─────────────────────────────────────────────
        severity_counts = {}
        for f in findings_sorted:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

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

        techniques = list(dict.fromkeys(
            f.get("technique", "") for f in findings_sorted if f.get("technique")
        ))

        confirmed = [
            f for f in findings_sorted
            if f.get("confidence") == "CONFIRMED" and
            f.get("severity") in ("CRITICAL", "HIGH")
        ]

        # ── v2.3: Session correlation ─────────────────────────────────
        session_correlation = {}
        if sessions and CORRELATOR_AVAILABLE:
            correlator = SessionOverlapCorrelator(
                sessions, gap_seconds=_CORRELATOR_GAP_SECS
            )
            correlator.analyze()

            # Patch cross-carrier findings with pinned timestamp pairs
            if PATCHER_AVAILABLE and correlator.parallel_pairs:
                patcher = CrossCarrierEvidencePatcher(
                    all_events=events,
                    parallel_pairs=correlator.parallel_pairs,
                    session_meta=correlator.session_meta,
                    gap_seconds=_PATCHER_GAP_SECS,
                )
                patcher.apply(findings_sorted)

            session_correlation = correlator.to_dict()
            # Store correlator on self so print_terminal can access it
            self._correlator = correlator
        else:
            self._correlator = None

        # ── Assemble report ───────────────────────────────────────────
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
            # v2.3: session correlation block
            "session_correlation": session_correlation,
            "legal_reference": {
                "investigation_ref": "CIRS-20260331-141",
                "acma_ref":          "ACMA-ENQ-1851DVJH04",
                "telstra_complaint": "128653446",
                "tio_ref":           "2026-03-04898",
                "applicable_law": [
                    "Radiocommunications Act 1992 (Cth) s.189",
                    "Telecommunications (Interception and Access) Act 1979 (Cth)",
                    "Privacy Act 1988 (Cth)",
                    "Criminal Code Act 1995 (Cth) - Div 477 "
                    "(Unauthorised access/modification)",
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

    # ─────────────────────────────────────────────────────────────────
    # Rich output
    # ─────────────────────────────────────────────────────────────────

    def _print_rich(self, report: dict):
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
                f"[{SEVERITY_COLOURS.get(k,'white')}]{k}: {v}"
                f"[/{SEVERITY_COLOURS.get(k,'white')}]"
                for k, v in sorted(
                    summary["severity_breakdown"].items(),
                    key=lambda x: SEVERITY_ORDER.get(x[0], 0),
                    reverse=True,
                )
            )
            c.print(f"  Severity: {breakdown}")

        # ── Hardware candidates ───────────────────────────────────────
        if report.get("hardware_candidates"):
            c.print()
            c.print("[bold yellow]◆ HARDWARE CANDIDATES[/bold yellow]")
            for hw in report["hardware_candidates"]:
                conf = hw.get("confidence", "?")
                sev_col = SEVERITY_COLOURS.get(hw.get("severity", "HIGH"))
                c.print(f"  [{sev_col}][{conf}] {hw['hardware']}[/{sev_col}]")
                c.print(f"       {hw['notes'][:120]}")

        # ── Techniques ───────────────────────────────────────────────
        if summary.get("techniques_detected"):
            c.print()
            c.print("[bold]Techniques Detected:[/bold]")
            for t in summary["techniques_detected"][:10]:
                c.print(f"  • {t}")

        # ── v2.3: Session correlation ─────────────────────────────────
        if self._correlator and (
            self._correlator.parallel_pairs or
            self._correlator.timestamp_pairs
        ):
            corr_text = self._correlator.render_text()
            c.print()
            c.print(Panel(
                corr_text,
                title="[bold cyan]SESSION OVERLAP CORRELATION[/bold cyan]",
                border_style="cyan",
                padding=(0, 1),
            ))

        # ── Findings ─────────────────────────────────────────────────
        c.print()
        c.print("[bold]" + "═" * 60 + "[/bold]")
        c.print("[bold]DETAILED FINDINGS[/bold]")
        c.print("[bold]" + "═" * 60 + "[/bold]")

        for i, finding in enumerate(report["findings"], 1):
            sev    = finding.get("severity", "INFO")
            conf   = finding.get("confidence", "SUSPECTED")
            colour = SEVERITY_COLOURS.get(sev, "white")
            symbol = CONFIDENCE_SYMBOLS.get(conf, "?")

            c.print()
            c.print(Panel(
                self._format_finding_rich(finding),
                title=(
                    f"[{colour}][{i}] {sev} | {symbol} {conf} — "
                    f"{finding.get('title', finding.get('description', finding.get('label', 'Unknown')))}[/{colour}]"
                ),
                border_style=colour.replace("bold ", ""),
                padding=(0, 1),
            ))

        # ── Priority actions ──────────────────────────────────────────
        critical = [f for f in report["findings"] if f.get("severity") == "CRITICAL"]
        if critical:
            c.print()
            c.print(Panel(
                self._format_top_actions(critical),
                title="[bold red]PRIORITY ACTIONS[/bold red]",
                border_style="red",
            ))

        c.print()
        c.print(
            f"[dim]Report generated: {report['generated_at']} | "
            f"Analysis time: {report['analysis_duration_seconds']}s[/dim]"
        )

    def _format_finding_rich(self, finding: dict) -> str:
        lines = []

        # RRCPeriodicityDetector uses a non-standard structure — synthesize display
        if finding.get("type") == "rrc_periodicity" or finding.get("finding_type") == "rrc_periodicity":
            lines.append(finding.get("message", ""))
            lines.append(f"\n[bold]Technique:[/bold] Metronomic RRCConnectionRelease — timed measurement sweep")
            lines.append(f"[bold]Spec:[/bold] 3GPP TS 36.331 §5.3.8")
            lines.append(f"[bold]Hardware:[/bold] Harris HailStorm / srsRAN — timer signature match")
            lines.append("\n[bold]Evidence:[/bold]")
            lines.append(f"  Mean cycle: {finding.get('mean_interval_s', '?')}s")
            lines.append(f"  Std deviation: {finding.get('std_dev_ms', '?')}ms")
            lines.append(f"  Matching intervals: {finding.get('matching_intervals', '?')} / {finding.get('total_intervals', '?')}")
            lines.append(f"  Total releases: {finding.get('total_releases', '?')}")
            lines.append(f"  Machine precision: {finding.get('machine_precision', '?')}")
            lines.append(f"  Profile: {finding.get('profile_hint', '?')}")
            lines.append("\n[bold]Action:[/bold]")
            lines.append("  Document RRC release cycle as evidence of timed measurement sweep.")
            lines.append("  Cross-reference with RRCConnectionRelease timing for composite signature.")
            lines.append("  Include in VicPol USB evidence package.")
            return "\n".join(lines)

        lines.append(finding.get("description", finding.get("message", "")))

        if finding.get("technique"):
            lines.append(f"\n[bold]Technique:[/bold] {finding['technique']}")
        if finding.get("spec_reference") or finding.get("spec_ref"):
            lines.append(f"[bold]Spec:[/bold] {finding.get('spec_reference') or finding.get('spec_ref')}")
        if finding.get("hardware_hint"):
            lines.append(f"[bold]Hardware:[/bold] {finding['hardware_hint']}")

        evidence = finding.get("evidence", [])
        if evidence:
            lines.append("\n[bold]Evidence:[/bold]")
            # v2.3: do not cap cross-carrier evidence blocks — they contain
            # pinned timestamp pairs that must not be truncated.
            is_cross_carrier = "cross_carrier" in (
                finding.get("technique", "") + finding.get("title", "")
            ).lower()
            max_ev = (
                len(evidence)
                if is_cross_carrier
                else self.cfg.get("output", {}).get("max_evidence_lines", 10)
            )
            for e in evidence[:max_ev]:
                lines.append(f"  [dim]{e}[/dim]")
            if len(evidence) > max_ev:
                lines.append(
                    f"  [dim]... and {len(evidence) - max_ev} more "
                    f"(see JSON report)[/dim]"
                )

        if finding.get("recommended_action") or finding.get("action"):
            lines.append(
                f"\n[bold]Action:[/bold]\n{finding.get('recommended_action') or finding.get('action', '')}"
            )

        return "\n".join(lines)

    def _format_top_actions(self, critical_findings: list) -> str:
        lines = ["Take these actions immediately:\n"]
        for i, f in enumerate(critical_findings[:5], 1):
            action = f.get("recommended_action", "Preserve evidence.")
            first_line = action.split("\n")[0]
            lines.append(f"{i}. [{f['title']}]\n   {first_line}")
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────
    # Plain text fallback (no rich)
    # ─────────────────────────────────────────────────────────────────

    def _print_plain(self, report: dict):
        summary = report["summary"]
        print(f"\n{'='*62}")
        print(f"THREAT LEVEL: {summary['threat_level']}")
        print(
            f"Findings: {summary['total_findings']} | "
            f"Events: {summary['total_events_analyzed']}"
        )
        print(f"{'='*62}")

        for i, finding in enumerate(report["findings"], 1):
            print(f"\n[{i}] {finding.get('severity','?')} | "
                  f"{finding.get('confidence','?')}")
            print(f"    {finding.get('title', finding.get('description', finding.get('label', 'Unknown')))}")
            print(f"    {finding.get('description','')[:200]}")
            for ev in finding.get("evidence", [])[:5]:
                print(f"    EVIDENCE: {ev}")
            if finding.get("recommended_action") or finding.get("action"):
                print(
                    f"    ACTION: "
                    f"{finding['recommended_action'].split(chr(10))[0]}"
                )

        # v2.3: plain text session correlation
        if self._correlator and (
            self._correlator.parallel_pairs or
            self._correlator.timestamp_pairs
        ):
            print(self._correlator.render_text())

        if report.get("hardware_candidates"):
            print(f"\n{'='*62}")
            print("HARDWARE CANDIDATES:")
            for hw in report["hardware_candidates"]:
                print(f"  [{hw['confidence']}] {hw['hardware']}")

        print(f"\nGenerated: {report['generated_at']}")