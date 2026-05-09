#!/usr/bin/env python3
"""
Report Differ — Compare Two Analysis Runs
==========================================
Shows what changed between two rayhunter_analyzer JSON reports.
Useful for tracking whether surveillance activity increases/decreases
over time, or confirming new evidence vs prior submissions.

Usage:
    python main.py --compare report_a.json report_b.json
"""

import json
from pathlib import Path
from typing import Dict, List, Optional


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _load(path: str) -> Dict:
    """Load a report JSON file."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[ERROR] Could not load {path}: {e}")
        return {}


def _finding_key(f: Dict) -> str:
    """Generate a stable key for a finding."""
    return f"{f.get('detector','')}:{f.get('title','')}"


def diff_reports(path_a: str, path_b: str) -> Dict:
    """
    Compare two report JSON files and return a diff dict.
    path_a = older / baseline report
    path_b = newer / current report
    """
    report_a = _load(path_a)
    report_b = _load(path_b)

    if not report_a or not report_b:
        return {"error": "Could not load one or both reports"}

    sum_a = report_a.get("summary", {})
    sum_b = report_b.get("summary", {})
    find_a = {_finding_key(f): f for f in report_a.get("findings", [])}
    find_b = {_finding_key(f): f for f in report_b.get("findings", [])}

    # New findings (in B but not A)
    new_findings = [
        find_b[k] for k in find_b if k not in find_a
    ]

    # Resolved findings (in A but not B) — good news
    resolved_findings = [
        find_a[k] for k in find_a if k not in find_b
    ]

    # Changed findings (in both, but counts or severity changed)
    changed_findings = []
    for k in find_a:
        if k in find_b:
            fa = find_a[k]
            fb = find_b[k]
            changes = {}
            if fa.get("event_count") != fb.get("event_count"):
                old_c = fa.get("event_count", 0)
                new_c = fb.get("event_count", 0)
                delta = new_c - old_c
                changes["event_count"] = {
                    "old": old_c,
                    "new": new_c,
                    "delta": delta,
                    "direction": "INCREASED" if delta > 0 else "DECREASED",
                }
            if fa.get("severity") != fb.get("severity"):
                changes["severity"] = {
                    "old": fa.get("severity"),
                    "new": fb.get("severity"),
                }
            if fa.get("confidence") != fb.get("confidence"):
                changes["confidence"] = {
                    "old": fa.get("confidence"),
                    "new": fb.get("confidence"),
                }
            if changes:
                changed_findings.append({
                    "finding": fb,
                    "changes": changes,
                })

    # Summary deltas
    summary_delta = {
        "events_analyzed": {
            "old": sum_a.get("total_events_analyzed", 0),
            "new": sum_b.get("total_events_analyzed", 0),
            "delta": sum_b.get("total_events_analyzed", 0) -
                     sum_a.get("total_events_analyzed", 0),
        },
        "confirmed_attacks": {
            "old": sum_a.get("confirmed_attacks", 0),
            "new": sum_b.get("confirmed_attacks", 0),
            "delta": sum_b.get("confirmed_attacks", 0) -
                     sum_a.get("confirmed_attacks", 0),
        },
        "threat_level": {
            "old": sum_a.get("threat_level", "?"),
            "new": sum_b.get("threat_level", "?"),
            "changed": sum_a.get("threat_level") != sum_b.get("threat_level"),
        },
    }

    # New techniques
    tech_a = set(sum_a.get("techniques_detected", []))
    tech_b = set(sum_b.get("techniques_detected", []))
    new_techniques = sorted(tech_b - tech_a)
    resolved_techniques = sorted(tech_a - tech_b)

    diff = {
        "report_a": {
            "path": path_a,
            "generated_at": report_a.get("generated_at", "?"),
        },
        "report_b": {
            "path": path_b,
            "generated_at": report_b.get("generated_at", "?"),
        },
        "summary_delta": summary_delta,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "changed_findings": changed_findings,
        "new_techniques": new_techniques,
        "resolved_techniques": resolved_techniques,
        "overall_assessment": _assess(
            new_findings, resolved_findings, changed_findings, summary_delta
        ),
    }

    return diff


def _assess(new, resolved, changed, summary_delta) -> str:
    """Generate plain-English assessment of the diff."""
    parts = []

    if new:
        sevs = [f.get("severity", "?") for f in new]
        crits = sevs.count("CRITICAL")
        highs = sevs.count("HIGH")
        parts.append(
            f"NEW THREATS: {len(new)} new finding(s) detected"
            + (f" including {crits} CRITICAL" if crits else "")
            + (f", {highs} HIGH" if highs else "")
            + ". Situation has ESCALATED."
        )

    if resolved:
        parts.append(
            f"RESOLVED: {len(resolved)} finding(s) no longer detected "
            f"in current run — may indicate reduced activity or "
            f"different file set."
        )

    events_delta = summary_delta["events_analyzed"]["delta"]
    if events_delta > 0:
        parts.append(
            f"EXPANDED DATASET: {events_delta:+,} additional events analyzed."
        )
    elif events_delta < 0:
        parts.append(
            f"SMALLER DATASET: {events_delta:,} fewer events in new run "
            f"(different --dir scope?)."
        )

    for cf in changed:
        for field, ch in cf["changes"].items():
            if field == "event_count" and abs(ch["delta"]) > 1000:
                parts.append(
                    f"{cf['finding'].get('title','?')}: event count "
                    f"{ch['direction']} by {ch['delta']:+,} "
                    f"({ch['old']:,} → {ch['new']:,})."
                )

    if not parts:
        parts.append("No significant changes detected between reports.")

    return " | ".join(parts)


def print_diff(diff: Dict):
    """Print diff to terminal in readable format."""
    if "error" in diff:
        print(f"[ERROR] {diff['error']}")
        return

    print(f"\n{'='*70}")
    print(f"  REPORT COMPARISON")
    print(f"{'='*70}")
    print(f"  Baseline: {diff['report_a']['path']}")
    print(f"            Generated: {diff['report_a']['generated_at'][:19]}")
    print(f"  Current:  {diff['report_b']['path']}")
    print(f"            Generated: {diff['report_b']['generated_at'][:19]}")
    print()

    sd = diff["summary_delta"]
    ev = sd["events_analyzed"]
    print(f"  Events analyzed: {ev['old']:,} → {ev['new']:,} ({ev['delta']:+,})")
    ca = sd["confirmed_attacks"]
    print(f"  Confirmed attacks: {ca['old']} → {ca['new']} ({ca['delta']:+d})")
    tl = sd["threat_level"]
    changed = " ← CHANGED" if tl["changed"] else ""
    print(f"  Threat level: {tl['old']} → {tl['new']}{changed}")

    if diff["new_findings"]:
        print(f"\n  NEW FINDINGS ({len(diff['new_findings'])}):")
        for f in diff["new_findings"]:
            print(f"    [+] [{f.get('severity','?')}] {f.get('title','?')}")

    if diff["resolved_findings"]:
        print(f"\n  RESOLVED FINDINGS ({len(diff['resolved_findings'])}):")
        for f in diff["resolved_findings"]:
            print(f"    [-] [{f.get('severity','?')}] {f.get('title','?')}")

    if diff["changed_findings"]:
        print(f"\n  CHANGED FINDINGS ({len(diff['changed_findings'])}):")
        for cf in diff["changed_findings"]:
            for field, ch in cf["changes"].items():
                if field == "event_count":
                    print(f"    [~] {cf['finding'].get('title','?')}: "
                          f"count {ch['direction']} {ch['old']:,}→{ch['new']:,}")
                else:
                    print(f"    [~] {cf['finding'].get('title','?')}: "
                          f"{field} {ch['old']}→{ch['new']}")

    if diff["new_techniques"]:
        print(f"\n  NEW TECHNIQUES: {', '.join(diff['new_techniques'])}")
    if diff["resolved_techniques"]:
        print(f"  RESOLVED TECHNIQUES: {', '.join(diff['resolved_techniques'])}")

    print(f"\n  ASSESSMENT: {diff['overall_assessment']}")
    print(f"{'='*70}\n")
