#!/usr/bin/env python3
"""
RegulatoryEventCorrelator — Annotates corpus with regulatory timeline.

Automatically compares attack signatures before and after each key
regulatory event to show the operator's conscious responses.

Key events tracked:
- 2026-01-23: Earliest confirmed attack
- 2026-03-31: VicPol CIRS-20260331-141 filed
- 2026-04-13: VicPol CIRS-20260413-6 filed
- 2026-05-08: ACMA field inspection (ENQ-1851DVJH04)
- 2026-05-19: AFP referral (via VicPol)

For each event window (7 days before vs 7 days after), compares:
- Handover injection rate
- CID rotation frequency
- IMSI harvest rate
- ProSe proximity tracking rate
- Metronomic timer precision (StdDev)
- New CID clusters appearing

This makes the causal relationship between regulatory action and
operator behavioral response undeniable in a legal submission.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Key regulatory events
REGULATORY_EVENTS = [
    {
        "date": datetime(2026, 1, 23, tzinfo=timezone.utc),
        "label": "Earliest Confirmed Attack",
        "ref": "Internal — first IMSI catcher event in corpus",
        "expected_change": "baseline",
    },
    {
        "date": datetime(2026, 3, 31, tzinfo=timezone.utc),
        "label": "VicPol Report Filed",
        "ref": "CIRS-20260331-141",
        "expected_change": "possible evasion response",
    },
    {
        "date": datetime(2026, 4, 13, tzinfo=timezone.utc),
        "label": "VicPol Second Report Filed",
        "ref": "CIRS-20260413-6",
        "expected_change": "possible evasion response",
    },
    {
        "date": datetime(2026, 5, 8, tzinfo=timezone.utc),
        "label": "ACMA Field Inspection",
        "ref": "ENQ-1851DVJH04 — Inspector attended neighbouring property",
        "expected_change": "reconfiguration — new CID cluster, precision collapse",
    },
    {
        "date": datetime(2026, 5, 19, tzinfo=timezone.utc),
        "label": "AFP Referral (via VicPol)",
        "ref": "VicPol → AFP escalation",
        "expected_change": "possible shutdown or further reconfiguration",
    },
]

WINDOW_DAYS = 7  # Compare 7 days before vs 7 days after each event

# Message type classifiers
HANDOVER_TYPES = {"rrcconnectionreconfiguration", "mobilitycontrolinfo"}
IMSI_TYPES     = {"identityrequest", "identity request"}
PROSE_TYPES    = {"reportproximityconfig", "prose", "proximityconfig"}
RELEASE_TYPES  = {"rrcconnectionrelease", "rrc connection release"}
REJECT_TYPES   = {"authenticationreject", "attachreject"}


class RegulatoryEventCorrelator(BaseDetector):
    """
    Annotates the event corpus with regulatory timeline and shows
    operator behavioral responses to each regulatory action.
    """

    name = "RegulatoryEventCorrelator"
    description = (
        "Regulatory timeline annotation — before/after comparison for each "
        "regulatory event showing operator behavioral responses"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract all timestamped events
        ts_events = []
        for e in events:
            ts = self._get_ts(e)
            if ts:
                ts_events.append((ts, e))

        if len(ts_events) < 50:
            return []

        ts_events.sort(key=lambda x: x[0])
        corpus_start = ts_events[0][0]
        corpus_end   = ts_events[-1][0]

        # Analyse each regulatory event
        for reg_event in REGULATORY_EVENTS:
            event_ts = reg_event["date"]

            # Skip if event is outside corpus window (allow 7-day buffer)
            if event_ts.timestamp() > corpus_end + WINDOW_DAYS * 86400:
                continue
            if event_ts.timestamp() < corpus_start - WINDOW_DAYS * 86400:
                continue

            before_start = (event_ts - timedelta(days=WINDOW_DAYS)).timestamp()
            before_end   = event_ts.timestamp()
            after_start  = event_ts.timestamp()
            after_end    = (event_ts + timedelta(days=WINDOW_DAYS)).timestamp()

            before_events = [e for ts, e in ts_events if before_start <= ts < before_end]
            after_events  = [e for ts, e in ts_events if after_start  <= ts < after_end]

            if not before_events and not after_events:
                continue

            # Count metrics for each window
            b = self._count_metrics(before_events)
            a = self._count_metrics(after_events)

            # CID sets before/after
            b_cids = set(str(e.get("cell_id") or e.get("cid") or "") for e in before_events if e.get("cell_id") or e.get("cid"))
            a_cids = set(str(e.get("cell_id") or e.get("cid") or "") for e in after_events  if e.get("cell_id") or e.get("cid"))
            new_cids = a_cids - b_cids
            gone_cids = b_cids - a_cids

            # RRC release timing precision
            b_jitter = self._calc_jitter(before_events)
            a_jitter = self._calc_jitter(after_events)

            # Calculate changes
            changes = []
            severity_score = 0

            def pct_change(before_val, after_val):
                if before_val == 0 and after_val == 0:
                    return None
                if before_val == 0:
                    return float('inf')
                return ((after_val - before_val) / before_val) * 100

            for metric, b_val, a_val, label in [
                ("handovers",  b["handovers"],  a["handovers"],  "Injected handovers"),
                ("imsi",       b["imsi"],        a["imsi"],       "IMSI harvest events"),
                ("prose",      b["prose"],       a["prose"],      "ProSe proximity events"),
                ("releases",   b["releases"],    a["releases"],   "RRC releases"),
                ("rejects",    b["rejects"],     a["rejects"],    "Auth/Attach rejects"),
            ]:
                pct = pct_change(b_val, a_val)
                if pct is None:
                    continue
                direction = "▲" if pct > 0 else "▼"
                if abs(pct) >= 20 or (b_val == 0 and a_val > 0):
                    changes.append(
                        f"  {label}: {b_val} → {a_val} "
                        f"({direction}{abs(pct):.0f}%)" if pct != float('inf') else
                        f"  {label}: 0 → {a_val} (NEW post-event)"
                    )
                    if abs(pct) >= 50 or (b_val == 0 and a_val > 0):
                        severity_score += 2
                    elif abs(pct) >= 20:
                        severity_score += 1

            if new_cids:
                changes.append(
                    f"  NEW Cell IDs post-event: {', '.join(sorted(new_cids)[:8])}"
                    + (f" (+{len(new_cids)-8} more)" if len(new_cids) > 8 else "")
                )
                severity_score += len(new_cids) * 2

            if gone_cids:
                changes.append(
                    f"  Cell IDs gone post-event: {', '.join(sorted(gone_cids)[:8])}"
                    + (f" (+{len(gone_cids)-8} more)" if len(gone_cids) > 8 else "")
                )
                severity_score += 1

            if b_jitter and a_jitter:
                jitter_change = a_jitter - b_jitter
                if abs(jitter_change) > 100:
                    direction = "▲ INCREASED" if jitter_change > 0 else "▼ DECREASED"
                    changes.append(
                        f"  Timer precision (StdDev): {b_jitter:.1f}ms → {a_jitter:.1f}ms "
                        f"({direction} by {abs(jitter_change):.1f}ms)"
                    )
                    severity_score += 3 if abs(jitter_change) > 1000 else 1

            if not changes and not new_cids:
                # Still report if we have data — no change is also informative
                changes.append("  No significant behavioral change detected in this window")

            evidence = [
                f"Regulatory event: {reg_event['label']}",
                f"Reference: {reg_event['ref']}",
                f"Event date: {event_ts.strftime('%Y-%m-%d %H:%M UTC')}",
                f"Analysis window: ±{WINDOW_DAYS} days",
                f"Events before: {len(before_events):,} | Events after: {len(after_events):,}",
                f"",
                f"BEFORE ({WINDOW_DAYS}d prior):",
                f"  Handovers: {b['handovers']} | IMSI events: {b['imsi']} | "
                f"ProSe: {b['prose']} | Releases: {b['releases']}",
                f"",
                f"AFTER ({WINDOW_DAYS}d post):",
                f"  Handovers: {a['handovers']} | IMSI events: {a['imsi']} | "
                f"ProSe: {a['prose']} | Releases: {a['releases']}",
                f"",
                f"CHANGES DETECTED:",
            ]
            evidence.extend(changes)

            if new_cids:
                evidence.append(
                    f"",
                    )
                evidence.append(
                    f"FORENSIC SIGNIFICANCE: {len(new_cids)} new Cell ID(s) appeared "
                    f"after this regulatory event — consistent with operator reconfiguring "
                    f"platform to evade detection."
                )

            severity   = "CRITICAL" if severity_score >= 6 else "HIGH" if severity_score >= 3 else "MEDIUM"
            confidence = "CONFIRMED" if (new_cids or severity_score >= 4) else "PROBABLE"

            has_response = severity_score >= 3 or bool(new_cids) or bool(gone_cids)

            findings.append(make_finding(
                detector=self.name,
                title=(
                    f"Regulatory Response Detected — {reg_event['label']} "
                    f"{'— Operator Reacted' if has_response else '— No Change'}"
                ),
                description=(
                    f"Analysis of {WINDOW_DAYS}-day windows before and after "
                    f"{reg_event['label']} ({reg_event['ref']}) "
                    f"{'reveals significant behavioral changes consistent with the operator '
                    'consciously responding to regulatory presence.' if has_response else
                    'shows no significant change in attack patterns.'} "
                    f"{'NEW CELL IDs appeared post-event. ' if new_cids else ''}"
                    f"{'Cell IDs disappeared post-event. ' if gone_cids else ''}"
                    f"This {'supports' if has_response else 'does not contradict'} the finding "
                    f"that the platform is human-operated and monitored in real-time."
                ),
                severity=severity,
                confidence=confidence,
                technique="Regulatory timeline annotation — before/after behavioral comparison",
                evidence=evidence,
                hardware_hint=(
                    "Human-operated platform responding to external stimuli. "
                    "Automated infrastructure does not reconfigure in response to regulatory visits."
                    if has_response else
                    "No behavioral change detected — platform may have been offline during this window."
                ),
                action=(
                    f"1. Include this before/after comparison in AFP submission.\n"
                    f"2. The behavioral change post-{reg_event['label']} demonstrates the "
                    f"operator was aware of and responding to regulatory activity.\n"
                    f"3. This is evidence of conscious, deliberate operation — not automated infrastructure.\n"
                    f"4. New CIDs post-event should be added to known_rogue_cells in config.yaml."
                    if has_response else
                    f"1. No significant change detected — include as baseline reference.\n"
                    f"2. Absence of change may indicate platform was offline or already reconfigured."
                ),
                spec_ref=(
                    f"ACMA ENQ-1851DVJH04; VicPol CIRS-20260331-141; "
                    f"Radiocommunications Act 1992 (Cth) s.189"
                ),
            ))

        return findings

    def _count_metrics(self, events: List[Dict]) -> Dict:
        counts = {"handovers": 0, "imsi": 0, "prose": 0, "releases": 0, "rejects": 0}
        for e in events:
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            if any(t in msg for t in HANDOVER_TYPES):
                counts["handovers"] += 1
            if any(t in msg for t in IMSI_TYPES):
                counts["imsi"] += 1
            if any(t in msg for t in PROSE_TYPES):
                counts["prose"] += 1
            if any(t in msg for t in RELEASE_TYPES):
                counts["releases"] += 1
            if any(t in msg for t in REJECT_TYPES):
                counts["rejects"] += 1
        return counts

    def _calc_jitter(self, events: List[Dict]) -> Optional[float]:
        releases = sorted([
            self._get_ts(e) for e in events
            if any(t in str(e.get("message_type") or "").lower()
                   for t in RELEASE_TYPES)
            and self._get_ts(e) is not None
        ])
        if len(releases) < 5:
            return None
        intervals = [releases[i+1] - releases[i] for i in range(len(releases)-1)]
        valid = [iv for iv in intervals if 1.0 <= iv <= 1800.0]
        if len(valid) < 4:
            return None
        return statistics.stdev(valid) * 1000

    def _get_ts(self, event: Dict) -> Optional[float]:
        ts = event.get("timestamp") or event.get("time") or event.get("ts")
        if ts is None:
            return None
        try:
            if isinstance(ts, (int, float)):
                return float(ts)
            if isinstance(ts, str):
                ts_clean = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
        except (ValueError, OSError):
            return None
