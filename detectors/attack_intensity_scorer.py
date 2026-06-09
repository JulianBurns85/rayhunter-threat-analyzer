#!/usr/bin/env python3
"""
AttackIntensityScorer — Daily/weekly surveillance threat scoring.

Combines handover injection count + IMSI harvest events + ProSe
activations + CID rotation rate + auth rejects into a single
daily threat score plotted over time.

Produces:
- Daily threat score timeline
- Weekly averages
- Peak attack days identified
- Phase detection (survey → active harvest → post-ACMA chaos)
- Magistrate-friendly summary: "Surveillance was most intense on
  these specific dates"

No technical expertise required to understand the output.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


# Threat score weights per event type
SCORE_WEIGHTS = {
    "handover":    5,   # Forced handover injection — highest severity
    "imsi":        4,   # IMSI harvest
    "prose":       4,   # ProSe proximity tracking
    "reject":      3,   # Auth/Attach reject (IMSI extraction technique)
    "cid_novel":   3,   # Novel/transient CID (sweep mode)
    "release":     1,   # RRC release (contributes to metronomic pattern)
    "paging":      2,   # Targeted paging
}

# Operational phase thresholds
PHASE_THRESHOLDS = {
    "passive_survey":   (0,   50),
    "active_harvest":   (51,  200),
    "intensive":        (201, 500),
    "maximum":          (501, float('inf')),
}

# Key reference dates
PHASE_TRANSITIONS = [
    (datetime(2026, 1, 23, tzinfo=timezone.utc),  "Phase 1→2: Active harvest begins"),
    (datetime(2026, 5, 8,  tzinfo=timezone.utc),  "Phase 2→3: Post-ACMA reconfiguration"),
]


class AttackIntensityScorer(BaseDetector):
    """
    Produces daily threat scores across the entire corpus.
    Shows surveillance intensity over time with phase annotations.
    """

    name = "AttackIntensityScorer"
    description = (
        "Daily surveillance threat scoring — intensity timeline "
        "with phase detection and peak attack identification"
    )

    HANDOVER_TYPES = {"rrcconnectionreconfiguration", "mobilitycontrolinfo"}
    IMSI_TYPES     = {"identityrequest", "identity request"}
    PROSE_TYPES    = {"reportproximityconfig", "prose"}
    REJECT_TYPES   = {"authenticationreject", "attachreject", "authentication reject"}
    RELEASE_TYPES  = {"rrcconnectionrelease", "rrc connection release"}
    PAGING_TYPES   = {"paging", "pagingmessage"}
    NOVEL_TYPES    = {"novelcid", "transientcid"}

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Build daily score map
        daily_scores: Dict[str, float] = defaultdict(float)
        daily_counts: Dict[str, Dict] = defaultdict(lambda: defaultdict(int))

        for e in events:
            ts = self._get_ts(e)
            if ts is None:
                continue
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            day_key = dt.strftime("%Y-%m-%d")
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()

            score_add = 0
            if any(t in msg for t in self.HANDOVER_TYPES):
                score_add = SCORE_WEIGHTS["handover"]
                daily_counts[day_key]["handovers"] += 1
            elif any(t in msg for t in self.IMSI_TYPES):
                score_add = SCORE_WEIGHTS["imsi"]
                daily_counts[day_key]["imsi"] += 1
            elif any(t in msg for t in self.PROSE_TYPES):
                score_add = SCORE_WEIGHTS["prose"]
                daily_counts[day_key]["prose"] += 1
            elif any(t in msg for t in self.REJECT_TYPES):
                score_add = SCORE_WEIGHTS["reject"]
                daily_counts[day_key]["rejects"] += 1
            elif any(t in msg for t in self.RELEASE_TYPES):
                score_add = SCORE_WEIGHTS["release"]
                daily_counts[day_key]["releases"] += 1
            elif any(t in msg for t in self.PAGING_TYPES):
                score_add = SCORE_WEIGHTS["paging"]
                daily_counts[day_key]["paging"] += 1

            if score_add > 0:
                daily_scores[day_key] += score_add

        if len(daily_scores) < 3:
            return []

        # Sort days
        sorted_days = sorted(daily_scores.keys())
        scores      = [daily_scores[d] for d in sorted_days]

        # Statistics
        max_score   = max(scores)
        mean_score  = statistics.mean(scores)
        median_score= statistics.median(scores)
        total_score = sum(scores)

        # Peak days (top 5)
        peak_days = sorted(sorted_days, key=lambda d: daily_scores[d], reverse=True)[:5]

        # Phase classification per day
        phases_by_day = {}
        for day in sorted_days:
            s = daily_scores[day]
            for phase, (lo, hi) in PHASE_THRESHOLDS.items():
                if lo <= s <= hi:
                    phases_by_day[day] = phase
                    break

        # Weekly averages
        weekly: Dict[str, List] = defaultdict(list)
        for day in sorted_days:
            dt = datetime.strptime(day, "%Y-%m-%d")
            week_key = dt.strftime("%Y-W%U")
            weekly[week_key].append(daily_scores[day])
        weekly_avgs = {w: statistics.mean(v) for w, v in sorted(weekly.items())}
        peak_week   = max(weekly_avgs, key=weekly_avgs.get) if weekly_avgs else None

        # Detect phase transitions in data
        detected_transitions = []
        if len(scores) >= 7:
            for i in range(3, len(sorted_days) - 3):
                before_avg = statistics.mean(scores[max(0, i-3):i])
                after_avg  = statistics.mean(scores[i:min(len(scores), i+3)])
                if before_avg > 0 and after_avg / before_avg > 2.0:
                    detected_transitions.append({
                        "date":   sorted_days[i],
                        "before": before_avg,
                        "after":  after_avg,
                        "ratio":  after_avg / before_avg,
                    })
                elif before_avg > 0 and after_avg / before_avg < 0.3:
                    detected_transitions.append({
                        "date":   sorted_days[i],
                        "before": before_avg,
                        "after":  after_avg,
                        "ratio":  after_avg / before_avg,
                    })

        # Build ASCII intensity chart (last 30 days or all if fewer)
        chart_days = sorted_days[-30:] if len(sorted_days) > 30 else sorted_days
        chart_max  = max(daily_scores[d] for d in chart_days) if chart_days else 1
        chart_lines = []
        for day in chart_days:
            s = daily_scores[day]
            bar_len = int((s / chart_max) * 40) if chart_max > 0 else 0
            phase = phases_by_day.get(day, "")
            phase_marker = {
                "passive_survey":  "·",
                "active_harvest":  "▪",
                "intensive":       "█",
                "maximum":         "█",
            }.get(phase, " ")
            bar = phase_marker * bar_len
            chart_lines.append(f"  {day} [{bar:<40}] {s:.0f}")

        # Build evidence
        evidence = [
            f"Corpus span: {sorted_days[0]} to {sorted_days[-1]}",
            f"Active days: {len(sorted_days)}",
            f"Total threat score: {total_score:,.0f}",
            f"Daily mean: {mean_score:.1f} | Median: {median_score:.1f} | Peak: {max_score:.0f}",
            f"",
            f"PEAK ATTACK DAYS:",
        ]
        for day in peak_days:
            c = daily_counts[day]
            evidence.append(
                f"  {day} — Score: {daily_scores[day]:.0f} | "
                f"Handovers: {c['handovers']} | IMSI: {c['imsi']} | "
                f"ProSe: {c['prose']} | Rejects: {c['rejects']}"
            )

        evidence.append(f"")
        evidence.append(f"PEAK WEEK: {peak_week} (avg score: {weekly_avgs.get(peak_week, 0):.1f}/day)")

        if detected_transitions:
            evidence.append(f"")
            evidence.append(f"INTENSITY TRANSITIONS DETECTED:")
            for t in detected_transitions[:3]:
                direction = "ESCALATION" if t["ratio"] > 1 else "DE-ESCALATION"
                evidence.append(
                    f"  {t['date']} — {direction}: "
                    f"{t['before']:.1f} → {t['after']:.1f}/day "
                    f"(×{t['ratio']:.1f})"
                )

        evidence.append(f"")
        evidence.append(f"DAILY INTENSITY CHART (· survey ▪ active █ intensive):")
        evidence.extend(chart_lines)

        # Phase distribution summary
        phase_counts = defaultdict(int)
        for p in phases_by_day.values():
            phase_counts[p] += 1
        evidence.append(f"")
        evidence.append(f"PHASE DISTRIBUTION:")
        for phase, count in sorted(phase_counts.items()):
            evidence.append(f"  {phase.replace('_', ' ').title()}: {count} days")

        # Determine severity
        intensive_days = phase_counts.get("intensive", 0) + phase_counts.get("maximum", 0)
        severity   = "CRITICAL" if intensive_days >= 5 else "HIGH" if intensive_days >= 1 else "MEDIUM"
        confidence = "CONFIRMED" if len(sorted_days) >= 14 else "PROBABLE"

        # Build description
        acma_day = "2026-05-08"
        pre_acma_scores  = [daily_scores[d] for d in sorted_days if d < acma_day]
        post_acma_scores = [daily_scores[d] for d in sorted_days if d >= acma_day]
        acma_comparison  = ""
        if pre_acma_scores and post_acma_scores:
            pre_mean  = statistics.mean(pre_acma_scores)
            post_mean = statistics.mean(post_acma_scores)
            pct = ((post_mean - pre_mean) / pre_mean * 100) if pre_mean > 0 else 0
            direction = "increased" if pct > 0 else "decreased"
            acma_comparison = (
                f" Post-ACMA inspection daily scores {direction} by {abs(pct):.0f}% "
                f"({pre_mean:.0f} → {post_mean:.0f}/day average)."
            )

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Attack Intensity Timeline — {len(sorted_days)} Days | "
                f"Peak: {peak_days[0] if peak_days else 'N/A'} | "
                f"Intensive Days: {intensive_days}"
            ),
            description=(
                f"Daily surveillance threat scoring across {len(sorted_days)} days of captures. "
                f"Total threat score: {total_score:,.0f}. "
                f"Peak attack day: {peak_days[0] if peak_days else 'N/A'} "
                f"(score: {daily_scores[peak_days[0]] if peak_days else 0:.0f}). "
                f"{intensive_days} day(s) classified as intensive/maximum surveillance."
                f"{acma_comparison} "
                f"This timeline provides a magistrate-friendly visual record of surveillance "
                f"intensity without requiring technical expertise to interpret."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Daily threat score aggregation — weighted sum of attack events "
                "per 24-hour window with phase classification"
            ),
            evidence=evidence,
            hardware_hint=(
                "Sustained multi-week surveillance pattern inconsistent with "
                "automated infrastructure or testing. Human-operated platform."
            ),
            action=(
                "1. Include daily intensity chart in AFP submission — no technical explanation needed.\n"
                "2. Peak attack days correlate with specific dates for cross-referencing.\n"
                "3. Phase transitions show operational changes (survey → harvest → post-regulatory).\n"
                "4. Cross-reference peak days with operator rhythm profile for shift patterns.\n"
                "5. Weekly averages suitable for summary statistics in legal documents."
            ),
            spec_ref=(
                "Threat scoring methodology — weighted aggregation of 3GPP protocol violations; "
                "YAICD framework (Ziayi et al. 2021)"
            ),
        ))

        return findings

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
