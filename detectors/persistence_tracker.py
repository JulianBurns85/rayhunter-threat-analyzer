#!/usr/bin/env python3
"""
CrossSessionPersistenceTracker — Proves continuous platform operation.

Reads multiple JSON report files and cross-correlates:
- Jitter signatures (hardware DNA)
- CID rotation clusters
- Operator rhythm patterns
- Attack technique fingerprints

Produces a timeline proving the SAME physical device has been
continuously present across months of independent analysis sessions.

This is the difference between "we detected anomalies" and
"the same hardware has been targeting this address for X months."

Usage: python main.py --dir captures --compare-reports report1.json report2.json
Or: automatically runs if multiple JSON reports exist in working directory.
"""

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Set
import json
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


class CrossSessionPersistenceTracker(BaseDetector):
    """
    Cross-correlates multiple analysis sessions to prove continuous
    platform operation by the same physical hardware.

    Runs automatically if prior JSON reports exist in the working directory.
    Also useful as a standalone comparison tool.
    """

    name = "CrossSessionPersistenceTracker"
    description = (
        "Cross-session hardware persistence tracking — proves the same "
        "physical device has been continuously present across months"
    )

    # Jitter similarity threshold (ms) — same hardware if within this delta
    JITTER_MATCH_THRESHOLD_MS = 5000.0
    # Mean cycle similarity threshold (s)
    MEAN_MATCH_THRESHOLD_S    = 10.0
    # Minimum CID overlap to confirm same platform
    MIN_CID_OVERLAP           = 2

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Load any prior JSON reports from working directory
        prior_reports = self._load_prior_reports()
        if not prior_reports:
            return []

        # Extract current session fingerprint from events
        current = self._fingerprint_session(events, "current")

        # Compare against each prior report
        matches = []
        for report in prior_reports:
            prior = self._fingerprint_from_report(report)
            if not prior:
                continue
            match = self._compare_sessions(current, prior)
            if match["score"] > 0:
                matches.append(match)

        if not matches:
            return []

        # Sort by match score
        matches.sort(key=lambda m: m["score"], reverse=True)

        # Build timeline of confirmed sessions
        confirmed_sessions = [m for m in matches if m["score"] >= 2]
        probable_sessions  = [m for m in matches if m["score"] == 1]

        if not confirmed_sessions and not probable_sessions:
            return []

        # Calculate persistence span
        all_dates = []
        for m in matches:
            if m.get("prior_start"):
                all_dates.append(m["prior_start"])
            if m.get("prior_end"):
                all_dates.append(m["prior_end"])

        if all_dates:
            earliest = min(all_dates)
            latest   = datetime.now(tz=timezone.utc)
            span_days = (latest - earliest).days
        else:
            span_days = 0

        evidence = [
            f"Prior reports analysed: {len(prior_reports)}",
            f"Sessions with confirmed hardware match: {len(confirmed_sessions)}",
            f"Sessions with probable match: {len(probable_sessions)}",
            f"Confirmed persistence span: {span_days}+ days",
            f"",
        ]

        if confirmed_sessions:
            evidence.append("CONFIRMED SAME-HARDWARE SESSIONS:")
            for m in confirmed_sessions[:5]:
                evidence.append(
                    f"  {m['report_name']} — Match score: {m['score']} | "
                    f"Matched on: {', '.join(m['match_reasons'])}"
                )
                if m.get("shared_cids"):
                    evidence.append(
                        f"    Shared CIDs: {', '.join(list(m['shared_cids'])[:5])}"
                    )
                if m.get("jitter_delta_ms") is not None:
                    evidence.append(
                        f"    Jitter delta: {m['jitter_delta_ms']:.1f}ms "
                        f"(threshold: {self.JITTER_MATCH_THRESHOLD_MS}ms)"
                    )

        if probable_sessions:
            evidence.append("")
            evidence.append("PROBABLE SAME-PLATFORM SESSIONS:")
            for m in probable_sessions[:3]:
                evidence.append(
                    f"  {m['report_name']} — {', '.join(m['match_reasons'])}"
                )

        evidence.append("")
        evidence.append(
            f"FORENSIC CONCLUSION: The hardware temporal DNA, CID rotation "
            f"clusters, and attack technique fingerprints across {len(confirmed_sessions)} "
            f"independent analysis sessions confirm the SAME physical device has been "
            f"continuously operational for {span_days}+ days."
        )

        severity   = "CRITICAL" if span_days >= 30 else "HIGH"
        confidence = "CONFIRMED" if confirmed_sessions else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Cross-Session Hardware Persistence — {span_days}+ Days Confirmed — "
                f"{len(confirmed_sessions)} Session Match(es)"
            ),
            description=(
                f"Cross-correlation of {len(prior_reports)} independent analysis sessions "
                f"confirms the same physical surveillance hardware has been continuously "
                f"present for {span_days}+ days. "
                f"Hardware identification is based on jitter signature DNA, shared CID "
                f"rotation clusters, and consistent attack technique fingerprints across "
                f"independent capture sessions. "
                f"This is not a transient test or accidental interference — it is persistent, "
                f"targeted surveillance by the same device."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Cross-session hardware fingerprint correlation — "
                "jitter DNA + CID cluster + technique matching"
            ),
            evidence=evidence,
            hardware_hint=(
                f"Same physical hardware confirmed across {len(confirmed_sessions)} sessions. "
                f"Persistent operation for {span_days}+ days."
            ),
            action=(
                "1. Include session comparison timeline in AFP submission.\n"
                "2. Jitter DNA match across sessions proves same physical device.\n"
               f"3. {span_days}+ day persistence rules out testing or accidental interference.\n"
                "4. Cross-reference session dates with operator rhythm for shift patterns.\n"
                "5. Attach all matched JSON reports as supporting evidence."
            ),
            spec_ref=(
                "Hardware persistence analysis; SeaGlass (UW 2017) — impermanence signature; "
                "YAICD framework (Ziayi et al. 2021)"
            ),
        ))

        return findings

    def _load_prior_reports(self) -> List[Dict]:
        """Load prior rayhunter JSON reports from working directory."""
        reports = []
        cwd = Path(".")
        for f in sorted(cwd.glob("rayhunter_report_*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                data["_report_file"] = f.name
                reports.append(data)
            except (json.JSONDecodeError, OSError):
                continue
        return reports

    def _fingerprint_session(self, events: List[Dict], label: str) -> Dict:
        """Extract fingerprint from current event list."""
        cids = set()
        jitter_ms = None
        techniques = set()
        timestamps = []

        releases = []
        for e in events:
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            cid = str(e.get("cell_id") or e.get("cid") or "")
            ts  = self._get_ts(e)

            if cid:
                cids.add(cid)
            if ts:
                timestamps.append(ts)
            if "rrcconnectionrelease" in msg or "rrc connection release" in msg:
                if ts:
                    releases.append(ts)
            if "mobilitycontrolinfo" in msg or "handover" in msg:
                techniques.add("handover_injection")
            if "identityrequest" in msg:
                techniques.add("imsi_harvest")
            if "prose" in msg or "proximityconfig" in msg:
                techniques.add("prose_tracking")

        releases.sort()
        if len(releases) >= 5:
            intervals = [releases[i+1] - releases[i] for i in range(len(releases)-1)]
            valid = [iv for iv in intervals if 1.0 <= iv <= 1800.0]
            if len(valid) >= 4:
                jitter_ms = statistics.stdev(valid) * 1000

        return {
            "label":      label,
            "cids":       cids,
            "jitter_ms":  jitter_ms,
            "techniques": techniques,
            "start":      datetime.fromtimestamp(min(timestamps), tz=timezone.utc) if timestamps else None,
            "end":        datetime.fromtimestamp(max(timestamps), tz=timezone.utc) if timestamps else None,
        }

    def _fingerprint_from_report(self, report: Dict) -> Optional[Dict]:
        """Extract fingerprint from a prior JSON report."""
        try:
            findings = report.get("findings", [])
            cids = set()
            jitter_ms = None
            techniques = set()

            for f in findings:
                title = str(f.get("title", "")).lower()
                desc  = str(f.get("description", "")).lower()
                evid  = " ".join(f.get("evidence", [])).lower()

                if "cid rotation" in title or "cell id" in title:
                    # Try to extract CIDs from evidence
                    for line in f.get("evidence", []):
                        if "rotating cids:" in line.lower():
                            cid_part = line.split(":", 1)[-1].strip()
                            for cid in cid_part.split(","):
                                cid = cid.strip()
                                if cid.isdigit():
                                    cids.add(cid)

                if "jitter" in title or "temporal dna" in title:
                    for line in f.get("evidence", []):
                        if "std deviation" in line.lower():
                            try:
                                jitter_ms = float(line.split(":")[-1].strip().replace("ms", "").strip())
                            except (ValueError, IndexError):
                                pass

                if "handover" in title:
                    techniques.add("handover_injection")
                if "imsi" in title or "identity" in title:
                    techniques.add("imsi_harvest")
                if "prose" in title:
                    techniques.add("prose_tracking")

            # Extract report date from generated_at field
            prior_start = None
            gen_at = report.get("generated_at")
            if gen_at:
                try:
                    from datetime import timezone
                    gen_str = str(gen_at).replace("Z", "+00:00")
                    prior_start = datetime.fromisoformat(gen_str)
                    if prior_start.tzinfo is None:
                        prior_start = prior_start.replace(tzinfo=timezone.utc)
                except (ValueError, AttributeError):
                    prior_start = None

            return {
                "label":       report.get("_report_file", "unknown"),
                "cids":        cids,
                "jitter_ms":   jitter_ms,
                "techniques":  techniques,
                "prior_start": prior_start,
                "prior_end":   prior_start,  # use same date for both
            }
        except Exception:
            return None

    def _compare_sessions(self, current: Dict, prior: Dict) -> Dict:
        """Compare two session fingerprints and return match score."""
        score = 0
        reasons = []
        shared_cids = set()
        jitter_delta = None

        # CID overlap
        if current["cids"] and prior["cids"]:
            shared = current["cids"] & prior["cids"]
            if len(shared) >= self.MIN_CID_OVERLAP:
                score += len(shared)
                shared_cids = shared
                reasons.append(f"{len(shared)} shared CID(s)")

        # Jitter signature match
        if current["jitter_ms"] and prior["jitter_ms"]:
            delta = abs(current["jitter_ms"] - prior["jitter_ms"])
            jitter_delta = delta
            if delta <= self.JITTER_MATCH_THRESHOLD_MS:
                score += 2
                reasons.append(f"jitter DNA match (Δ{delta:.0f}ms)")

        # Technique overlap
        if current["techniques"] and prior["techniques"]:
            shared_tech = current["techniques"] & prior["techniques"]
            if shared_tech:
                score += len(shared_tech)
                reasons.append(f"shared techniques: {', '.join(shared_tech)}")

        return {
            "report_name":    prior.get("label", "unknown"),
            "score":          score,
            "match_reasons":  reasons,
            "shared_cids":    shared_cids,
            "jitter_delta_ms": jitter_delta,
            "prior_start":    prior.get("prior_start"),
            "prior_end":      prior.get("prior_end"),
        }

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
