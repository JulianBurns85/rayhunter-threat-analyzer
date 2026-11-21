#!/usr/bin/env python3
"""
OperationalProfileSynthesiser — Consolidated operational intelligence summary.

Takes accumulated findings and corpus events and synthesises a single
operational profile finding without hardcoded claims or zero-count filler lines.
"""

from datetime import datetime, timezone
import os
import re
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding

_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class OperationalProfileSynthesiser(BaseDetector):
    """
    Synthesises accumulated detector findings and event metrics into a
    single operational profile finding.
    """

    name = "OperationalProfileSynthesiser"
    description = "Operational profile synthesis — consolidated intelligence product"

    KNOWN_FACTS = {
        "subject_address":     "74 Prendergast Avenue, Cranbourne East VIC 3977",
        "earliest_detection":  "2026-01-23",
        "hardware_primary":    "Multi-carrier LTE/GSM surveillance platform",
        "hardware_confidence": "PROBABLE",
        "carrier_telstra":     "505-01 TAC=12385",
        "carrier_vodafone":    "505-03 TAC=30336",
        "rogue_cids_telstra":  ["137713155", "137713165", "137713175", "137713195"],
        "rogue_cids_vodafone": ["8666381", "8666391", "8666411"],
        "acma_ref":            "ENQ-1851DVJH04",
        "vicpol_refs":         ["CIRS-20260331-141", "CIRS-20260413-6"],
        "afp_referral":        "May 2026",
        "tio_ref":             "2026-03-04898",
        "operator_hours":      "10:00-18:00 AEST Monday-Friday",
        "operator_sleep":      "00:00-10:00 AEST",
    }

    def set_findings(self, findings: List[Dict]) -> None:
        """Receive accumulated findings from all other detectors."""
        self._all_findings = list(findings or [])

    def _count_from_findings(self, keyword: str) -> int:
        """Pull confirmed counts from existing findings by keyword."""
        if not hasattr(self, "_all_findings"):
            return 0
        kw = keyword.lower()
        for f in self._all_findings:
            title = str(f.get("title", "")).lower()
            desc = str(f.get("description", "")).lower()
            if kw in title or kw in desc:
                if "event_count" in f and f["event_count"] is not None:
                    try:
                        return int(f["event_count"])
                    except (ValueError, TypeError):
                        pass
                nums = re.findall(r"(\d+)\s*(?:confirmed|event|injection|harvest|tracking)", desc)
                if nums:
                    return int(nums[0])
        return 0

    def _derive_severity_and_confidence(self) -> tuple[str, str]:
        findings = getattr(self, "_all_findings", None) or []
        if not findings:
            return "LOW", "PROBABLE"

        max_sev = "LOW"
        confirmed_count = 0
        detectors = set()

        for f in findings:
            sev = str(f.get("severity") or "LOW").upper()
            if _SEV_RANK.get(sev, 1) > _SEV_RANK.get(max_sev, 1):
                max_sev = sev
            if str(f.get("confidence") or "").upper() == "CONFIRMED":
                confirmed_count += 1
            det = f.get("detector") or f.get("source")
            if det:
                detectors.add(str(det))

        # Require corroboration across multiple sources/detectors for CONFIRMED
        if confirmed_count >= 1 and len(detectors) >= 2:
            conf = "CONFIRMED"
        else:
            conf = "PROBABLE"

        return max_sev, conf

    def analyze(self, events: List[Dict]) -> List[Dict]:
        total_events = len(events)
        ts_all = sorted([
            ts for e in events if (ts := self._get_ts(e)) is not None
        ])

        if not ts_all:
            return []

        span_days = (ts_all[-1] - ts_all[0]) / 86400.0
        start_dt = datetime.fromtimestamp(ts_all[0], tz=timezone.utc)
        end_dt = datetime.fromtimestamp(ts_all[-1], tz=timezone.utc)

        all_findings = getattr(self, "_all_findings", None) or []

        def _extract_count(keyword: str, fallback_keywords: Optional[List[str]] = None) -> int:
            terms = [keyword.lower()] + [k.lower() for k in (fallback_keywords or [])]
            for f in all_findings:
                title = str(f.get("title", "")).lower()
                desc = str(f.get("description", "")).lower()
                if any(t in title or t in desc for t in terms):
                    if "event_count" in f and f["event_count"] is not None:
                        try:
                            return int(f["event_count"])
                        except (ValueError, TypeError):
                            pass
                    nums = re.findall(r"(\d[\d,]*)\s*(?:injected|confirmed|event|harvest)", desc)
                    if nums:
                        return int(nums[0].replace(",", ""))
            return 0

        handovers = _extract_count("handover inject", ["mobilitycontrolinfo"])
        imsi_events = _extract_count("imsi harvest", ["identity request", "imsi catcher"])
        prose = _extract_count("prose", ["proximity tracking", "reportproximityconfig"])

        releases = sum(
            1 for e in events
            if "rrcconnectionrelease" in str(e.get("message_type", "") or e.get("msg_type", "")).lower()
        )

        all_rogue = set(
            self.KNOWN_FACTS["rogue_cids_telstra"]
            + self.KNOWN_FACTS["rogue_cids_vodafone"]
        )
        observed_rogue = {
            cid for e in events
            if (cid := str(e.get("cell_id") or e.get("cid") or "")) in all_rogue
        }

        severity, confidence = self._derive_severity_and_confidence()

        evidence: List[str] = [
            "=" * 70,
            "  OPERATIONAL SURVEILLANCE PROFILE",
            "=" * 70,
            f"Events analysed: {total_events:,} across {span_days:.1f} days "
            f"({start_dt.strftime('%Y-%m-%d')} -> {end_dt.strftime('%Y-%m-%d')})",
            f"Prior findings evaluated: {len(all_findings)}",
        ]

        if handovers > 0:
            evidence.append(f"  - Forced handover injection: {handovers:,} event(s)")
        if imsi_events > 0:
            evidence.append(f"  - IMSI harvest events: {imsi_events:,} event(s)")
        if prose > 0:
            evidence.append(f"  - ProSe proximity tracking: {prose:,} event(s)")
        if releases > 0:
            evidence.append(f"  - RRC release events: {releases:,} event(s)")
        if observed_rogue:
            evidence.append(
                f"  - Rogue CIDs observed: {len(observed_rogue)}/{len(all_rogue)} "
                f"({', '.join(sorted(observed_rogue))})"
            )

        for f in all_findings:
            f_title = f.get("title") or f.get("detector") or "Finding"
            f_sev = str(f.get("severity") or "INFO").upper()
            f_cnt = f.get("event_count")
            if f_cnt is not None:
                evidence.append(f"  - [{f_sev}] {f_title}: {f_cnt} event(s)")
            else:
                evidence.append(f"  - [{f_sev}] {f_title}")

        description = (
            f"Synthesised operational profile from {total_events:,} events across "
            f"{span_days:.1f} days and {len(all_findings)} prior detector finding(s)."
        )

        return [
            make_finding(
                detector=self.name,
                title=f"Operational Profile — {span_days:.0f}d Window ({severity})",
                description=description,
                severity=severity,
                confidence=confidence,
                technique="Operational intelligence synthesis — consolidated findings",
                evidence=evidence,
                hardware_hint="Derived strictly from observed capture events and detector findings.",
                action="Review underlying detector findings and capture evidence before escalation.",
                spec_ref="3GPP TS 24.301 / TS 36.331 / TS 36.300",
            )
        ]

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
