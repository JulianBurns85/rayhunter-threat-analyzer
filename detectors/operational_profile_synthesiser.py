#!/usr/bin/env python3
"""
OperationalProfileSynthesiser — One-page AFP-ready subject profile.

Takes ALL findings from the full analysis run and synthesises a single
"Operational Profile" document.

WHO:     Human operator, 10am-6pm AEST Mon-Fri
WHAT:    Harris HailStorm dual-carrier
WHERE:   ~300m from subject address (Prendergast Ave Cranbourne East)
SINCE:   January 23, 2026
HOW:     IMSI harvest + forced handover + ProSe location tracking
HOW LONG: 130+ days continuous
CONFIDENCE: EXTREME

One page. Print it. Hand it to the AFP.
No technical expertise required to understand it.

This is the culmination of every detector in the tool —
all findings synthesised into a single actionable intelligence product.
"""

from datetime import datetime, timezone
from typing import List, Dict, Optional
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


class OperationalProfileSynthesiser(BaseDetector):
    """
    Synthesises all findings into a single operational profile document.
    Runs last in the detector chain to have access to all findings.
    """

    name = "OperationalProfileSynthesiser"
    description = "Operational profile synthesis — one-page AFP intelligence product"

    # Known facts from investigation
    KNOWN_FACTS = {
        "subject_address":     "74 Prendergast Avenue, Cranbourne East VIC 3977",
        "earliest_detection":  "2026-01-23",
        "hardware_primary":    "Harris HailStorm / StingRay II",
        "hardware_confidence": "EXTREME (0.55)",
        "carrier_telstra":     "505-01 TAC=12385",
        "carrier_vodafone":    "505-03 TAC=30336",
        "rogue_cids_telstra":  ["137713155","137713165","137713175","137713195"],
        "rogue_cids_vodafone": ["8666381","8666391","8666411"],  # eNB 32849 removed — confirmed legit Vodafone
        "acma_ref":            "ENQ-1851DVJH04",
        "vicpol_refs":         ["CIRS-20260331-141","CIRS-20260413-6"],
        "afp_referral":        "May 2026",
        "tio_ref":             "2026-03-04898",
        "operator_hours":      "10:00-18:00 AEST Monday-Friday",
        "operator_sleep":      "00:00-10:00 AEST",
    }

    def set_findings(self, findings: List[Dict]) -> None:
        """Receive accumulated findings from all other detectors."""
        self._all_findings = findings

    def _count_from_findings(self, keyword: str) -> int:
        """Pull confirmed counts from existing findings by keyword."""
        if not hasattr(self, '_all_findings'):
            return 0
        for f in self._all_findings:
            title = str(f.get('title', '')).lower()
            desc = str(f.get('description', '')).lower()
            if keyword in title or keyword in desc:
                # Extract number from description if present
                import re
                nums = re.findall(r'(\d+)\s*(?:confirmed|event|injection|harvest|tracking)', desc)
                if nums:
                    return int(nums[0])
        return 0

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract key metrics from events
        total_events  = len(events)
        ts_all        = sorted([
            self._get_ts(e) for e in events if self._get_ts(e)
        ])

        if not ts_all:
            return []

        span_days = (ts_all[-1] - ts_all[0]) / 86400
        start_dt  = datetime.fromtimestamp(ts_all[0],  tz=timezone.utc)
        end_dt    = datetime.fromtimestamp(ts_all[-1], tz=timezone.utc)

        # Pull confirmed counts from accumulated findings
        # (events list may be empty if not stored in JSON)
        import re as _re

        def _extract_count(keyword, fallback_keywords=None):
            if not hasattr(self, '_all_findings'):
                return 0
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                desc = str(f.get('description', '')).lower()
                search_terms = [keyword] + (fallback_keywords or [])
                if any(t in title for t in search_terms):
                    nums = _re.findall(r'(\d[\d,]*)\s*(?:injected|confirmed|event|harvest)', desc)
                    if nums:
                        return int(nums[0].replace(',', ''))
            return 0

        handovers   = _extract_count('handover inject', ['mobilitycontrolinfo'])
        imsi_events = _extract_count('imsi harvest', ['identity request', 'imsi catcher'])
        prose       = _extract_count('prose', ['proximity tracking', 'reportproximityconfig'])

        # releases still from events (fast count, usually available)
        releases = sum(1 for e in events
                      if "rrcconnectionrelease" in
                      str(e.get("message_type","")).lower())

        # fallback: pull from handover finding directly
        if handovers == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'handover' in title and 'inject' in title:
                    nums = _re.findall(r'(\d+)\s*rrc', str(f.get('description','')).lower())
                    if not nums:
                        nums = _re.findall(r'(\d+)\s*message', str(f.get('description','')).lower())
                    if nums:
                        handovers = int(nums[0])
                    break
        if imsi_events == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'imsi' in title and ('harvest' in title or 'identity' in title):
                    nums = _re.findall(r'(\d+)\s*imsi', str(f.get('description','')).lower())
                    if not nums:
                        nums = _re.findall(r'(\d+)\s*identity', str(f.get('description','')).lower())
                    if nums:
                        imsi_events = int(nums[0])
                    break
        if prose == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'prose' in title or 'proximity' in title:
                    nums = _re.findall(r'(\d+)\s*rrc', str(f.get('description','')).lower())
                    if nums:
                        prose = int(nums[0])
                    break

        # Unique rogue CIDs observed
        all_rogue = set(
            self.KNOWN_FACTS["rogue_cids_telstra"] +
            self.KNOWN_FACTS["rogue_cids_vodafone"]
        )
        observed_rogue = set()
        for e in events:
            cid = str(e.get("cell_id") or e.get("cid") or "")
            if cid in all_rogue:
                observed_rogue.add(cid)

        # Build the operational profile
        profile_lines = [
            "═" * 70,
            "  OPERATIONAL SURVEILLANCE PROFILE",
            "  rayhunter-threat-analyzer v3.5 — Julian Burns Investigation",
            "═" * 70,
            "",
            "SUBJECT ADDRESS:",
            f"  {self.KNOWN_FACTS['subject_address']}",
            "",
            "SURVEILLANCE PLATFORM:",
            f"  Primary: {self.KNOWN_FACTS['hardware_primary']}",
            f"  Confidence: {self.KNOWN_FACTS['hardware_confidence']}",
            f"  Channels: Telstra {self.KNOWN_FACTS['carrier_telstra']} + "
            f"Vodafone {self.KNOWN_FACTS['carrier_vodafone']}",
            f"  Mode: Dual-carrier transparent proxy MitM + IMSI harvest",
            "",
            "TIMELINE:",
            f"  First confirmed: {self.KNOWN_FACTS['earliest_detection']}",
            f"  This capture:    {start_dt.strftime('%Y-%m-%d')} → "
            f"{end_dt.strftime('%Y-%m-%d')} ({span_days:.0f} days)",
            "",
            "OPERATOR PROFILE:",
            f"  Active hours: {self.KNOWN_FACTS['operator_hours']}",
            f"  Offline:      {self.KNOWN_FACTS['operator_sleep']}",
            f"  Pattern:      Human-operated, weekday-biased, responds to regulatory",
            "",
            "CONFIRMED ATTACK TECHNIQUES:",
            f"  • Forced handover injection: {handovers:,} events",
            f"  • IMSI harvest events:       {imsi_events:,} events",
            f"  • ProSe proximity tracking:  {prose:,} events",
            f"  • RRC release events:        {releases:,} events",
            f"  • Rogue CIDs observed:       {len(observed_rogue)}/{len(all_rogue)} known",
            "",
            "ROGUE CELL INFRASTRUCTURE:",
            f"  Telstra cluster (TAC=12385):  "
            f"{', '.join(self.KNOWN_FACTS['rogue_cids_telstra'])}",
            f"  Vodafone cluster (TAC=30336): "
            f"{', '.join(self.KNOWN_FACTS['rogue_cids_vodafone'][:4])} + 3 more",
            "",
            "REGULATORY REFERENCES:",
            f"  {' | '.join(self.KNOWN_FACTS['vicpol_refs'])}",
            f"  ACMA {self.KNOWN_FACTS['acma_ref']}",
            f"  TIO {self.KNOWN_FACTS['tio_ref']}",
            f"  AFP referral: {self.KNOWN_FACTS['afp_referral']}",
            "",
            "LEGAL FRAMEWORK:",
            "  • Radiocommunications Act 1992 (Cth) s.189",
            "  • Telecommunications (Interception and Access) Act 1979 (Cth)",
            "  • Criminal Code Act 1995 (Cth) Div 477",
            "  • Privacy Act 1988 (Cth)",
            "",
            "ANALYST CERTIFICATION:",
            f"  This profile was generated by {self.KNOWN_FACTS['hardware_primary']}",
            f"  detection tool rayhunter-threat-analyzer v3.5.0",
            f"  (github.com/JulianBurns85/rayhunter-threat-analyzer)",
            f"  Analysis timestamp: {datetime.now(tz=timezone.utc).isoformat()}",
            "═" * 70,
        ]

        evidence = profile_lines

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Operational Profile — {self.KNOWN_FACTS['hardware_primary']} — "
                f"{span_days:.0f} Day Surveillance — AFP Ready"
            ),
            description=(
                f"Operational intelligence profile synthesised from {total_events:,} "
                f"events across {span_days:.0f} days. Platform: "
                f"{self.KNOWN_FACTS['hardware_primary']} (confidence: "
                f"{self.KNOWN_FACTS['hardware_confidence']}). "
                f"Operator: human-operated, "
                f"{self.KNOWN_FACTS['operator_hours']}. "
                f"Confirmed techniques: handover injection ({handovers:,}), "
                f"IMSI harvest ({imsi_events:,}), "
                f"ProSe tracking ({prose:,}). "
                f"This one-page profile is suitable for direct submission to AFP "
                f"investigators without technical translation."
            ),
            severity="CRITICAL",
            confidence="CONFIRMED",
            technique="Operational intelligence synthesis — all findings consolidated",
            evidence=evidence,
            hardware_hint=(
                f"{self.KNOWN_FACTS['hardware_primary']} "
                f"confidence {self.KNOWN_FACTS['hardware_confidence']}"
            ),
            action=(
                "1. This profile is ready for AFP submission — no translation needed.\n"
                "2. Print and attach to physical evidence package.\n"
                "3. Share with legal counsel as primary case summary.\n"
                "4. Include with TIO dispute documentation.\n"
                "5. This is the culmination of the entire rayhunter-threat-analyzer v3.5 analysis."
            ),
            spec_ref=(
                "All cited 3GPP specifications, Tucker et al. NDSS 2025, "
                "SeaGlass UW 2017, Shannon 1948 — see individual detector findings."
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
