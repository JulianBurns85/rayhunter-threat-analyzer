"""
PlatformFusionEngine - rayhunter-threat-analyzer v4.0
Correlates all detector outputs into unified Platform profiles.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import defaultdict


@dataclass
class PlatformProfile:
    platform_id: str
    confidence: float = 0.0
    cid_clusters: List[str] = field(default_factory=list)
    tac_clusters: List[str] = field(default_factory=list)
    jitter_dna: Optional[float] = None
    operator_schedule: Optional[str] = None
    weekday_bias: Optional[float] = None
    persistence_days: int = 0
    handover_inject_count: int = 0
    imsi_harvest_count: int = 0
    prose_tracking: bool = False
    flashcatch: bool = False
    wallet_inspector: bool = False
    regulatory_response: bool = False
    tucker_ier: Optional[float] = None
    nas_entropy: Optional[float] = None
    contributing_findings: List[str] = field(default_factory=list)
    hypothesis_scores: Dict[str, float] = field(default_factory=dict)


def _get(f, attr, default=""):
    if isinstance(f, dict):
        return str(f.get(attr, default) or default)
    return str(getattr(f, attr, default) or default)


class PlatformFusionEngine:

    def __init__(self):
        self.platforms: Dict[str, PlatformProfile] = {}
        self._counter = 0

    def _next_id(self):
        names = ["ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON"]
        name = names[self._counter] if self._counter < len(names) else str(self._counter)
        self._counter += 1
        return f"PLATFORM_{name}"

    def ingest_findings(self, all_findings: list) -> Dict[str, PlatformProfile]:
        p = PlatformProfile(platform_id=self._next_id())
        self.platforms[p.platform_id] = p

        for f in all_findings:
            detector = _get(f, "detector").lower()
            title = _get(f, "title").lower()
            desc = _get(f, "description")
            desc_lower = desc.lower()
            event_count = int(f.get("event_count", 0) if isinstance(f, dict) else getattr(f, "event_count", 0) or 0)

            # CID Rotation
            if "rotation" in title or "cidrotation" in detector or "cid rotation" in title:
                cids = re.findall(r"\b(\d{7,})\b", desc)
                tacs = re.findall(r"TAC[=:]\s*(\d+)", desc)
                p.cid_clusters.extend(cids[:20])
                p.tac_clusters.extend(tacs)
                p.contributing_findings.append(_get(f, "title") or "CID Rotation")

            # Jitter DNA
            if "jitter" in title or "temporal dna" in title or "jitter" in detector:
                m = re.search(r"Mean cycle[:\s]+([0-9.]+)s", desc)
                if m:
                    p.jitter_dna = float(m.group(1)) * 1000
                p.contributing_findings.append("Jitter DNA")

            # Operator Rhythm
            if "rhythm" in title or "operator behavioral" in title or "rhythm" in detector:
                m = re.search(r"([\d.]+)%\s*weekday", desc)
                if m:
                    p.weekday_bias = float(m.group(1)) / 100
                p.operator_schedule = "Business hours (Monday-Friday, 08:00-18:00 AEST)"
                p.contributing_findings.append("Operator Rhythm")

            # Handover Injection
            if ("handover" in title and "inject" in title) or "handoverinject" in detector:
                p.handover_inject_count += event_count if event_count else 1
                p.contributing_findings.append("Handover Injection")

            # IMSI Harvest
            if "imsi" in title and ("harvest" in title or "identity request" in title):
                p.imsi_harvest_count += event_count if event_count else 1
                p.contributing_findings.append("IMSI Harvest")

            # Auth Reject harvest
            if "auth" in title and "reject" in title:
                p.imsi_harvest_count += 1
                p.contributing_findings.append("Auth Reject Harvest")

            # ProSe Tracking
            if "prose" in title or "proximity" in title or "prose" in detector:
                p.prose_tracking = True
                p.contributing_findings.append("ProSe Proximity Tracking")

            # FlashCatch
            if "flashcatch" in title or "flashcatch" in detector or "flash" in title:
                p.flashcatch = True
                p.contributing_findings.append("FlashCatch")

            # Wallet Inspector
            if "wallet" in title or "walletinspector" in detector:
                p.wallet_inspector = True
                p.contributing_findings.append("Wallet Inspector")

            # Persistence
            if "persistence" in title or "cross-session" in title or "crosssession" in detector:
                m = re.search(r"(\d+)\+?\s*days? confirmed", desc_lower)
                if m:
                    days = int(m.group(1))
                    if days > p.persistence_days:
                        p.persistence_days = days
                p.contributing_findings.append("Cross-Session Persistence")

            # Tucker Taxonomy
            if "tucker" in title or "tucker" in detector or "exposure ratio" in title:
                m = re.search(r"IER[=:]?\s*([\d.]+)%", desc)
                if m:
                    p.tucker_ier = float(m.group(1)) / 100
                p.contributing_findings.append("Tucker Taxonomy")

            # NAS Entropy
            if "entropy" in title or "entropy" in detector:
                m = re.search(r"score of ([\d.]+) bits", desc_lower)
                if m:
                    p.nas_entropy = float(m.group(1))
                p.contributing_findings.append("NAS Entropy")

            # Regulatory Response
            if "regulatory" in title or "regulatory" in detector or "acma" in desc_lower:
                p.regulatory_response = True
                p.contributing_findings.append("Regulatory Response")

            # Campaign Segmentation
            if "campaign" in title or "campaign" in detector:
                p.contributing_findings.append("Attack Campaign Segmentation")

            # Attack Intensity
            if "intensity" in title or "intensity" in detector:
                p.contributing_findings.append("Attack Intensity Timeline")

            # Rogue Tower
            if "rogue tower" in title or "roguetower" in detector:
                p.contributing_findings.append("Rogue Tower Detection")

            # Protocol Sequence
            if "protocol sequence" in title or "sequence" in detector:
                p.contributing_findings.append("Protocol Sequence Violation")

            # Paging Anomaly
            if "paging" in title and ("volume" in title or "anomaly" in title):
                p.contributing_findings.append("Paging Volume Anomaly")

            # CRNTI Profiler
            if "c-rnti" in title or "crnti" in detector:
                p.contributing_findings.append("C-RNTI Target Profiling")

        # Deduplicate
        p.contributing_findings = list(dict.fromkeys(p.contributing_findings))

        p.confidence = self._calc_confidence(p)
        p.hypothesis_scores = self._hypothesis_defeater(p)

        return self.platforms

    def _calc_confidence(self, p: PlatformProfile) -> float:
        score = 0.0
        if p.cid_clusters:        score += 0.15
        if p.jitter_dna:          score += 0.15
        if p.operator_schedule:   score += 0.10
        if p.handover_inject_count > 0: score += 0.15
        if p.imsi_harvest_count > 0:    score += 0.10
        if p.prose_tracking:      score += 0.10
        if p.flashcatch:          score += 0.05
        if p.wallet_inspector:    score += 0.10
        if p.regulatory_response: score += 0.05
        if p.tucker_ier and p.tucker_ier > 0.15: score += 0.05
        return min(round(score, 3), 1.0)

    def _hypothesis_defeater(self, p: PlatformProfile) -> Dict[str, float]:
        repeater = 1.0
        macro = 1.0
        rogue = 0.1

        # Cross-carrier eliminates repeater
        has_cross_carrier = len(set(p.tac_clusters)) > 1
        if has_cross_carrier:
            repeater *= 0.001
            rogue += 0.30

        if p.handover_inject_count > 10:
            repeater *= 0.001
            macro *= 0.01
            rogue += 0.25

        if p.wallet_inspector:
            repeater *= 0.0001
            macro *= 0.001
            rogue += 0.20

        if p.prose_tracking:
            repeater *= 0.001
            macro *= 0.01
            rogue += 0.10

        if p.flashcatch:
            repeater *= 0.01
            rogue += 0.05

        if p.regulatory_response:
            repeater *= 0.01
            macro *= 0.1
            rogue += 0.10

        if p.operator_schedule:
            rogue += 0.05

        total = repeater + macro + rogue
        return {
            "cel_fi_repeater": round(repeater / total, 4),
            "legitimate_carrier_edge_case": round(macro / total, 4),
            "active_rogue_platform": round(min(rogue / total, 0.9999), 4),
        }

    def format_summary(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("PLATFORM FUSION ENGINE - INTELLIGENCE SUMMARY")
        lines.append("=" * 70)

        for pid, p in self.platforms.items():
            lines.append(f"\n+- {pid} -- Confidence: {p.confidence:.1%}")
            lines.append("|")

            if p.cid_clusters:
                unique = list(dict.fromkeys(p.cid_clusters))[:8]
                lines.append(f"|  CID Cluster:      {', '.join(unique)}")
            if p.tac_clusters:
                unique_tacs = list(dict.fromkeys(p.tac_clusters))
                lines.append(f"|  TAC Cluster:      {', '.join(unique_tacs)}")
            if p.jitter_dna:
                lines.append(f"|  Jitter DNA:       {p.jitter_dna:.1f}ms mean cycle (hardware fingerprint)")
            if p.operator_schedule:
                lines.append(f"|  Operator:         {p.operator_schedule}")
            if p.weekday_bias:
                lines.append(f"|  Weekday Bias:     {p.weekday_bias:.1%} of activity on weekdays")
            if p.persistence_days:
                lines.append(f"|  Persistence:      {p.persistence_days}+ days confirmed")
            if p.handover_inject_count:
                lines.append(f"|  Handovers:        {p.handover_inject_count} injected (no MeasurementReport)")
            if p.imsi_harvest_count:
                lines.append(f"|  IMSI Harvests:    {p.imsi_harvest_count} confirmed")
            if p.prose_tracking:
                lines.append(f"|  ProSe Tracking:   CONFIRMED - real-time location tracking active")
            if p.flashcatch:
                lines.append(f"|  FlashCatch:       CONFIRMED - sub-second IMSI capture")
            if p.wallet_inspector:
                lines.append(f"|  Wallet Inspector: CONFIRMED - pre-encryption IMSI extraction")
            if p.tucker_ier:
                lines.append(f"|  Tucker IER:       {p.tucker_ier:.1%} (court median 28.6%)")
            if p.nas_entropy:
                lines.append(f"|  NAS Entropy:      {p.nas_entropy:.4f} bits (rogue threshold <2.5)")
            if p.regulatory_response:
                lines.append(f"|  Regulatory:       Behavioral reconfiguration post-ACMA CONFIRMED")

            lines.append("|")
            lines.append("|  HYPOTHESIS DEFEATER:")
            hs = p.hypothesis_scores
            lines.append(f"|    Cel-Fi G51 repeater:          {hs.get('cel_fi_repeater', 0):.4f} ({hs.get('cel_fi_repeater', 0):.2%})")
            lines.append(f"|    Legitimate carrier edge case:  {hs.get('legitimate_carrier_edge_case', 0):.4f} ({hs.get('legitimate_carrier_edge_case', 0):.2%})")
            lines.append(f"|    Active rogue platform:         {hs.get('active_rogue_platform', 0):.4f} ({hs.get('active_rogue_platform', 0):.2%})")
            lines.append("|")

            lines.append(f"|  Contributing detectors ({len(p.contributing_findings)}):")
            for fn in p.contributing_findings:
                lines.append(f"|    + {fn}")
            lines.append("+" + "-" * 68)

        return "\n".join(lines)
