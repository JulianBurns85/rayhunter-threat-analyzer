#!/usr/bin/env python3
"""
IMSI Catcher Intelligence Database Engine
==========================================
Rayhunter Threat Analyzer v2.0 — Intelligence Layer

Loads the structured YAML intelligence database and provides:
  - Attack matching against analyzer findings
  - Device attribution scoring
  - Attacker profiler (aggregate operator assessment)
  - Per-finding enrichment with source citations
  - Rating cards for the GUI

Built from:
  Tucker et al. 2025 (NDSS) — 53-message IMSI exposure taxonomy
  Dabrowski et al. 2016 (RAID) — operator-side detection
  Ney et al. 2017 (SeaGlass/PoPETs) — city-wide detection signatures
  PKI Electronic Catalogue 2022 — commercial device specifications
  MuckRock FOIA archives — Harris/DRT procurement records

Usage:
    from intelligence.db_engine import IntelligenceDB
    db = IntelligenceDB()
    enriched = db.enrich_findings(findings)
    profile  = db.build_attacker_profile(enriched)

Standalone test:
    python db_engine.py --test
"""

import os
import sys
import glob
import yaml
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any


# ─────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────

@dataclass
class AttackRecord:
    id: str
    name: str
    category: str
    severity_score: int
    severity_level: str
    severity_rationale: str
    description: str
    detection_signature: dict
    automation: dict
    skill_required: str
    compatible_devices: List[str]
    sources: List[dict]
    generation: List[str] = field(default_factory=list)
    standard_ref: str = ""


@dataclass
class DeviceRecord:
    id: str
    name: str
    tier: str
    manufacturer: str
    supported_rats: List[str]
    attack_capabilities: List[str]
    behavioral_fingerprints: List[dict]
    operator_skill_required: str
    source_quality: str
    sources: List[dict]
    description: str = ""
    specifications: dict = field(default_factory=dict)


@dataclass
class AttackerProfile:
    id: str
    name: str
    indicator_attacks: dict
    likely_devices: List[str]
    operator_ratings: dict
    description: str = ""


@dataclass
class EnrichedFinding:
    """A finding from the analyzer enriched with intelligence database data."""
    original_finding: dict
    matched_attacks: List[AttackRecord]
    attributed_devices: List[Tuple[DeviceRecord, float]]  # (device, confidence_score)
    attack_rating_card: dict
    citations: List[str]


@dataclass
class AttackerAssessment:
    """Aggregate attacker profile built from all enriched findings."""
    matched_profile: Optional[AttackerProfile]
    automation_level: str
    sophistication_level: str
    persistence_level: str
    skill_level: str
    likely_actor: str
    likely_devices: List[str]
    danger_score: float
    danger_rating: str
    confidence: str
    evidence_summary: List[str]
    citations: List[str]


# ─────────────────────────────────────────────────────────
# Database loader
# ─────────────────────────────────────────────────────────

class IntelligenceDB:
    """
    Loads and queries the IMSI catcher intelligence YAML database.
    """

    # Paths relative to this file
    DB_ROOT = Path(__file__).parent

    # Severity thresholds for IMSI exposure ratio (Tucker et al. 2025)
    IMSI_EXPOSURE_RATIO_LTE_MAX_LEGITIMATE = 0.03   # 3% — LTE baseline
    IMSI_EXPOSURE_RATIO_GSM_MAX_LEGITIMATE = 0.06   # 6% — GSM baseline
    IMSI_EXPOSURE_RATIO_CATCHER_THRESHOLD  = 0.15   # 15% — anomaly flag
    IMSI_EXPOSURE_RATIO_CATCHER_CONFIRMED  = 0.28   # 28.6% — Tucker court event

    def __init__(self, db_root: Optional[Path] = None):
        if db_root:
            self.DB_ROOT = Path(db_root)
        self.attacks: Dict[str, AttackRecord] = {}
        self.devices: Dict[str, DeviceRecord] = {}
        self.profiles: Dict[str, AttackerProfile] = {}
        self._load_all()

    # ── Loaders ─────────────────────────────────────────

    def _load_all(self):
        """Load all YAML files from attacks/, devices/, profiles/ directories."""
        attacks_loaded = self._load_attacks()
        devices_loaded = self._load_devices()
        profiles_loaded = self._load_profiles()
        print(f"[IntelligenceDB] Loaded: {attacks_loaded} attacks, "
              f"{devices_loaded} devices, {profiles_loaded} profiles")

    def _load_attacks(self) -> int:
        attack_dir = self.DB_ROOT / "attacks"
        count = 0
        for yaml_file in sorted(attack_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    records = yaml.safe_load(f) or []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    attack = AttackRecord(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        category=rec.get("category", ""),
                        severity_score=rec.get("severity", {}).get("score", 5),
                        severity_level=rec.get("severity", {}).get("level", "MEDIUM"),
                        severity_rationale=rec.get("severity", {}).get("rationale", ""),
                        description=rec.get("description", ""),
                        detection_signature=rec.get("detection_signature", {}),
                        automation=rec.get("automation", {}),
                        skill_required=rec.get("skill_required", "UNKNOWN"),
                        compatible_devices=rec.get("compatible_devices", []),
                        sources=rec.get("sources", []),
                        generation=rec.get("generation", []),
                        standard_ref=rec.get("standard_ref", ""),
                    )
                    if attack.id:
                        self.attacks[attack.id] = attack
                        count += 1
            except Exception as e:
                print(f"[IntelligenceDB] WARN: Failed to load {yaml_file}: {e}")
        return count

    def _load_devices(self) -> int:
        device_dir = self.DB_ROOT / "devices"
        count = 0
        for yaml_file in sorted(device_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    records = yaml.safe_load(f) or []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    device = DeviceRecord(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        tier=rec.get("tier", "UNKNOWN"),
                        manufacturer=rec.get("manufacturer", "Unknown"),
                        supported_rats=rec.get("supported_rats", []),
                        attack_capabilities=rec.get("attack_capabilities", []),
                        behavioral_fingerprints=rec.get("behavioral_fingerprints", []),
                        operator_skill_required=rec.get("operator_skill_required", "UNKNOWN"),
                        source_quality=rec.get("source_quality", "LOW"),
                        sources=rec.get("sources", []),
                        description=rec.get("description", ""),
                        specifications=rec.get("specifications", {}),
                    )
                    if device.id:
                        self.devices[device.id] = device
                        count += 1
            except Exception as e:
                print(f"[IntelligenceDB] WARN: Failed to load {yaml_file}: {e}")
        return count

    def _load_profiles(self) -> int:
        profiles_dir = self.DB_ROOT / "profiles"
        count = 0
        for yaml_file in sorted(profiles_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    records = yaml.safe_load(f) or []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    profile = AttackerProfile(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        indicator_attacks=rec.get("indicator_attacks", {}),
                        likely_devices=rec.get("likely_devices", []),
                        operator_ratings=rec.get("operator_ratings", {}),
                        description=rec.get("description", ""),
                    )
                    if profile.id:
                        self.profiles[profile.id] = profile
                        count += 1
            except Exception as e:
                print(f"[IntelligenceDB] WARN: Failed to load {yaml_file}: {e}")
        return count

    # ── Attack matching ──────────────────────────────────

    def match_attack_to_finding(self, finding: dict) -> List[AttackRecord]:
        """
        Match a finding from the analyzer to attack records in the database.
        Uses title keywords, category, severity, and message type matching.
        """
        matched = []
        title = (finding.get("title", "") or "").lower()
        category = (finding.get("category", "") or "").lower()
        msg_type = (finding.get("msg_type", "") or "").lower()
        severity = (finding.get("severity", "") or "").upper()

        for attack in self.attacks.values():
            score = 0

            # Title keyword matching
            attack_keywords = {
                "identity": ["identity request", "identity harvest", "imsi"],
                "cipher_downgrade": ["cipher", "null", "eea0", "a5/0", "a50", "encryption"],
                "geran_redirect": ["geran", "redirect", "gsm redirect", "rrc release"],
                "attach_reject": ["attach reject", "attach_reject"],
                "rrc_release": ["rrc", "release", "paging"],
                "rogue_tower": ["rogue", "cell id", "cross", "carrier"],
                "handover": ["handover", "reconfiguration", "mobility"],
                "paging": ["paging", "210", "cycle", "metronomic"],
                "proximity": ["prose", "proximity", "reportproximity"],
                "earfcn": ["earfcn", "frequency", "channel"],
                "ue_information": ["ueinformation", "ue information", "capability"],
            }
            for attack_keyword_cat, keywords in attack_keywords.items():
                if attack_keyword_cat in attack.category.lower() or attack_keyword_cat in attack.id.lower():
                    for kw in keywords:
                        if kw in title or kw in msg_type:
                            score += 2
                            break

            # Category matching
            if attack.category and attack.category.lower() in category:
                score += 3
            if attack.category and attack.category.lower() in title:
                score += 2

            # Severity cross-match
            if severity and attack.severity_level and severity == attack.severity_level:
                score += 1

            # Direct ID keyword match (highest confidence)
            attack_name_parts = attack.name.lower().split()
            for part in attack_name_parts:
                if len(part) > 4 and part in title:
                    score += 3

            if score >= 3:
                matched.append(attack)

        # Sort by severity score descending
        matched.sort(key=lambda a: a.severity_score, reverse=True)
        return matched[:5]  # Top 5 matches

    def attribute_devices(self, matched_attacks: List[AttackRecord],
                          behavioral_flags: Optional[List[str]] = None) -> List[Tuple[DeviceRecord, float]]:
        """
        Score each device based on how many of the matched attacks it supports,
        plus bonus scoring for behavioral fingerprint matches.
        Returns list of (device, confidence_score) sorted by score descending.
        """
        device_scores: Dict[str, float] = {}

        attack_ids = {a.id for a in matched_attacks}

        for device in self.devices.values():
            score = 0.0
            device_attack_ids = set(device.attack_capabilities)

            # Score for attack capability overlap
            overlap = attack_ids & device_attack_ids
            if not overlap:
                continue
            score += len(overlap) * 1.5

            # Bonus for behavioral fingerprint matches
            if behavioral_flags:
                for fp in device.behavioral_fingerprints:
                    fp_id = fp.get("id", "")
                    if any(flag in fp_id for flag in behavioral_flags):
                        confidence = fp.get("confidence", "POSSIBLE")
                        bonus = {"CONFIRMED": 3.0, "PROBABLE": 1.5, "POSSIBLE": 0.5}.get(confidence, 0.5)
                        score += bonus

            # Source quality modifier
            quality_modifier = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}.get(device.source_quality, 0.7)
            score *= quality_modifier

            if score > 0:
                device_scores[device.id] = score

        results = [
            (self.devices[did], score)
            for did, score in device_scores.items()
            if did in self.devices
        ]
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:8]  # Top 8

    def build_rating_card(self, finding: dict,
                          matched_attacks: List[AttackRecord],
                          attributed_devices: List[Tuple[DeviceRecord, float]]) -> dict:
        """Build the per-finding rating card for display in the GUI."""
        if not matched_attacks:
            return {}

        primary = matched_attacks[0]
        top_device = attributed_devices[0][0] if attributed_devices else None
        top_device_confidence = attributed_devices[0][1] if attributed_devices else 0

        # Automation determination
        auto_flags = [a.automation.get("initiation", "UNKNOWN") for a in matched_attacks]
        initiation = "AUTO" if auto_flags.count("AUTO") >= len(auto_flags) * 0.6 else "MANUAL"

        # Skill level (highest across matched attacks)
        skill_order = ["SCRIPT_KIDDIE", "SEMI_PROFESSIONAL", "PROFESSIONAL", "STATE_ACTOR"]
        skills = [a.skill_required for a in matched_attacks if a.skill_required in skill_order]
        max_skill = max(skills, key=lambda s: skill_order.index(s)) if skills else "UNKNOWN"

        # Likely scripted
        scripted = any(a.automation.get("likely_scripted", False) for a in matched_attacks)
        attack_type = "Known scripted pattern" if scripted else "Custom/manual attack"

        # Device candidates
        device_names = [f"{d.name} ({d.tier})" for d, _ in attributed_devices[:3]]

        return {
            "finding_title": finding.get("title", "Unknown"),
            "severity_score": primary.severity_score,
            "severity_level": primary.severity_level,
            "severity_rationale": primary.severity_rationale,
            "attack_type": attack_type,
            "initiation": initiation,
            "likely_scripted": scripted,
            "skill_level": max_skill,
            "skill_label": {
                "SCRIPT_KIDDIE": "Low — pre-built toolchain (srsRAN/YateBTS default)",
                "SEMI_PROFESSIONAL": "Medium — modified open-source or commercial GUI",
                "PROFESSIONAL": "High — commercial LE-grade hardware/software",
                "STATE_ACTOR": "Very High — state/military platform",
            }.get(max_skill, "Unknown"),
            "likely_devices": device_names,
            "primary_device": top_device.name if top_device else "Unknown",
            "primary_device_tier": top_device.tier if top_device else "UNKNOWN",
            "device_confidence": self._confidence_label(top_device_confidence),
            "standard_refs": list({a.standard_ref for a in matched_attacks if a.standard_ref}),
            "3gpp_citations": self._extract_3gpp_refs(matched_attacks),
            "source_count": sum(len(a.sources) for a in matched_attacks),
        }

    def _confidence_label(self, score: float) -> str:
        if score >= 6.0:
            return "HIGH"
        elif score >= 3.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        return "SPECULATIVE"

    def _extract_3gpp_refs(self, attacks: List[AttackRecord]) -> List[str]:
        refs = set()
        for attack in attacks:
            if attack.standard_ref:
                refs.add(attack.standard_ref)
        return sorted(refs)

    # ── Finding enrichment ───────────────────────────────

    def enrich_findings(self, findings: List[dict],
                        behavioral_flags: Optional[List[str]] = None) -> List[EnrichedFinding]:
        """Enrich all findings from the analyzer with intelligence database data."""
        enriched = []
        for finding in findings:
            matched_attacks = self.match_attack_to_finding(finding)
            if not matched_attacks:
                continue

            attributed = self.attribute_devices(matched_attacks, behavioral_flags)
            card = self.build_rating_card(finding, matched_attacks, attributed)
            citations = self._collect_citations(matched_attacks, attributed)

            enriched.append(EnrichedFinding(
                original_finding=finding,
                matched_attacks=matched_attacks,
                attributed_devices=attributed,
                attack_rating_card=card,
                citations=citations,
            ))
        return enriched

    def _collect_citations(self, attacks: List[AttackRecord],
                           devices: List[Tuple[DeviceRecord, float]]) -> List[str]:
        """Collect all unique citations from matched attacks and devices."""
        citations = set()
        for attack in attacks:
            for source in attack.sources:
                citations.add(source.get("citation", ""))
        for device, _ in devices:
            for source in device.sources:
                citations.add(source.get("citation", ""))
        return sorted(c for c in citations if c)

    # ── Attacker profiling ───────────────────────────────

    def build_attacker_profile(self, enriched_findings: List[EnrichedFinding],
                               imsi_exposure_ratio: Optional[float] = None) -> AttackerAssessment:
        """
        Build an aggregate attacker assessment from all enriched findings.
        Uses profile matching against the profiles YAML.
        """
        if not enriched_findings:
            return self._empty_assessment()

        # Collect all attack IDs across all findings
        all_attack_ids = set()
        for ef in enriched_findings:
            for attack in ef.matched_attacks:
                all_attack_ids.add(attack.id)

        # Match attacker profiles
        matched_profile = None
        best_profile_score = 0
        for profile in self.profiles.values():
            score = self._score_profile_match(all_attack_ids, profile)
            if score > best_profile_score:
                best_profile_score = score
                matched_profile = profile

        # Aggregate device candidates
        device_vote: Dict[str, float] = {}
        for ef in enriched_findings:
            for device, score in ef.attributed_devices:
                device_vote[device.id] = device_vote.get(device.id, 0) + score

        top_devices = sorted(device_vote.items(), key=lambda x: x[1], reverse=True)[:5]
        likely_device_names = [
            self.devices[did].name for did, _ in top_devices if did in self.devices
        ]

        # Aggregate severity
        all_severities = [
            attack.severity_score
            for ef in enriched_findings
            for attack in ef.matched_attacks
        ]
        avg_severity = sum(all_severities) / len(all_severities) if all_severities else 5.0
        max_severity = max(all_severities) if all_severities else 5

        # Apply IMSI exposure ratio modifier
        ratio_modifier = 0.0
        if imsi_exposure_ratio is not None:
            if imsi_exposure_ratio >= self.IMSI_EXPOSURE_RATIO_CATCHER_CONFIRMED:
                ratio_modifier = 1.5
            elif imsi_exposure_ratio >= self.IMSI_EXPOSURE_RATIO_CATCHER_THRESHOLD:
                ratio_modifier = 0.8

        # Compute danger score
        danger_score = min(10.0, (avg_severity * 0.6 + max_severity * 0.4) + ratio_modifier)
        if matched_profile:
            profile_danger = matched_profile.operator_ratings.get("danger_score", 5)
            danger_score = min(10.0, (danger_score + profile_danger) / 2 + ratio_modifier)

        # Ratings from best matched profile or defaults
        if matched_profile:
            ratings = matched_profile.operator_ratings
        else:
            ratings = self._infer_ratings(all_attack_ids)

        # Confidence based on evidence count
        evidence_count = len(all_attack_ids)
        confidence = "HIGH" if evidence_count >= 4 else "MEDIUM" if evidence_count >= 2 else "LOW"

        # Evidence summary
        evidence_summary = []
        for ef in enriched_findings:
            title = ef.original_finding.get("title", "")
            if title:
                evidence_summary.append(f"{title} — {ef.matched_attacks[0].name if ef.matched_attacks else 'unknown'}")

        # Collect all citations
        all_citations = set()
        for ef in enriched_findings:
            all_citations.update(ef.citations)

        return AttackerAssessment(
            matched_profile=matched_profile,
            automation_level=ratings.get("automation", "UNKNOWN"),
            sophistication_level=ratings.get("sophistication", "UNKNOWN"),
            persistence_level=ratings.get("persistence", "UNKNOWN"),
            skill_level=ratings.get("skill_level", "UNKNOWN"),
            likely_actor=ratings.get("likely_actor", "Unknown"),
            likely_devices=likely_device_names,
            danger_score=round(danger_score, 1),
            danger_rating=self._danger_label(danger_score),
            confidence=confidence,
            evidence_summary=evidence_summary,
            citations=sorted(all_citations),
        )

    def _score_profile_match(self, found_attack_ids: set, profile: AttackerProfile) -> float:
        """Score how well found attacks match an attacker profile."""
        required = set(profile.indicator_attacks.get("required", []))
        supporting = set(profile.indicator_attacks.get("supporting", []))
        incompatible = set(profile.indicator_attacks.get("incompatible", []))

        # Incompatible attacks disqualify the profile
        if found_attack_ids & incompatible:
            return 0.0

        score = 0.0
        # Required attacks
        required_met = found_attack_ids & required
        score += len(required_met) * 3.0
        # Supporting attacks
        supporting_met = found_attack_ids & supporting
        score += len(supporting_met) * 1.0
        return score

    def _infer_ratings(self, attack_ids: set) -> dict:
        """Infer ratings when no profile matches cleanly."""
        high_severity = {
            "attach_reject_imsi_exposure", "a53_manipulation", "round_trip_time_relay_delay"
        }
        if attack_ids & high_severity:
            return {
                "automation": "MEDIUM", "sophistication": "HIGH",
                "skill_level": "PROFESSIONAL", "danger_score": 7,
                "likely_actor": "Professional — commercial or LE grade equipment"
            }
        return {
            "automation": "HIGH", "sophistication": "MEDIUM",
            "skill_level": "SEMI_PROFESSIONAL", "danger_score": 5,
            "likely_actor": "Semi-professional — modified open-source tools"
        }

    def _danger_label(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        if score >= 3.0: return "LOW"
        return "MINIMAL"

    def _empty_assessment(self) -> AttackerAssessment:
        return AttackerAssessment(
            matched_profile=None,
            automation_level="UNKNOWN",
            sophistication_level="UNKNOWN",
            persistence_level="UNKNOWN",
            skill_level="UNKNOWN",
            likely_actor="Insufficient evidence",
            likely_devices=[],
            danger_score=0.0,
            danger_rating="INSUFFICIENT DATA",
            confidence="NONE",
            evidence_summary=[],
            citations=[],
        )

    # ── Summary report ───────────────────────────────────

    def print_assessment(self, assessment: AttackerAssessment):
        """Print attacker assessment to terminal."""
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            console = Console()
            use_rich = True
        except ImportError:
            use_rich = False

        if use_rich:
            self._print_rich_assessment(assessment, console)
        else:
            self._print_plain_assessment(assessment)

    def _print_rich_assessment(self, assessment: AttackerAssessment, console):
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        colour = {
            "CRITICAL": "red", "HIGH": "orange3",
            "MEDIUM": "yellow", "LOW": "green", "MINIMAL": "blue"
        }.get(assessment.danger_rating, "white")

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Field", style="bold cyan", width=25)
        table.add_column("Value")
        table.add_row("Matched Profile", assessment.matched_profile.name if assessment.matched_profile else "No direct match")
        table.add_row("Automation Level", assessment.automation_level)
        table.add_row("Sophistication", assessment.sophistication_level)
        table.add_row("Skill Level", assessment.skill_level)
        table.add_row("Persistence", assessment.persistence_level)
        table.add_row("Likely Actor", assessment.likely_actor)
        table.add_row("Likely Hardware", ", ".join(assessment.likely_devices[:3]) or "Unknown")
        table.add_row(f"[{colour}]Danger Score[/{colour}]",
                      f"[{colour}]{assessment.danger_score}/10 ({assessment.danger_rating})[/{colour}]")
        table.add_row("Confidence", assessment.confidence)
        console.print(Panel(table, title="[bold red]OPERATOR ASSESSMENT[/bold red]", border_style=colour))

        if assessment.evidence_summary:
            console.print("\n[bold]Evidence collected:[/bold]")
            for e in assessment.evidence_summary[:8]:
                console.print(f"  • {e}")

    def _print_plain_assessment(self, assessment: AttackerAssessment):
        print("\n" + "="*60)
        print("  OPERATOR ASSESSMENT")
        print("="*60)
        print(f"  Profile:        {assessment.matched_profile.name if assessment.matched_profile else 'No direct match'}")
        print(f"  Automation:     {assessment.automation_level}")
        print(f"  Sophistication: {assessment.sophistication_level}")
        print(f"  Skill Level:    {assessment.skill_level}")
        print(f"  Likely Actor:   {assessment.likely_actor}")
        print(f"  Likely HW:      {', '.join(assessment.likely_devices[:3]) or 'Unknown'}")
        print(f"  Danger Score:   {assessment.danger_score}/10 ({assessment.danger_rating})")
        print(f"  Confidence:     {assessment.confidence}")
        print("="*60)


# ─────────────────────────────────────────────────────────
# Standalone test
# ─────────────────────────────────────────────────────────

def _run_test(db: IntelligenceDB):
    print("\n" + "="*60)
    print("  INTELLIGENCE DB — LOAD TEST")
    print("="*60)
    print(f"\n  Attacks loaded:  {len(db.attacks)}")
    print(f"  Devices loaded:  {len(db.devices)}")
    print(f"  Profiles loaded: {len(db.profiles)}")

    # Test with synthetic Julian Burns findings
    test_findings = [
        {
            "title": "Metronomic RRCConnectionRelease Cycle",
            "category": "paging_anomaly",
            "severity": "CRITICAL",
            "msg_type": "RRCConnectionRelease",
        },
        {
            "title": "GERAN Redirect + Null Cipher Detected",
            "category": "cipher_downgrade",
            "severity": "CRITICAL",
            "msg_type": "Security Mode Command",
        },
        {
            "title": "Unprovoked IMSI Identity Request",
            "category": "identity_harvest",
            "severity": "CRITICAL",
            "msg_type": "Identity Request",
        },
        {
            "title": "Cross-Carrier Simultaneous Release",
            "category": "rogue_cell",
            "severity": "CRITICAL",
            "msg_type": "RRCConnectionRelease",
        },
        {
            "title": "UEInformationRequest-r9 Detected",
            "category": "rogue_cell",
            "severity": "MEDIUM",
            "msg_type": "UEInformationRequest-r9",
        },
    ]

    print(f"\n  Running enrichment on {len(test_findings)} synthetic findings...")
    behavioral_flags = ["srsran_210s", "cross_carrier", "identity_request"]
    enriched = db.enrich_findings(test_findings, behavioral_flags)
    print(f"  Enriched: {len(enriched)} findings matched to database")

    for ef in enriched:
        card = ef.attack_rating_card
        if card:
            print(f"\n  ── {card.get('finding_title', 'Unknown')}")
            print(f"     Severity:    {card.get('severity_score')}/10 ({card.get('severity_level')})")
            print(f"     Attack Type: {card.get('attack_type')}")
            print(f"     Initiation:  {card.get('initiation')}")
            print(f"     Skill:       {card.get('skill_label')}")
            print(f"     Top Device:  {card.get('primary_device')} ({card.get('primary_device_tier')})")
            print(f"     Sources:     {card.get('source_count')} citations")

    # Build attacker profile
    print("\n  Building attacker profile (Julian Burns case, IMSI exposure ~100%)...")
    assessment = db.build_attacker_profile(enriched, imsi_exposure_ratio=1.0)
    db.print_assessment(assessment)

    print(f"\n  [PASS] Database engine test complete\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IMSI Intelligence DB Engine")
    parser.add_argument("--test", action="store_true", help="Run self-test")
    parser.add_argument("--db-root", type=str, default=None, help="Path to db root directory")
    args = parser.parse_args()

    db_root = Path(args.db_root) if args.db_root else Path(__file__).parent
    db = IntelligenceDB(db_root=db_root)

    if args.test:
        _run_test(db)
    else:
        print(f"Loaded {len(db.attacks)} attacks, {len(db.devices)} devices, {len(db.profiles)} profiles")
        print("Use --test to run full self-test")
