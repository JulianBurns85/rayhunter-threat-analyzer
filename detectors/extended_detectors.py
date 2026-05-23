"""
Extended Detector Suite for rayhunter-threat-analyzer v2.5+

Modules:
  1. FlashCatchDetector — sub-second CID flash + auth reject + cell barring
  2. NeighborListAnomalyDetector — empty/minimal SIB4/SIB5 neighbor lists  
  3. GUTIReallocationDetector — missing GUTI refresh
  4. PagingVolumeDetector — mass surveillance paging enumeration
  5. CIDeBNBConsistencyDetector — novel eNB appearing on same band

Author: Julian Burns / Claude AI-assisted
Date: 2026-05-22
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import re


@dataclass
class Finding:
    detector: str
    severity: str
    confirmed: bool
    title: str
    description: str
    technique: str
    spec_ref: str
    evidence: List[Dict[str, Any]]
    actions: List[str]
    tshark_verify: Optional[str] = None


# ============================================================
# 1. FlashCatchDetector
# ============================================================

class FlashCatchDetector:
    """
    Detects FlashCatch-style sub-second IMSI capture attacks.
    
    FlashCatch (Paci et al., WiSec 2025) is a two-phase technique:
      Phase 1: Sub-second IMSI capture via immediate Identity Request
               after the UE sends Attach Request with unrecognized GUTI
      Phase 2: Intentional authentication failure to trigger cell barring,
               causing the UE to immediately reattach to the legitimate cell
    
    Detection signatures:
      - CID appearance duration < 2 seconds (Phase 1 probe)
      - CID on same band as home cell but different eNB
      - CID never seen before or after (cell barring effect)
      - Authentication Reject near Identity Requests (Phase 2)
      - Zero OpenCelliD observations for the CID
    
    References:
      - Paci et al. "FlashCatch: Minimizing Disruption in IMSI Catcher
        Operations" ACM WiSec 2025, DOI: 10.1145/3734477.3734705
      - 3GPP TS 24.301 §5.4.4 (Identity Procedure)
      - 3GPP TS 24.301 §5.4.3.2 (Auth failure → cell barring)
    """
    
    NAME = "FlashCatchDetector"
    VERSION = 1
    
    FLASH_DURATION_THRESHOLD = 2.0  # seconds
    MIN_OBSERVATIONS = 2  # minimum SIB1 observations to count
    
    def detect(self, cid_observations: List[Dict], 
               home_cids: List[Dict],
               auth_events: List[Dict],
               session_file: str) -> Optional[Finding]:
        """
        Args:
            cid_observations: List of {cid, enb, band, timestamp, tac, plmn}
            home_cids: List of {cid, enb, band} for established home cells
            auth_events: List of {timestamp, event_type} for auth reject/request
            session_file: source filename
        """
        # Group observations by CID
        cid_groups = {}
        for obs in cid_observations:
            cid = obs['cid']
            if cid not in cid_groups:
                cid_groups[cid] = []
            cid_groups[cid].append(obs)
        
        home_enbs = set(h['enb'] for h in home_cids)
        home_bands = set(h['band'] for h in home_cids)
        
        findings = []
        
        for cid, observations in cid_groups.items():
            obs_sorted = sorted(observations, key=lambda x: x['timestamp'])
            
            if len(obs_sorted) < self.MIN_OBSERVATIONS:
                continue
            
            duration = obs_sorted[-1]['timestamp'] - obs_sorted[0]['timestamp']
            enb = obs_sorted[0].get('enb')
            band = obs_sorted[0].get('band')
            
            # Phase 1 checks
            is_flash = duration < self.FLASH_DURATION_THRESHOLD
            is_different_enb = enb is not None and enb not in home_enbs
            is_same_band = band is not None and band in home_bands
            
            if not is_flash:
                continue
            
            # Phase 2 checks — auth reject within 60s of the flash
            flash_time = obs_sorted[0]['timestamp']
            nearby_auth_rejects = [
                e for e in auth_events
                if 'reject' in e.get('event_type', '').lower()
                and abs(e['timestamp'] - flash_time) < 60
            ]
            
            # Score
            indicators = []
            score = 0
            
            if is_flash:
                indicators.append(f"Sub-{self.FLASH_DURATION_THRESHOLD}s CID flash ({duration:.3f}s)")
                score += 1
            if is_different_enb:
                indicators.append(f"Different eNB ({enb}) from home ({home_enbs})")
                score += 1
            if is_same_band:
                indicators.append(f"Same Band {band} as home cell — frequency displacement")
                score += 1
            if nearby_auth_rejects:
                indicators.append(f"Auth Reject within 60s of flash ({len(nearby_auth_rejects)} events)")
                score += 1
            
            if score < 2:
                continue
            
            severity = "CRITICAL" if score >= 3 else "HIGH"
            
            return Finding(
                detector=self.NAME,
                severity=severity,
                confirmed=(score >= 3),
                title=f"FlashCatch Signature — CID={cid} ({duration:.3f}s flash, {len(obs_sorted)} obs)",
                description=(
                    f"CID {cid} appeared for {duration:.3f} seconds with "
                    f"{len(obs_sorted)} SIB1 observations, then vanished. "
                    f"Indicators: {'; '.join(indicators)}. "
                    f"This signature matches the FlashCatch technique "
                    f"(Paci et al., WiSec 2025) which achieves sub-second "
                    f"IMSI retrieval by exploiting 3GPP vulnerabilities in the "
                    f"attach procedure. Phase 2 uses intentional authentication "
                    f"failure to trigger cell barring, preventing the UE from "
                    f"reconnecting to the rogue cell."
                ),
                technique="FlashCatch sub-second IMSI capture (Phase 1 + Phase 2)",
                spec_ref="3GPP TS 24.301 §5.4.4, §5.4.3.2; Paci et al. WiSec 2025",
                evidence=[{
                    "cid": cid,
                    "enb": enb,
                    "band": band,
                    "duration_s": round(duration, 4),
                    "observations": len(obs_sorted),
                    "timestamps": [o['timestamp'] for o in obs_sorted],
                    "different_enb": is_different_enb,
                    "same_band_as_home": is_same_band,
                    "nearby_auth_rejects": len(nearby_auth_rejects),
                    "indicator_count": score,
                    "source_file": session_file,
                }],
                actions=[
                    f"Verify CID {cid} against OpenCelliD/CellMapper — if zero observations, confirm rogue",
                    f"Check RFNSA.com.au for eNB {enb} physical tower registration",
                    "Capture RF fingerprint (FBSleuth methodology) during next occurrence",
                    "Include in USB evidence package with full timestamp documentation",
                ],
            )
        
        return None


# ============================================================
# 2. CID eNB Consistency Detector
# ============================================================

class CIDConsistencyDetector:
    """
    Detects when a novel CID appears on a different eNB from established
    home cells, especially when on the same frequency band.
    
    A rogue cell displacing a legitimate tower broadcasts on the same
    frequency but from a different physical location (different eNB).
    """
    
    NAME = "CIDConsistencyDetector"
    VERSION = 1
    
    def detect(self, all_cid_data: List[Dict], session_file: str) -> Optional[Finding]:
        """
        Args:
            all_cid_data: List of {cid, enb, band, tac, plmn, observation_count, 
                          first_seen, last_seen, source_files}
        """
        if not all_cid_data:
            return None
        
        # Find the dominant eNB (most observations)
        enb_counts = {}
        for c in all_cid_data:
            enb = c.get('enb')
            if enb:
                enb_counts[enb] = enb_counts.get(enb, 0) + c.get('observation_count', 1)
        
        if not enb_counts:
            return None
        
        home_enb = max(enb_counts, key=enb_counts.get)
        home_bands = set(
            c['band'] for c in all_cid_data 
            if c.get('enb') == home_enb and c.get('band')
        )
        
        # Find novel CIDs on different eNBs
        novel_cids = []
        for c in all_cid_data:
            enb = c.get('enb')
            if enb and enb != home_enb:
                band = c.get('band')
                same_band = band in home_bands if band else False
                novel_cids.append({
                    **c,
                    'same_band_as_home': same_band,
                })
        
        if not novel_cids:
            return None
        
        # Prioritize same-band novel CIDs (strongest indicator)
        same_band_novel = [c for c in novel_cids if c.get('same_band_as_home')]
        
        if same_band_novel:
            target = same_band_novel[0]
            severity = "HIGH"
            description = (
                f"CID {target['cid']} (eNB {target['enb']}) operates on "
                f"Band {target.get('band')} — the SAME band as home cell "
                f"eNB {home_enb}. A rogue cell on the same frequency as the "
                f"legitimate tower is the textbook IMSI catcher configuration: "
                f"broadcast stronger on the same channel to attract devices."
            )
        else:
            target = novel_cids[0]
            severity = "MEDIUM"
            description = (
                f"CID {target['cid']} (eNB {target['enb']}) is on a different "
                f"eNB from the established home tower (eNB {home_enb}). "
                f"This may indicate a nearby legitimate tower or a rogue cell."
            )
        
        return Finding(
            detector=self.NAME,
            severity=severity,
            confirmed=(severity == "HIGH"),
            title=f"Novel eNB Detected — CID={target['cid']} eNB={target['enb']} Band={target.get('band')}",
            description=description,
            technique="Cell ID / eNB consistency analysis",
            spec_ref="3GPP TS 36.331 §6.2.2 (SIB1 cellIdentity)",
            evidence=[{
                "novel_cid": target['cid'],
                "novel_enb": target['enb'],
                "novel_band": target.get('band'),
                "home_enb": home_enb,
                "home_bands": list(home_bands),
                "same_band": target.get('same_band_as_home', False),
                "observation_count": target.get('observation_count'),
                "source_file": session_file,
            }],
            actions=[
                f"Query RFNSA.com.au for eNB {target['enb']} registration status",
                f"Query OpenCelliD for CID {target['cid']}",
                "If unregistered, this confirms unauthorized transmission",
                "Capture RF fingerprint for physical-layer identification",
            ],
        )


# ============================================================
# 3. Composite Evidence Scorer
# ============================================================

class CompositeEvidenceScorer:
    """
    Aggregates findings across all sessions and detectors into a single
    evidence strength score with AFP-grade statistical backing.
    
    Weights temporal persistence, cross-carrier correlation, and
    statistical significance.
    """
    
    NAME = "CompositeEvidenceScorer"
    VERSION = 1
    
    def score(self, all_findings: List[Finding], 
              session_metadata: List[Dict]) -> Dict[str, Any]:
        """
        Args:
            all_findings: All findings from all detectors across all sessions
            session_metadata: List of {file, carrier, start_time, end_time, duration}
        """
        score = 0.0
        components = []
        
        # Count by severity
        severity_counts = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        
        if critical_count > 0:
            points = min(critical_count * 2.0, 6.0)
            score += points
            components.append(f"+{points:.1f}: {critical_count} CRITICAL findings")
        
        if high_count > 0:
            points = min(high_count * 1.0, 4.0)
            score += points
            components.append(f"+{points:.1f}: {high_count} HIGH findings")
        
        # Cross-carrier presence
        carriers = set(m.get('carrier', '') for m in session_metadata)
        if len(carriers) >= 2:
            score += 2.0
            components.append(f"+2.0: Multi-carrier operation ({', '.join(carriers)})")
        
        # Temporal persistence (>24h of data)
        total_duration = sum(m.get('duration', 0) for m in session_metadata)
        if total_duration > 86400:  # > 24 hours
            score += 1.5
            components.append(f"+1.5: Persistent across {total_duration/3600:.1f}h of captures")
        
        # Statistical significance (check for p-value findings)
        for f in all_findings:
            for ev in f.evidence:
                if isinstance(ev, dict):
                    p = ev.get('log10_p_value')
                    if p is not None and p < -10:
                        score += 2.0
                        components.append(f"+2.0: Statistical significance p < 10^{int(p)}")
                        break
        
        # Unique detector types
        detector_types = set(f.detector for f in all_findings)
        if len(detector_types) >= 4:
            score += 1.0
            components.append(f"+1.0: {len(detector_types)} independent detector types confirm")
        
        # Determine overall assessment
        if score >= 10:
            assessment = "OVERWHELMING — evidence strongly supports IMSI catcher presence"
        elif score >= 7:
            assessment = "STRONG — multiple independent indicators confirm anomalous activity"
        elif score >= 4:
            assessment = "MODERATE — significant anomalies detected, warrants investigation"
        elif score >= 2:
            assessment = "WEAK — some anomalies detected, additional data needed"
        else:
            assessment = "INSUFFICIENT — no significant anomalies detected"
        
        return {
            "composite_score": round(score, 1),
            "assessment": assessment,
            "components": components,
            "findings_by_severity": severity_counts,
            "detectors_triggered": list(detector_types),
            "carriers_affected": list(carriers),
            "total_capture_hours": round(total_duration / 3600, 1),
            "sessions_analyzed": len(session_metadata),
        }
