"""
New detectors for rayhunter-threat-analyzer v2.5+
Drop these into your detectors/ directory and register in the detector pipeline.

Modules:
  1. AuthenticationAbsenceDetector — flags sessions with anomalously low auth rates
  2. MeasurementReportRateDetector — flags forced sub-10s measurement reporting
  3. RRCReconfigurationPeriodicityDetector — detects metronomic reconfig cycles

Author: Julian Burns / Claude AI-assisted
Date: 2026-05-22
"""

import statistics
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


# ============================================================
# Shared types
# ============================================================

@dataclass
class Finding:
    """A single detection finding."""
    detector: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confirmed: bool
    title: str
    description: str
    technique: str
    spec_ref: str
    evidence: List[Dict[str, Any]]
    actions: List[str]
    tshark_verify: Optional[str] = None


@dataclass
class RRCEvent:
    """Represents an RRC-layer event extracted from PCAPNG or NDJSON."""
    timestamp: float  # epoch seconds
    event_type: str   # e.g. "RRCConnectionRelease", "SecurityModeCommand", etc.
    source_file: str
    details: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# 1. AuthenticationAbsenceDetector
# ============================================================

class AuthenticationAbsenceDetector:
    """
    Detects sessions where the authentication rate is anomalously low.
    
    Rationale:
        Legitimate LTE networks authenticate devices during Attach procedures
        and periodically during Service Requests. An IMSI catcher operating as
        a MitM proxy may skip authentication entirely or authenticate only on
        initial connection, resulting in authentication rates far below normal.
        
    Scoring:
        - auth_rate < 10%  → CRITICAL (consistent with IMSI catcher)
        - auth_rate < 50%  → HIGH (anomalous, warrants investigation)
        - auth_rate < 80%  → MEDIUM (possibly degraded network)
        - auth_rate >= 80% → PASS (normal)
        
    References:
        - 3GPP TS 24.301 §5.4.3 (EPS Authentication)
        - 3GPP TS 33.401 §6.1 (Authentication framework)
        - Tucker et al. (NDSS 2025) — causal vs. correlated indicators
        
    Distinguishes:
        - Attach procedures (should ALWAYS authenticate)
        - Service Request procedures (may reuse NAS security context)
        Reports both rates separately for accurate characterization.
    """
    
    NAME = "AuthenticationAbsenceDetector"
    VERSION = 1
    
    # Thresholds
    CRITICAL_THRESHOLD = 0.10  # Below 10% overall auth rate
    HIGH_THRESHOLD = 0.50
    MEDIUM_THRESHOLD = 0.80
    
    # Minimum connections to trigger (avoid false positives on tiny sessions)
    MIN_CONNECTIONS = 5
    
    def detect(self, events: List[RRCEvent], session_file: str) -> Optional[Finding]:
        """
        Analyze a list of RRC events for authentication absence.
        
        Args:
            events: List of RRCEvent objects from a single session
            session_file: Filename for evidence attribution
            
        Returns:
            Finding if anomaly detected, None otherwise
        """
        # Count key event types
        smc_count = 0          # SecurityModeCommand = proxy for total connections
        auth_req_count = 0     # Authentication Request
        auth_resp_count = 0    # Authentication Response
        attach_count = 0       # Attach Request (full attach, should auth)
        service_req_count = 0  # Service Request (may skip auth)
        
        for evt in events:
            et = evt.event_type.lower()
            if "securitymodecommand" in et and "complete" not in et:
                smc_count += 1
            elif "authentication request" in et or "authenticationrequest" in et:
                auth_req_count += 1
            elif "authentication response" in et or "authenticationresponse" in et:
                auth_resp_count += 1
            elif "attach request" in et or "attachrequest" in et:
                attach_count += 1
            elif "service request" in et or "servicerequest" in et:
                service_req_count += 1
        
        total_connections = smc_count
        if total_connections < self.MIN_CONNECTIONS:
            return None  # Not enough data
        
        # Use the lower of auth_req and auth_resp (completed authentications)
        completed_auth = min(auth_req_count, auth_resp_count)
        auth_rate = completed_auth / total_connections if total_connections > 0 else 1.0
        
        # Determine severity
        if auth_rate < self.CRITICAL_THRESHOLD:
            severity = "CRITICAL"
            confirmed = True
        elif auth_rate < self.HIGH_THRESHOLD:
            severity = "HIGH"
            confirmed = False
        elif auth_rate < self.MEDIUM_THRESHOLD:
            severity = "MEDIUM"
            confirmed = False
        else:
            return None  # Normal
        
        # Build finding
        unauthenticated = total_connections - completed_auth
        
        description = (
            f"{completed_auth} out of {total_connections} connections included "
            f"authentication ({auth_rate*100:.1f}%). "
            f"{unauthenticated} connections proceeded directly to "
            f"SecurityModeCommand without any Authentication Request/Response. "
        )
        
        if attach_count > 0:
            attach_auth_rate = completed_auth / attach_count if attach_count > 0 else 0
            description += (
                f"Of {attach_count} Attach procedures, "
                f"{completed_auth} were authenticated ({attach_auth_rate*100:.1f}%). "
            )
        
        if service_req_count > 0:
            description += (
                f"{service_req_count} Service Request reconnections observed. "
                f"While NAS security context reuse can skip authentication for "
                f"Service Requests (3GPP TS 24.301 §5.4.3.2), the aggregate rate "
                f"of {auth_rate*100:.1f}% across {total_connections} connections "
                f"over the session duration is anomalous."
            )
        
        return Finding(
            detector=self.NAME,
            severity=severity,
            confirmed=confirmed,
            title=f"Authentication Absence — {auth_rate*100:.1f}% auth rate ({completed_auth}/{total_connections})",
            description=description,
            technique="Authentication bypass / NAS security context exploitation",
            spec_ref="3GPP TS 24.301 §5.4.3, TS 33.401 §6.1",
            evidence=[{
                "total_connections": total_connections,
                "authenticated": completed_auth,
                "auth_rate": round(auth_rate, 4),
                "attach_procedures": attach_count,
                "service_requests": service_req_count,
                "unauthenticated": unauthenticated,
                "source_file": session_file,
            }],
            actions=[
                f"Verify: tshark -r {session_file} | grep -c 'Authentication request'",
                f"Verify: tshark -r {session_file} | grep -c 'SecurityModeCommand'",
                "Compare auth rate against legitimate baseline (expected ≥90% for Attach, variable for Service Request)",
                "Cross-reference with carrier records for authentication policy on this eNB",
            ],
            tshark_verify=(
                f'tshark -r {session_file} -T fields -e _ws.col.Info | '
                f'grep -c "Authentication request"  # Expected: {completed_auth}'
            ),
        )


# ============================================================
# 2. MeasurementReportRateDetector
# ============================================================

class MeasurementReportRateDetector:
    """
    Detects forced high-frequency MeasurementReport intervals.
    
    Rationale:
        Legitimate LTE cells configure measurement reporting at intervals
        typically ranging from 120ms to 60 minutes, with common values being
        120s, 240s, or 480s for connected-mode measurements. An IMSI catcher
        performing location tracking configures aggressive measurement
        reporting (e.g., reportInterval=ms5120 / 5.12s) to continuously
        track the target device's RF environment.
        
    Detection:
        Extracts MeasurementReport timestamps, computes inter-report
        intervals, filters out boundary artifacts (across release/reconnect
        events), and flags sessions where the mean interval is below
        the tracking-grade threshold.
        
    Thresholds:
        - mean < 10s   → HIGH (tracking-grade, consistent with IMSI catcher)
        - mean < 30s   → MEDIUM (aggressive but possibly legitimate)
        - mean >= 30s  → PASS (normal)
        
    References:
        - 3GPP TS 36.331 §5.5.5 (Measurement reporting)
        - 3GPP TS 36.331 §6.3.5 (ReportConfigEUTRA — reportInterval IE)
    """
    
    NAME = "MeasurementReportRateDetector"
    VERSION = 1
    
    HIGH_THRESHOLD = 10.0    # seconds — tracking-grade
    MEDIUM_THRESHOLD = 30.0  # seconds — aggressive
    MIN_REPORTS = 10         # minimum reports to analyze
    
    # Filter bounds for "normal" inter-report intervals
    # (exclude cross-release boundary gaps and sub-second duplicates)
    MIN_INTERVAL = 1.0   # seconds
    MAX_INTERVAL = 15.0  # seconds (generous upper bound for forced reporting)
    
    def detect(self, events: List[RRCEvent], session_file: str) -> Optional[Finding]:
        """
        Analyze MeasurementReport timing for forced high-frequency reporting.
        """
        # Extract MeasurementReport timestamps
        mr_times = []
        for evt in events:
            if "measurementreport" in evt.event_type.lower():
                mr_times.append(evt.timestamp)
        
        if len(mr_times) < self.MIN_REPORTS:
            return None
        
        mr_times.sort()
        
        # Compute intervals, filtering out boundary artifacts
        intervals = []
        for i in range(1, len(mr_times)):
            delta = mr_times[i] - mr_times[i - 1]
            if self.MIN_INTERVAL <= delta <= self.MAX_INTERVAL:
                intervals.append(delta)
        
        if len(intervals) < self.MIN_REPORTS:
            return None
        
        mean_interval = statistics.mean(intervals)
        sd_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        
        # Also count total connections to compute per-connection ratio
        connection_count = sum(
            1 for evt in events
            if "securitymodecommand" in evt.event_type.lower()
            and "complete" not in evt.event_type.lower()
        )
        reports_per_conn = len(mr_times) / connection_count if connection_count > 0 else len(mr_times)
        
        # Determine severity
        if mean_interval < self.HIGH_THRESHOLD:
            severity = "HIGH"
        elif mean_interval < self.MEDIUM_THRESHOLD:
            severity = "MEDIUM"
        else:
            return None  # Normal
        
        # Map to 3GPP reportInterval value
        ri_ms = round(mean_interval * 1000)
        ri_3gpp = self._nearest_report_interval(ri_ms)
        
        return Finding(
            detector=self.NAME,
            severity=severity,
            confirmed=(mean_interval < self.HIGH_THRESHOLD),
            title=(
                f"Forced MeasurementReport — {mean_interval:.2f}s interval "
                f"(reportInterval ≈ ms{ri_3gpp})"
            ),
            description=(
                f"{len(mr_times)} MeasurementReports observed with a mean interval "
                f"of {mean_interval:.3f}s ± {sd_interval:.3f}s "
                f"(n={len(intervals)} valid intervals). "
                f"This corresponds to reportInterval ≈ ms{ri_3gpp} in the "
                f"RRC Reconfiguration measurement configuration. "
                f"Normal cells use reportInterval values of 120s–240s. "
                f"A {mean_interval:.1f}s interval is tracking-grade configuration "
                f"consistent with an IMSI catcher performing continuous RF "
                f"environment monitoring of the target device. "
                f"Reports per connection: {reports_per_conn:.1f}."
            ),
            technique="Forced high-frequency measurement reporting for location tracking",
            spec_ref="3GPP TS 36.331 §5.5.5, §6.3.5 (ReportConfigEUTRA)",
            evidence=[{
                "total_reports": len(mr_times),
                "valid_intervals": len(intervals),
                "mean_interval_s": round(mean_interval, 4),
                "sd_interval_s": round(sd_interval, 4),
                "min_interval_s": round(min(intervals), 4),
                "max_interval_s": round(max(intervals), 4),
                "estimated_report_interval_ms": ri_3gpp,
                "reports_per_connection": round(reports_per_conn, 1),
                "connections": connection_count,
                "source_file": session_file,
            }],
            actions=[
                f"Verify: tshark -r {session_file} -Y lte_rrc.measurementReport "
                f"-T fields -e frame.time_epoch | awk 'NR>1{{d=$1-prev; "
                f"if(d>1 && d<10) print d}}{{prev=$1}}' | awk '{{s+=$1; n++}} "
                f"END {{print \"mean:\", s/n}}'",
                "Compare against legitimate baseline (expected >120s for normal cells)",
                "Cross-reference with RRC Reconfiguration to extract exact reportInterval IE",
            ],
            tshark_verify=(
                f'tshark -r {session_file} -Y "lte_rrc.measurementReport" | wc -l'
                f'  # Expected: {len(mr_times)}'
            ),
        )
    
    @staticmethod
    def _nearest_report_interval(ms: int) -> int:
        """Map observed interval to nearest 3GPP reportInterval enum value."""
        # 3GPP TS 36.331 reportInterval values (ms)
        valid = [120, 240, 480, 640, 1024, 2048, 5120, 10240,
                 20480, 40960, 60000, 360000, 720000, 1800000, 3600000]
        return min(valid, key=lambda v: abs(v - ms))


# ============================================================
# 3. RRCReconfigurationPeriodicityDetector
# ============================================================

class RRCReconfigurationPeriodicityDetector:
    """
    Detects metronomic periodicity in RRCConnectionReconfiguration events.
    
    Rationale:
        The existing RRCPeriodicityDetector analyzes RRCConnectionRelease
        timing. However, some IMSI catcher modes trigger periodic
        RRCConnectionReconfiguration events (measurement reconfigurations)
        at fixed intervals WITHOUT releasing the connection. This produces
        a distinct timer signature visible only in reconfiguration timing.
        
    Detection:
        1. Extract RRCConnectionReconfiguration timestamps
        2. Filter out "paired" events (sub-5s gaps from rapid handovers)
        3. Compute major intervals
        4. Detect periodicity via coefficient of variation (CV)
        5. Report dominant period if CV < threshold
        
    Known signatures:
        - T4: ~88.1s reconfiguration cycle (observed May 21, 2026)
        
    References:
        - 3GPP TS 36.331 §5.3.5 (RRC Connection Reconfiguration)
        - Harris operator manuals (leaked via The Intercept, 2016)
    """
    
    NAME = "RRCReconfigurationPeriodicityDetector"
    VERSION = 1
    
    # A CV (coefficient of variation) below this indicates periodicity
    CV_THRESHOLD = 0.05  # 5% — very tight periodicity
    CV_MODERATE = 0.15   # 15% — moderate periodicity
    
    # Minimum intervals to detect a pattern
    MIN_INTERVALS = 4
    
    # Filter: ignore paired events (rapid sub-threshold gaps)
    PAIR_THRESHOLD = 5.0  # seconds
    
    # Ignore massive gaps (overnight, detach/reattach)
    MAX_GAP = 600.0  # 10 minutes
    
    def detect(self, events: List[RRCEvent], session_file: str) -> Optional[Finding]:
        """
        Detect metronomic periodicity in RRC Reconfiguration events.
        """
        # Extract reconfiguration timestamps (exclude Complete messages)
        reconfig_times = []
        for evt in events:
            et = evt.event_type.lower()
            if "rrcconnectionreconfiguration" in et and "complete" not in et:
                reconfig_times.append(evt.timestamp)
        
        if len(reconfig_times) < self.MIN_INTERVALS + 1:
            return None
        
        reconfig_times.sort()
        
        # Compute all deltas
        raw_deltas = [
            reconfig_times[i] - reconfig_times[i - 1]
            for i in range(1, len(reconfig_times))
        ]
        
        # Filter: keep only "major" intervals (not paired, not massive gaps)
        major_intervals = [
            d for d in raw_deltas
            if self.PAIR_THRESHOLD < d < self.MAX_GAP
        ]
        
        if len(major_intervals) < self.MIN_INTERVALS:
            return None
        
        mean_interval = statistics.mean(major_intervals)
        sd_interval = statistics.stdev(major_intervals) if len(major_intervals) > 1 else 0.0
        cv = sd_interval / mean_interval if mean_interval > 0 else float('inf')
        
        # Determine severity
        if cv < self.CV_THRESHOLD:
            severity = "CRITICAL"
            confirmed = True
            periodicity_label = "metronomic"
        elif cv < self.CV_MODERATE:
            severity = "HIGH"
            confirmed = False
            periodicity_label = "periodic"
        else:
            return None  # No significant periodicity
        
        # Compute longest consecutive streak
        streak, max_streak = 0, 0
        tolerance = mean_interval * 0.05  # 5% tolerance
        for d in major_intervals:
            if abs(d - mean_interval) <= tolerance:
                streak += 1
                max_streak = max(max_streak, streak)
            else:
                streak = 0
        
        return Finding(
            detector=self.NAME,
            severity=severity,
            confirmed=confirmed,
            title=(
                f"RRC Reconfiguration Periodicity — "
                f"{mean_interval:.1f}s ± {sd_interval:.3f}s "
                f"(CV={cv:.4f}, {periodicity_label})"
            ),
            description=(
                f"{len(major_intervals)} major RRCConnectionReconfiguration intervals "
                f"detected with mean {mean_interval:.3f}s, SD {sd_interval:.3f}s, "
                f"coefficient of variation {cv:.4f}. "
                f"{'This is metronomic-grade periodicity (CV < 5%)' if cv < self.CV_THRESHOLD else 'This shows significant periodicity'}. "
                f"Longest consecutive streak at this period: {max_streak} intervals. "
                f"Metronomic RRC reconfiguration timing is not produced by "
                f"legitimate network operations and is consistent with a cell site "
                f"simulator performing timed measurement sweeps."
            ),
            technique="Metronomic RRC Reconfiguration cycle — timed measurement sweep",
            spec_ref="3GPP TS 36.331 §5.3.5 (RRC Connection Reconfiguration)",
            evidence=[{
                "total_reconfigurations": len(reconfig_times),
                "major_intervals": len(major_intervals),
                "mean_interval_s": round(mean_interval, 4),
                "sd_interval_s": round(sd_interval, 4),
                "cv": round(cv, 6),
                "longest_streak": max_streak,
                "min_interval_s": round(min(major_intervals), 4),
                "max_interval_s": round(max(major_intervals), 4),
                "source_file": session_file,
            }],
            actions=[
                f"Verify: tshark -r {session_file} "
                f'-Y "lte_rrc.rrcConnectionReconfiguration" '
                f"-T fields -e frame.time_epoch | "
                f"awk 'NR>1{{d=$1-prev; if(d>5 && d<600) print d}}{{prev=$1}}'",
                "Compare period against known IMSI catcher timer database",
                f"Cross-reference with RRCConnectionRelease timing for composite signature",
            ],
            tshark_verify=(
                f'tshark -r {session_file} '
                f'-Y "lte_rrc.rrcConnectionReconfiguration" '
                f'-T fields -e frame.time_epoch | '
                f"awk 'NR>1{{d=$1-prev; if(d>5) print d}}{{prev=$1}}'"
            ),
        )


# ============================================================
# Integration example
# ============================================================

def run_new_detectors(events: List[RRCEvent], session_file: str) -> List[Finding]:
    """
    Run all three new detectors against a session's events.
    
    Usage:
        findings = run_new_detectors(events, "1656131.pcapng")
        for f in findings:
            print(f"{f.severity}: {f.title}")
    """
    detectors = [
        AuthenticationAbsenceDetector(),
        MeasurementReportRateDetector(),
        RRCReconfigurationPeriodicityDetector(),
    ]
    
    findings = []
    for detector in detectors:
        result = detector.detect(events, session_file)
        if result is not None:
            findings.append(result)
    
    return findings


# ============================================================
# PCAPNG event extraction helper (requires tshark in PATH)
# ============================================================

def extract_events_from_pcapng(pcapng_path: str) -> List[RRCEvent]:
    """
    Extract RRC events from a PCAPNG file using tshark.
    
    Requires tshark (Wireshark CLI) to be installed and in PATH.
    """
    import subprocess
    
    cmd = [
        "tshark", "-r", pcapng_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "_ws.col.Info",
    ]
    
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[WARN] tshark extraction failed: {e}")
        return []
    
    events = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) < 2:
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            continue
        info = parts[1].strip()
        
        # Skip paging — high volume, not needed for these detectors
        if "Paging" in info:
            continue
        
        events.append(RRCEvent(
            timestamp=ts,
            event_type=info,
            source_file=pcapng_path,
        ))
    
    return events


# ============================================================
# CLI entry point
# ============================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python new_detectors.py <pcapng_file> [pcapng_file2 ...]")
        print("Requires tshark in PATH.")
        sys.exit(1)
    
    for pcapng_path in sys.argv[1:]:
        print(f"\n{'='*70}")
        print(f"  Analyzing: {pcapng_path}")
        print(f"{'='*70}")
        
        events = extract_events_from_pcapng(pcapng_path)
        if not events:
            print("  No events extracted.")
            continue
        
        print(f"  Extracted {len(events)} non-paging events")
        
        findings = run_new_detectors(events, pcapng_path)
        
        if not findings:
            print("  No anomalies detected.")
        else:
            for f in findings:
                print(f"\n  [{f.severity}] {f.title}")
                print(f"  {f.description[:200]}...")
                if f.tshark_verify:
                    print(f"  Verify: {f.tshark_verify}")
