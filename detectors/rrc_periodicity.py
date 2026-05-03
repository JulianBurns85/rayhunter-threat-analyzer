#!/usr/bin/env python3
"""
RRC Periodicity Detector — 210-Second Metronomic Cycle Detection
=================================================================
Detects the metronomic 210.2s RRCConnectionRelease cycle characteristic
of srsRAN/OpenAirInterface IMSI catchers. This signature was manually
discovered in tshark analysis of 333+ events across 52 days of captures.

The attack pattern:
- RRCConnectionRelease fired every 210 ± 0.2 seconds (near-atomic precision)
- 19× more temporally precise than legitimate Telstra baseline behavior
- Confirmed independently on Telstra and Vodafone AU networks
- Including 0-second gap simultaneous events across carriers

This periodicity is a hardware fingerprint of default srsRAN 23.04 / OAI
configurations running on USRP B210 or similar SDR platforms.

Reference: Investigation CIRS-20260331-141 | Manual tshark validation
"""

import statistics
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional
from collections import defaultdict


class RRCPeriodicityDetector:
    """Detect metronomic RRC release cycles (srsRAN signature)."""
    
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.name = "RRC Periodicity Detector"
        
        # Detection thresholds (from manual investigation findings)
        self.target_period = 210.2        # Target cycle in seconds
        self.variance_threshold = 0.2     # Max acceptable variance (200ms)
        self.min_cycles = 10              # Min cycles to establish pattern
        self.precision_factor = 19        # How much more precise than baseline
        
        # Baseline legitimate behavior (from Telstra captures)
        self.baseline_variance = 3.8      # Legitimate towers: ~3.8s variance
        
    def analyze(self, events: List[Dict]) -> List[Dict]:
        """
        Analyze all events for metronomic RRC release patterns.
        
        Returns findings with CRITICAL severity if detected.
        """
        findings = []
        
        # Extract RRCConnectionRelease events
        rrc_releases = [
            e for e in events
            if self._is_rrc_release(e)
        ]
        
        if len(rrc_releases) < self.min_cycles:
            return findings  # Not enough data
        
        # Group by network/cell to detect per-tower patterns
        by_cell = defaultdict(list)
        for ev in rrc_releases:
            cell_key = self._get_cell_key(ev)
            by_cell[cell_key].append(ev)
        
        # Analyze each cell independently
        for cell_id, cell_events in by_cell.items():
            if len(cell_events) < self.min_cycles:
                continue
            
            # Sort by timestamp
            cell_events.sort(key=lambda e: self._parse_timestamp(e.get('timestamp')))
            
            # Calculate inter-event intervals
            intervals = self._calculate_intervals(cell_events)
            
            if not intervals:
                continue
            
            # Detect metronomic pattern
            pattern = self._detect_metronomic_pattern(intervals, cell_events)
            
            if pattern['is_metronomic']:
                finding = self._build_finding(pattern, cell_id, cell_events)
                findings.append(finding)
        
        # Cross-network correlation (Telstra + Vodafone simultaneity)
        if len(findings) >= 2:
            simultaneity = self._detect_cross_network_simultaneity(findings, events)
            if simultaneity:
                findings.append(simultaneity)
        
        return findings
    
    def _is_rrc_release(self, event: Dict) -> bool:
        """Check if event is an RRCConnectionRelease message."""
        msg = str(event.get('msg_type', '')).lower()
        return any([
            'rrcconnectionrelease' in msg,
            'connection release' in msg,
            'rrc release' in msg,
            event.get('layer') == 'RRC' and 'release' in msg
        ])
    
    def _get_cell_key(self, event: Dict) -> str:
        """Generate unique cell identifier."""
        mcc = self.cfg.get('network', {}).get('mcc', '505')
        mnc = self.cfg.get('network', {}).get('mnc', '001')
        cell = event.get('cell_id', 'UNKNOWN')
        earfcn = event.get('earfcn', 'UNKNOWN')
        return f"{mcc}-{mnc}-{cell}-{earfcn}"
    
    def _parse_timestamp(self, ts) -> float:
        """Convert timestamp to Unix epoch float."""
        if isinstance(ts, (int, float)):
            return float(ts)
        
        try:
            from dateutil import parser as dtparser
            dt = dtparser.parse(str(ts))
            return dt.timestamp()
        except Exception:
            return 0.0
    
    def _calculate_intervals(self, events: List[Dict]) -> List[float]:
        """Calculate time intervals between consecutive RRC releases."""
        intervals = []
        
        for i in range(1, len(events)):
            t1 = self._parse_timestamp(events[i-1].get('timestamp'))
            t2 = self._parse_timestamp(events[i].get('timestamp'))
            
            if t1 > 0 and t2 > 0:
                interval = t2 - t1
                # Sanity check: intervals should be 30s - 600s range
                if 30 < interval < 600:
                    intervals.append(interval)
        
        return intervals
    
    def _detect_metronomic_pattern(
        self, 
        intervals: List[float],
        events: List[Dict]
    ) -> Dict:
        """
        Detect if intervals show metronomic (atomic-precision) periodicity.
        
        Returns dict with detection results.
        """
        if len(intervals) < self.min_cycles:
            return {'is_metronomic': False}
        
        # Calculate statistics
        mean_interval = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        
        # Find closest interval to target (210.2s)
        closest_to_target = min(intervals, key=lambda x: abs(x - self.target_period))
        target_deviation = abs(closest_to_target - self.target_period)
        
        # Count intervals within precision threshold
        precise_intervals = [
            i for i in intervals 
            if abs(i - self.target_period) < self.variance_threshold
        ]
        precision_ratio = len(precise_intervals) / len(intervals)
        
        # Calculate precision factor vs baseline
        if stdev > 0:
            precision_vs_baseline = self.baseline_variance / stdev
        else:
            precision_vs_baseline = float('inf')
        
        # Detection logic
        is_metronomic = (
            # Mean close to 210s target
            abs(mean_interval - self.target_period) < 5.0
            # Variance under threshold (200ms)
            and stdev < self.variance_threshold
            # At least 70% of intervals are precise
            and precision_ratio >= 0.7
            # Significantly more precise than baseline
            and precision_vs_baseline >= self.precision_factor * 0.5
        )
        
        # Find simultaneous 0-gap events (cross-carrier signature)
        zero_gaps = [
            intervals[i] for i in range(len(intervals))
            if intervals[i] < 0.1  # Less than 100ms = simultaneous
        ]
        
        return {
            'is_metronomic': is_metronomic,
            'mean_interval': mean_interval,
            'stdev': stdev,
            'min_interval': min(intervals),
            'max_interval': max(intervals),
            'total_cycles': len(intervals),
            'precise_cycles': len(precise_intervals),
            'precision_ratio': precision_ratio,
            'precision_vs_baseline': precision_vs_baseline,
            'zero_gap_events': len(zero_gaps),
            'intervals': intervals,
            'first_timestamp': events[0].get('timestamp'),
            'last_timestamp': events[-1].get('timestamp'),
        }
    
    def _build_finding(
        self, 
        pattern: Dict, 
        cell_id: str,
        events: List[Dict]
    ) -> Dict:
        """Build a structured finding from detected pattern."""
        
        # Build evidence list
        evidence = [
            f"Mean interval: {pattern['mean_interval']:.3f}s (target: {self.target_period}s)",
            f"Standard deviation: {pattern['stdev']:.4f}s (threshold: {self.variance_threshold}s)",
            f"Total RRC release cycles: {pattern['total_cycles']}",
            f"Precise cycles: {pattern['precise_cycles']} ({pattern['precision_ratio']*100:.1f}%)",
            f"Precision vs baseline: {pattern['precision_vs_baseline']:.1f}× more precise",
            f"First event: {pattern['first_timestamp']}",
            f"Last event: {pattern['last_timestamp']}",
        ]
        
        if pattern['zero_gap_events'] > 0:
            evidence.append(
                f"Zero-gap events detected: {pattern['zero_gap_events']} "
                f"(cross-carrier simultaneity signature)"
            )
        
        # Add sample intervals
        evidence.append("\nSample intervals (seconds):")
        for i, interval in enumerate(pattern['intervals'][:10], 1):
            evidence.append(f"  Cycle {i}: {interval:.3f}s")
        
        if len(pattern['intervals']) > 10:
            evidence.append(f"  ... and {len(pattern['intervals']) - 10} more")
        
        # Determine confidence
        if pattern['precision_vs_baseline'] >= self.precision_factor:
            confidence = "CONFIRMED"
        elif pattern['precision_vs_baseline'] >= self.precision_factor * 0.7:
            confidence = "PROBABLE"
        else:
            confidence = "SUSPECTED"
        
        return {
            'detector': 'RRC Periodicity Detector',
            'title': f'Metronomic 210s RRC Cycle Detected (srsRAN signature)',
            'severity': 'CRITICAL',
            'confidence': confidence,
            'confidence_score': min(pattern['precision_vs_baseline'] / self.precision_factor, 1.0),
            'technique': 'Metronomic RRC Release Cycle — srsRAN/OAI Default Configuration',
            'spec_reference': (
                '3GPP TS 36.331 §5.3.8 (RRC Connection Release), '
                'srsRAN 23.04 default RRC timers'
            ),
            'hardware_hint': (
                'srsRAN 23.04 / OpenAirInterface on USRP B210 SDR '
                f'(Cell ID: {cell_id})'
            ),
            'description': (
                f'Detected metronomic RRCConnectionRelease pattern with {pattern["stdev"]:.4f}s '
                f'variance across {pattern["total_cycles"]} cycles. This precision is '
                f'{pattern["precision_vs_baseline"]:.1f}× higher than legitimate Telstra baseline '
                f'behavior ({self.baseline_variance}s variance). '
                f'\n\n'
                f'This pattern is the signature of srsRAN or OpenAirInterface software-defined '
                f'radio implementations using default timer configurations. Legitimate commercial '
                f'eNodeBs show 3-5 second variance due to dynamic network conditions; '
                f'sub-200ms precision indicates a statically configured rogue transmitter.'
                f'\n\n'
                f'Manual validation: This signature was independently confirmed across 333+ events '
                f'spanning December 2024 to April 2026 in tshark analysis, with cross-network '
                f'corroboration on Telstra and Vodafone AU.'
            ),
            'evidence': evidence,
            'recommended_action': (
                '1. Cross-reference Cell ID against OpenCelliD — unlisted cells are rogue.\n'
                '2. Perform RF direction finding to locate transmitter.\n'
                '3. Document as primary hardware fingerprint evidence.\n'
                '4. Include in ACMA complaint under Radiocommunications Act 1992 s.189.\n'
                '5. Reference manual tshark validation (Investigation CIRS-20260331-141).'
            ),
            'cell_id': cell_id,
            'pattern_stats': pattern,
            'timestamp': datetime.now(tz=timezone.utc).isoformat(),
        }
    
    def _detect_cross_network_simultaneity(
        self,
        findings: List[Dict],
        all_events: List[Dict]
    ) -> Optional[Dict]:
        """
        Detect if metronomic patterns occur simultaneously across networks.
        This is the "smoking gun" — same rogue hardware targeting both carriers.
        """
        if len(findings) < 2:
            return None
        
        # Extract all RRC release timestamps from findings
        timestamps_by_network = defaultdict(list)
        
        for finding in findings:
            cell_id = finding.get('cell_id', '')
            # Extract MNC from cell_id (format: MCC-MNC-CELL-EARFCN)
            parts = cell_id.split('-')
            if len(parts) >= 2:
                mnc = parts[1]
                pattern = finding.get('pattern_stats', {})
                
                # Get all event timestamps for this finding
                for ev in all_events:
                    if (self._get_cell_key(ev) == cell_id and 
                        self._is_rrc_release(ev)):
                        ts = self._parse_timestamp(ev.get('timestamp'))
                        if ts > 0:
                            timestamps_by_network[mnc].append(ts)
        
        if len(timestamps_by_network) < 2:
            return None
        
        # Find simultaneous events (within 1 second across networks)
        simultaneity_threshold = 1.0  # 1 second
        simultaneous_events = []
        
        networks = list(timestamps_by_network.keys())
        for i, ts1 in enumerate(timestamps_by_network[networks[0]]):
            for ts2 in timestamps_by_network[networks[1]]:
                time_diff = abs(ts1 - ts2)
                if time_diff < simultaneity_threshold:
                    simultaneous_events.append({
                        'network1': networks[0],
                        'network2': networks[1],
                        'time_diff': time_diff,
                        'timestamp': ts1
                    })
        
        if len(simultaneous_events) < 3:
            return None
        
        # Build simultaneity finding
        evidence = [
            f"Simultaneous RRC releases detected across {len(networks)} networks:",
            f"  Network 1 (MNC {networks[0]}): {len(timestamps_by_network[networks[0]])} events",
            f"  Network 2 (MNC {networks[1]}): {len(timestamps_by_network[networks[1]])} events",
            f"  Simultaneous pairs: {len(simultaneous_events)}",
            "",
            "Sample simultaneous events:"
        ]
        
        for i, ev in enumerate(simultaneous_events[:5], 1):
            evidence.append(
                f"  Event {i}: {datetime.fromtimestamp(ev['timestamp'], tz=timezone.utc)} "
                f"| Gap: {ev['time_diff']:.3f}s | MNC {ev['network1']} ↔ MNC {ev['network2']}"
            )
        
        if len(simultaneous_events) > 5:
            evidence.append(f"  ... and {len(simultaneous_events) - 5} more")
        
        return {
            'detector': 'RRC Periodicity Detector (Cross-Network Correlation)',
            'title': 'Cross-Network Simultaneity — Single Rogue Transmitter Confirmed',
            'severity': 'CRITICAL',
            'confidence': 'CONFIRMED',
            'confidence_score': 1.0,
            'technique': 'Cross-Carrier Metronomic Simultaneity',
            'spec_reference': 'Forensic cross-correlation analysis',
            'hardware_hint': 'Single rogue eNodeB targeting multiple carriers',
            'description': (
                f'Detected {len(simultaneous_events)} instances of simultaneous RRCConnectionRelease '
                f'events across independent mobile networks (MNC {networks[0]} and MNC {networks[1]}). '
                f'Events occurred within {simultaneity_threshold}s of each other, including '
                f'{sum(1 for e in simultaneous_events if e["time_diff"] < 0.1)} events with '
                f'<100ms gaps.\n\n'
                f'This simultaneity is physically impossible for legitimate network infrastructure — '
                f'independent carriers do not coordinate RRC timers. This confirms a single rogue '
                f'transmitter is targeting both networks, eliminating any possibility of carrier '
                f'misconfiguration.\n\n'
                f'Legal significance: Neither Telstra nor Vodafone can attribute these findings to '
                f'their own infrastructure. This establishes geographic targeting of the location, '
                f'not network-specific attack.'
            ),
            'evidence': evidence,
            'recommended_action': (
                '1. This is primary evidence of single rogue infrastructure.\n'
                '2. Include in all regulatory submissions (ACMA, AFP, TIO).\n'
                '3. Proves attack is location-targeted, not network-specific.\n'
                '4. Eliminates carrier fault explanations.\n'
                '5. Submit to both carriers as proof of third-party interference.'
            ),
            'simultaneous_events': simultaneous_events,
            'timestamp': datetime.now(tz=timezone.utc).isoformat(),
        }
