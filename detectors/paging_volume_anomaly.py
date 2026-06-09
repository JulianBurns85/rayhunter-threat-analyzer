#!/usr/bin/env python3
"""
PagingVolumeAnomalyDetector — Detects paging floods preceding attacks.

An IMSI catcher floods the paging channel to force devices to identify
themselves — this is the SETUP PHASE before the harvest.

We detect individual paging events. This detects the VOLUME SPIKE
on the paging channel that precedes every attack event.

If paging volume doubles in a 60-second window before every IMSI
harvest — that's the attack setup phase. Document it and you've
captured the full attack lifecycle:

  Paging flood → Identity Request → [IMSI extracted] → Release

This adds the missing pre-attack signature that completes the
evidence chain from setup through extraction to teardown.

Also detects:
- IMSI-targeted paging (paging by IMSI not TMSI)
- Machine-precision paging intervals
- Paging rate anomalies (too high for legitimate use)

Reference: 3GPP TS 24.301 §5.6.2 (paging procedure);
Tucker et al. NDSS 2025 msgs #1-5 (paging-based IMSI extraction).
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import statistics
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


PAGING_WINDOW_S  = 60.0   # Window before harvest event to check for paging spike
SPIKE_THRESHOLD  = 2.0    # Paging count must be this many times above baseline
BIN_SIZE_S       = 10.0   # 10-second bins for paging rate

PAGING_TYPES = {
    "paging", "pagingmessage", "paging message",
    "pcch", "pagingrecord",
}
IMSI_TYPES = {
    "identityrequest", "identity request",
}
TMSI_IMSI_TYPES = {
    "s-tmsi", "stmsi",  # Paging by S-TMSI = normal
    "imsi",              # Paging by IMSI = anomalous
}


class PagingVolumeAnomalyDetector(BaseDetector):
    """
    Detects paging volume spikes preceding IMSI harvest events
    and IMSI-targeted paging anomalies.
    """

    name = "PagingVolumeAnomalyDetector"
    description = (
        "Paging volume anomaly detection — flood preceding harvest, "
        "IMSI-targeted paging, machine-precision paging intervals"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        # Extract paging and harvest events with timestamps
        paging_ts  = []
        harvest_ts = []
        imsi_paging_ts = []

        for e in events:
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            ts  = self._get_ts(e)
            if ts is None:
                continue

            if any(t in msg for t in PAGING_TYPES):
                paging_ts.append(ts)
                # Check if IMSI-targeted (anomalous)
                paging_id = str(e.get("paging_identity") or
                               e.get("ue_identity") or "").lower()
                if "imsi" in paging_id or "imsi" in msg:
                    imsi_paging_ts.append(ts)

            if any(t in msg for t in IMSI_TYPES):
                harvest_ts.append(ts)

        if not paging_ts:
            return []

        paging_ts.sort()
        harvest_ts.sort()

        # Calculate baseline paging rate (events per 10s)
        if len(paging_ts) < 10:
            return []

        total_duration = paging_ts[-1] - paging_ts[0]
        if total_duration < 60:
            return []

        baseline_rate = len(paging_ts) / (total_duration / BIN_SIZE_S)

        # Find paging spikes before harvest events
        spikes_before_harvest = []
        for h_ts in harvest_ts:
            window_start = h_ts - PAGING_WINDOW_S
            paging_in_window = sum(
                1 for p_ts in paging_ts
                if window_start <= p_ts <= h_ts
            )
            rate_in_window = paging_in_window / (PAGING_WINDOW_S / BIN_SIZE_S)
            if baseline_rate > 0 and rate_in_window >= baseline_rate * SPIKE_THRESHOLD:
                spikes_before_harvest.append({
                    "harvest_ts":    h_ts,
                    "paging_count":  paging_in_window,
                    "rate":          rate_in_window,
                    "spike_factor":  rate_in_window / baseline_rate,
                })

        # Paging interval analysis (metronomic = rogue)
        paging_intervals = [
            paging_ts[i+1] - paging_ts[i]
            for i in range(len(paging_ts)-1)
        ]
        valid_intervals = [iv for iv in paging_intervals if 0.1 <= iv <= 300]
        metronomic_paging = None
        if len(valid_intervals) >= 10:
            mean_iv  = statistics.mean(valid_intervals)
            stdev_iv = statistics.stdev(valid_intervals) if len(valid_intervals) > 1 else 0
            cv       = stdev_iv / mean_iv if mean_iv > 0 else 0
            if cv < 0.05:  # < 5% coefficient of variation = metronomic
                metronomic_paging = {
                    "mean":  mean_iv,
                    "stdev": stdev_iv,
                    "cv":    cv,
                }

        # Assess overall findings
        total_anomalies = (
            len(spikes_before_harvest) +
            len(imsi_paging_ts) +
            (1 if metronomic_paging else 0)
        )

        if total_anomalies == 0:
            return []

        evidence = [
            f"Total paging events: {len(paging_ts)}",
            f"Baseline paging rate: {baseline_rate:.2f} events/{BIN_SIZE_S:.0f}s",
            f"IMSI harvest events: {len(harvest_ts)}",
            f"",
        ]

        if spikes_before_harvest:
            evidence.append(
                f"PAGING FLOODS PRECEDING HARVEST ({len(spikes_before_harvest)} events):"
            )
            for spike in spikes_before_harvest[:5]:
                ts_str = datetime.fromtimestamp(
                    spike["harvest_ts"], tz=timezone.utc
                ).isoformat()
                evidence.append(
                    f"  [{ts_str}] {spike['paging_count']} pages in "
                    f"{PAGING_WINDOW_S:.0f}s before harvest "
                    f"(×{spike['spike_factor']:.1f} above baseline)"
                )
            evidence.append(
                f"  FORENSIC SIGNIFICANCE: Paging flood is the setup phase "
                f"of the identity harvest attack — forcing devices to respond "
                f"before the Identity Request is issued."
            )

        if imsi_paging_ts:
            evidence.append(f"")
            evidence.append(
                f"IMSI-TARGETED PAGING DETECTED: {len(imsi_paging_ts)} events"
            )
            evidence.append(
                f"  Legitimate networks page by S-TMSI (temporary ID). "
                f"Paging by IMSI (permanent ID) means the attacker already "
                f"knows who they are targeting."
            )

        if metronomic_paging:
            evidence.append(f"")
            evidence.append(f"METRONOMIC PAGING DETECTED:")
            evidence.append(
                f"  Mean interval: {metronomic_paging['mean']:.3f}s | "
                f"CV: {metronomic_paging['cv']:.4f} "
                f"(< 0.05 = machine precision)"
            )

        severity   = "CRITICAL" if (spikes_before_harvest and imsi_paging_ts) else "HIGH"
        confidence = "CONFIRMED" if len(spikes_before_harvest) >= 3 else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Paging Volume Anomaly — "
                f"{len(spikes_before_harvest)} Pre-Harvest Floods | "
                f"{len(imsi_paging_ts)} IMSI-Targeted | "
                f"{'Metronomic' if metronomic_paging else 'Variable'} Interval"
            ),
            description=(
                f"Paging channel analysis reveals {len(spikes_before_harvest)} "
                f"volume spike(s) preceding IMSI harvest events "
                f"(>{SPIKE_THRESHOLD}× baseline rate in {PAGING_WINDOW_S:.0f}s window). "
                f"{'Additionally, ' + str(len(imsi_paging_ts)) + ' IMSI-targeted paging event(s) detected — ' if imsi_paging_ts else ''}"
                f"{'legitimate networks use S-TMSI not IMSI for paging. ' if imsi_paging_ts else ''}"
                f"This completes the attack lifecycle: "
                f"paging flood → identity harvest → release."
            ),
            severity=severity,
            confidence=confidence,
            technique=(
                "Paging volume spike detection — pre-harvest flood identification "
                "and IMSI-targeted paging analysis"
            ),
            evidence=evidence,
            hardware_hint=(
                "Active IMSI catcher — paging flood is documented pre-attack "
                "setup technique. IMSI-targeted paging requires prior knowledge "
                "of target identity."
            ),
            action=(
                "1. Paging flood + harvest sequence proves full attack lifecycle.\n"
                "2. IMSI-targeted paging proves operator knows specific target.\n"
                "3. Cite Tucker et al. NDSS 2025 msgs #1-5 (paging-based extraction).\n"
                "4. Cite 3GPP TS 24.301 §5.6.2 — paging should use S-TMSI not IMSI.\n"
                "5. Include paging rate timeline in AFP submission."
            ),
            spec_ref=(
                "3GPP TS 24.301 §5.6.2 (paging procedure — S-TMSI mandatory); "
                "Tucker et al. NDSS 2025 msgs #1-5; "
                "YAICD P7 (paging anomaly)"
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
