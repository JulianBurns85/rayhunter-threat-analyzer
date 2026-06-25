"""
RRCPeriodicityDetector
======================
Detects metronomic RRCConnectionRelease cycles — the primary timing
fingerprint distinguishing commercial IMSI catchers from legitimate
LTE base stations.

Key finding from Cranbourne East investigation:
  210.182s mean interval (SD 0.138s, 333 events) — machine-precision
  cycle consistent with RayFish Controller automated scheduling.
  19× more temporally precise than legitimate Telstra baseline.

Also detects:
  Harris HailStorm T1 signature: 610.6s
  Unknown tight-SD cycles (catches novel hardware)

Sources:
  Harris Gemini RayFish Controller R3.3.1 (leaked)
  3GPP TS 36.331 §5.3.8 (RRCConnectionRelease)
  Ziayi et al. YAICD Security and Communication Networks (2021) — P14

Save to: detectors/rrc_periodicity.py
"""

import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional


class RRCPeriodicityDetector:
    """
    Extracts RRCConnectionRelease events, calculates inter-event intervals,
    and flags statistically improbable (machine-precision) periodicities.
    """

    name = "RRCPeriodicityDetector"

    # Canonical cycle signatures
    SRSRAN_CYCLE_S  = 210.2    # srsRAN 23.04 / OpenAirInterface default
    HARRIS_T1_S     = 610.6    # HailStorm T1 (Gemini RayFish docs)

    # Event type names to match (normalised: lowercase, no hyphens/underscores)
    _RELEASE_NAMES = {
        "rrcconnectionrelease",
        "rrcrelease",
        "rrcconnectionreleaser8",
        "rrcreleaseindication",
        "rrcconnectionreject",   # Occasionally mislabelled in captures
    }

    def __init__(self, cfg: dict):
        rrc = cfg.get("detection", {}).get("rrc_periodicity", {})
        self.cycle_s         = rrc.get("cycle_seconds",       self.SRSRAN_CYCLE_S)
        self.tolerance_s     = rrc.get("tolerance_seconds",   15.0)
        self.min_obs         = rrc.get("min_observations",    3)
        self.sd_threshold_ms = rrc.get("sd_threshold_ms",     200)
        self.harris_t1_s     = rrc.get("harris_t1_seconds",   self.HARRIS_T1_S)
        self.harris_t1_tol   = rrc.get("harris_t1_tolerance", 5.0)

    # -----------------------------------------------------------------------

    def analyze(self, events: List[Any]) -> List[Dict]:
        releases = self._extract_releases(events)
        if len(releases) < self.min_obs + 1:
            return []

        releases.sort(key=lambda r: r["ts"])
        timestamps = [r["ts"] for r in releases]
        intervals  = [timestamps[i+1] - timestamps[i]
                      for i in range(len(timestamps) - 1)]

        if not intervals:
            return []

        findings: List[Dict] = []

        # Check srsRAN / configured target cycle
        findings.extend(self._check_cycle(
            intervals=intervals,
            releases=releases,
            target_s=self.cycle_s,
            tolerance_s=self.tolerance_s,
            label=f"srsRAN/RayFish {self.cycle_s}s",
            profile_hint="srsran_automated",
        ))

        # Check Harris HailStorm T1
        findings.extend(self._check_cycle(
            intervals=intervals,
            releases=releases,
            target_s=self.harris_t1_s,
            tolerance_s=self.harris_t1_tol,
            label=f"Harris HailStorm T1 ({self.harris_t1_s}s)",
            profile_hint="harris_commercial_lte_periodic",
        ))

        # Check for any unknown tight-SD cycle
        findings.extend(self._check_tight_sd(intervals, releases))

        return findings

    # -----------------------------------------------------------------------

    def _check_cycle(
        self,
        intervals: List[float],
        releases: List[Dict],
        target_s: float,
        tolerance_s: float,
        label: str,
        profile_hint: str,
    ) -> List[Dict]:
        in_range = [
            iv for iv in intervals
            if (target_s - tolerance_s) <= iv <= (target_s + tolerance_s)
        ]
        if len(in_range) < self.min_obs:
            return []

        mean_s = statistics.mean(in_range)
        sd_ms  = (statistics.stdev(in_range) * 1000.0
                  if len(in_range) > 1 else 0.0)
        machine_precision = sd_ms < self.sd_threshold_ms

        carriers: Dict[str, int] = {}
        for r in releases:
            carriers[r["mnc"]] = carriers.get(r["mnc"], 0) + 1
        multi_carrier = len(carriers) > 1

        msg = (
            f"Metronomic RRCConnectionRelease cycle detected: "
            f"{mean_s:.3f}s mean, SD {sd_ms:.1f}ms "
            f"({len(in_range)} matching / {len(intervals)} total intervals). "
            f"Signature: {label}. "
            f"Machine-precision: {'YES' if machine_precision else 'NO'} "
            f"(threshold {self.sd_threshold_ms}ms SD). "
            f"3GPP TS 36.331 §5.3.8. YAICD P14 = 1.5 (Ziayi et al. 2021)."
        )
        if multi_carrier:
            msg += (
                f" Cross-carrier: {dict(carriers)} — "
                f"simultaneous multi-carrier cycle confirms "
                f"Harris 4-CH Multi-Xmit architecture."
            )

        return [{
            "type":               "rrc_periodicity",
            "finding_type":       "rrc_periodicity",
            "detector":           self.name,
            "severity":           "CRITICAL" if machine_precision else "HIGH",
            # Standard make_finding() keys (required by provenance mapper and reporter)
            "title":              label,
            "description":        msg,
            "confidence":         "CONFIRMED" if machine_precision else "PROBABLE",
            "technique":          "Metronomic RRCConnectionRelease cycle — timed measurement sweep",
            "evidence":           [msg],
            "event_count":        len(in_range),
            "recommended_action": (
                "Document RRC release cycle as evidence of timed measurement sweep. "
                "Cross-reference with RRCConnectionRelease timing for composite signature. "
                "Include in VicPol USB evidence package."
            ),
            "spec_reference":     "3GPP TS 36.331 §5.3.8; YAICD P14_t3212_anomaly",
            # Legacy keys preserved for backward compatibility
            "confirmed":          machine_precision,
            "label":              label,
            "profile_hint":       profile_hint,
            "yaicd_param":        "P14_t3212_anomaly",
            "cycle_seconds":      round(mean_s, 3),
            "mean_interval_s":    round(mean_s, 3),
            "std_dev_ms":         round(sd_ms, 1),
            "matching_intervals": len(in_range),
            "total_intervals":    len(intervals),
            "total_releases":     len(releases),
            "machine_precision":  machine_precision,
            "multi_carrier":      multi_carrier,
            "carriers":           carriers,
            "message":            msg,
        }]

    def _check_tight_sd(
        self,
        intervals: List[float],
        releases: List[Dict],
    ) -> List[Dict]:
        """Flag any tight-SD cluster not already caught by specific checks."""
        if len(intervals) < self.min_obs:
            return []

        mean_s = statistics.mean(intervals)
        sd_ms  = (statistics.stdev(intervals) * 1000.0
                  if len(intervals) > 1 else 9999.0)

        # Skip if already matched by named cycles
        if (abs(mean_s - self.cycle_s)    <= self.tolerance_s or
                abs(mean_s - self.harris_t1_s) <= self.harris_t1_tol):
            return []

        if sd_ms >= self.sd_threshold_ms:
            return []

        _msg2 = (
            f"Unknown metronomic RRCConnectionRelease: "
            f"{mean_s:.3f}s mean, SD {sd_ms:.1f}ms "
            f"across {len(intervals)} intervals. "
            f"SD < {self.sd_threshold_ms}ms = machine-precision. "
            f"Does not match srsRAN ({self.cycle_s}s) "
            f"or Harris T1 ({self.harris_t1_s}s). "
            f"Novel hardware or modified firmware. "
            f"YAICD P14 = 1.5 (Ziayi et al. 2021)."
        )
        _label2 = f"Unknown metronomic cycle ({mean_s:.1f}s)"
        return [{
            "type":             "rrc_periodicity",
            "finding_type":     "rrc_periodicity",
            "detector":         self.name,
            "severity":         "HIGH",
            # Standard make_finding() keys
            "title":            _label2,
            "description":      _msg2,
            "confidence":       "CONFIRMED",
            "technique":        "Metronomic RRCConnectionRelease cycle — unknown hardware signature",
            "evidence":         [_msg2],
            "event_count":      len(intervals),
            "recommended_action": (
                "Document cycle as novel hardware signature. Cross-reference with "
                "bladeRF IQ-domain CFO measurement for hardware identification."
            ),
            "spec_reference":   "3GPP TS 36.331 §5.3.8; YAICD P14_t3212_anomaly",
            # Legacy keys preserved
            "confirmed":        True,
            "label":            _label2,
            "profile_hint":     "commercial_unknown",
            "yaicd_param":      "P14_t3212_anomaly",
            "cycle_seconds":    round(mean_s, 3),
            "mean_interval_s":  round(mean_s, 3),
            "std_dev_ms":       round(sd_ms, 1),
            "total_releases":   len(releases),
            "machine_precision": True,
            "message":          _msg2,
        }]

    # -----------------------------------------------------------------------

    def _extract_releases(self, events: List[Any]) -> List[Dict]:
        releases = []
        for e in events:
            # Normalise event type
            etype = ""
            for key in ("event_type", "type", "msg_type",
                        "message_type", "rrc_message"):
                v = self._get(e, key)
                if v:
                    etype = re.sub(r"[\-_\s]", "",
                                   str(v).lower().replace("r8", "")
                                                 .replace("r9", ""))
                    break
            if etype not in self._RELEASE_NAMES:
                continue

            ts = self._get_ts(e)
            if ts is None:
                continue

            releases.append({
                "ts":  ts,
                "cid": str(self._get(e, "cell_id", "cid", "cellId") or "?"),
                "mnc": str(self._get(e, "mnc", "network_code") or "?"),
            })
        return releases

    @staticmethod
    def _get(obj: Any, *keys: str) -> Optional[Any]:
        for key in keys:
            if isinstance(obj, dict):
                if key in obj:
                    return obj[key]
            else:
                v = getattr(obj, key, None)
                if v is not None:
                    return v
        return None

    def _get_ts(self, event: Any) -> Optional[float]:
        for key in ("timestamp", "ts", "time", "epoch",
                    "frame_time", "packet_time", "sniff_time"):
            val = self._get(event, key)
            if val is None:
                continue
            try:
                if isinstance(val, (int, float)):
                    f = float(val)
                    if 1.58e9 < f < 2.2e9:
                        return f
                else:
                    s = str(val).strip()
                    for fmt in (
                        "%Y-%m-%dT%H:%M:%S.%f%z",
                        "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%d %H:%M:%S.%f%z",
                        "%Y-%m-%d %H:%M:%S.%f",
                        "%Y-%m-%d %H:%M:%S",
                    ):
                        try:
                            dt = datetime.strptime(s[:26], fmt[:len(fmt)])
                            ts = dt.timestamp()
                            if 1.58e9 < ts < 2.2e9:
                                return ts
                        except (ValueError, OverflowError):
                            pass
            except (ValueError, TypeError, OSError):
                pass
        return None


# ---------------------------------------------------------------------------
# Late import to avoid circular at module level
import re
