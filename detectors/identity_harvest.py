#!/usr/bin/env python3
"""
Identity Harvest Detector ? IMSI/IMEI/IMEISV Catcher Detection
===============================================================
Flags abnormal Identity Request patterns consistent with IMSI catchers.
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


IDENTITY_TYPE_LABELS = {
    "IMSI":     "IMSI",
    "IMEI":     "IMEI",
    "IMEISV":   "IMEISV",
    "TMSI":     "TMSI",
    "GUTI":     "GUTI",
    None:       "IMSI",
}

IDENTITY_TYPE_SEVERITY = {
    "IMSI":   "CRITICAL",
    "IMEI":   "HIGH",
    "IMEISV": "LOW",
    "TMSI":   "MEDIUM",
    "GUTI":   "MEDIUM",
    None:     "CRITICAL",
}


class IdentityHarvestDetector(BaseDetector):
    name = "IdentityHarvestDetector"
    description = "Detects IMSI/IMEI/IMEISV catcher patterns via abnormal Identity Request sequences"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        det_cfg = cfg.get("detection", {}) if isinstance(cfg, dict) else {}
        ih_cfg = det_cfg.get("identity_harvest", {}) if isinstance(det_cfg, dict) else {}
        self.window = ih_cfg.get(
            "window_seconds",
            self.thresholds.get("identity_request_window_seconds", 120),
        )
        self.max_normal = ih_cfg.get(
            "max_requests",
            self.thresholds.get("identity_request_max_normal", 2),
        )

    def _is_protected(self, event: Dict) -> bool:
        sec_hdr = event.get("security_header_type")
        if sec_hdr is not None and str(sec_hdr) not in ("0", "None", ""):
            try:
                if int(sec_hdr) != 0:
                    return True
            except (ValueError, TypeError):
                return True
        return False

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []

        id_requests = self.filter_by_type(events, ["Identity Request"])
        if not id_requests:
            id_requests = [
                e for e in events
                if (
                    "IMSI_HARVEST" in e.get("threats", [])
                    or "IMSI_EXPOSURE_CONTEXT" in e.get("threats", [])
                    or any("imsi" in str(a).lower() or "identity" in str(a).lower()
                           for a in e.get("harness_alerts", []))
                )
            ]

        if not id_requests:
            return findings

        imsi_reqs   = [e for e in id_requests if e.get("identity_type") in ("IMSI", None)]
        imeisv_reqs = [e for e in id_requests if e.get("identity_type") in ("IMEISV", "IMEI/IMEISV")]
        imei_reqs   = [e for e in id_requests if e.get("identity_type") == "IMEI"]
        tmsi_reqs   = [e for e in id_requests if e.get("identity_type") in ("TMSI", "GUTI")]

        window = self.window
        max_normal = self.max_normal

        # Rule 1: IMEISV requests
        if imeisv_reqs:
            all_protected = all(self._is_protected(e) for e in imeisv_reqs)
            sev = "LOW" if all_protected else "INFO"
            findings.append(make_finding(
                detector=self.name,
                title=f"IMEISV Device Fingerprinting Detected ? {len(imeisv_reqs)} Event(s)",
                description=(
                    f"{len(imeisv_reqs)} NAS Identity Request(s) for IMEISV (identity type 3) "
                    f"observed. Source: 3GPP TS 24.301 ?5.4.4.3."
                ),
                severity=sev,
                confidence="CONFIRMED",
                technique="IMEISV Harvesting / Targeted Device Fingerprinting",
                evidence=self._format_evidence(imeisv_reqs),
                events=imeisv_reqs,
                action="Document frame numbers and timestamps; cross-reference with session events.",
                spec_ref="3GPP TS 24.301 ?5.4.4.3, TS 33.401",
            ))

        # Rule 2: IMEI requests
        if imei_reqs:
            findings.append(make_finding(
                detector=self.name,
                title=f"IMEI Hardware ID Harvesting ? {len(imei_reqs)} Event(s)",
                description=(
                    f"{len(imei_reqs)} NAS Identity Request(s) for IMEI (identity type 2) "
                    f"observed."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="IMEI Harvesting / Device Hardware Identification",
                evidence=self._format_evidence(imei_reqs),
                events=imei_reqs,
                spec_ref="3GPP TS 24.301 ?5.4.4.2",
            ))

        # Rule 3: IMSI flood (evaluated per source_file)
        if imsi_reqs:
            by_file: Dict[str, List[Dict]] = {}
            for e in imsi_reqs:
                src = str(e.get("source_file") or "__default__")
                by_file.setdefault(src, []).append(e)

            for src, file_reqs in by_file.items():
                if len(file_reqs) <= max_normal:
                    continue
                valid_ts = [t for t in (self.parse_timestamp(e) for e in file_reqs) if t and t > 0]
                has_times = len(valid_ts) == len(file_reqs) and len(valid_ts) > 0
                in_window = self._count_in_window(valid_ts, window) if has_times else len(file_reqs)

                if in_window > max_normal:
                    if has_times:
                        findings.append(make_finding(
                            detector=self.name,
                            title=f"Repeated IMSI Identity Requests ? {in_window} in {window}s ({src})",
                            description=(
                                f"{in_window} IMSI Identity Requests detected within a "
                                f"{window}-second window in {src} (normal ?{max_normal})."
                            ),
                            severity="CRITICAL",
                            confidence="CONFIRMED",
                            technique="IMSI Harvesting via Identity Request Flood",
                            evidence=self._format_evidence(file_reqs[:8]),
                            events=file_reqs,
                            spec_ref="3GPP TS 24.301 ?5.4.4, TS 33.401 ?8.2",
                        ))
                    else:
                        findings.append(make_finding(
                            detector=self.name,
                            title=f"Untimed IMSI Identity Requests ? {len(file_reqs)} Event(s)",
                            description=(
                                f"{len(file_reqs)} untimed IMSI Identity Request(s) observed "
                                f"without valid timestamps; window rate cannot be confirmed."
                            ),
                            severity="MEDIUM",
                            confidence="SUSPECTED",
                            technique="Untimed Identity Request Burst",
                            evidence=self._format_evidence(file_reqs[:8]),
                            events=file_reqs,
                            spec_ref="3GPP TS 24.301 ?5.4.4",
                        ))

        # Rule 4: Any identity request with no prior Attach/TAU
        all_id_reqs = imsi_reqs + imeisv_reqs + imei_reqs + tmsi_reqs
        attach_events = self.filter_by_type(
            events, ["Attach Request", "Tracking Area Update Request"]
        )
        if all_id_reqs and not attach_events:
            unprovoked = [e for e in all_id_reqs if e.get("identity_type") not in ("TMSI", "GUTI")]
            if unprovoked:
                all_protected_unprovoked = all(self._is_protected(e) for e in unprovoked)
                any_timed = any((self.parse_timestamp(e) or 0) > 0 for e in unprovoked)
                if all_protected_unprovoked:
                    sev = "LOW"
                    conf = "SUSPECTED"
                elif not any_timed:
                    sev = "MEDIUM"
                    conf = "SUSPECTED"
                else:
                    sev = "HIGH"
                    conf = "PROBABLE"
                id_type_str = self._summarise_types(unprovoked)
                findings.append(make_finding(
                    detector=self.name,
                    title="Unprovoked Identity Request ? No Prior Attach",
                    description=(
                        f"{id_type_str} Identity Request(s) observed with no preceding Attach "
                        f"or Tracking Area Update Request."
                    ),
                    severity=sev,
                    confidence=conf,
                    technique="Unprovoked Identity Solicitation",
                    evidence=self._format_evidence(unprovoked[:4]),
                    events=unprovoked,
                    spec_ref="3GPP TS 24.301 ?5.4.4",
                ))

        # Rule 5: Identity request after Auth Reject (requires valid timestamps)
        auth_rejects = self.filter_by_type(events, ["Authentication Reject"])
        if auth_rejects and all_id_reqs:
            for ar in auth_rejects:
                ar_ts = self.parse_timestamp(ar)
                if not ar_ts or ar_ts <= 0:
                    continue
                nearby_reqs = []
                for r in all_id_reqs:
                    r_ts = self.parse_timestamp(r)
                    if r_ts and r_ts > 0 and abs(r_ts - ar_ts) < 10:
                        nearby_reqs.append(r)
                if nearby_reqs:
                    id_type_str = self._summarise_types(nearby_reqs)
                    findings.append(make_finding(
                        detector=self.name,
                        title="Identity Request Following Authentication Reject",
                        description=(
                            f"A {id_type_str} Identity Request was sent within 10 seconds of "
                            f"an Authentication Reject."
                        ),
                        severity="HIGH",
                        confidence="CONFIRMED",
                        technique="Auth Reject -> Identity Request (identity extraction)",
                        evidence=self._format_evidence([ar] + nearby_reqs),
                        events=[ar] + nearby_reqs,
                        spec_ref="3GPP TS 24.301 ?5.4.3.2",
                    ))
                    break

        return findings

    def _count_in_window(self, timestamps: List[float], window: float) -> int:
        if not timestamps:
            return 0
        timestamps = sorted(timestamps)
        max_count = 1
        start = 0
        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > window:
                start += 1
            max_count = max(max_count, end - start + 1)
        return max_count

    def _summarise_types(self, events: List[Dict]) -> str:
        types = {}
        for e in events:
            t = e.get("identity_type") or "IMSI"
            types[t] = types.get(t, 0) + 1
        return ", ".join(f"{count}x{t}" for t, count in sorted(types.items()))

    def _format_evidence(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts   = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg  = e.get("msg_type", "Identity Request")
            id_t = e.get("identity_type", "unknown")
            cell = e.get("cell_id", "")
            src  = e.get("source_file", "")
            line = f"[{ts}] {msg} id_type={id_t}"
            if cell:
                line += f" cell={cell}"
            if src:
                line += f" ({src})"
            lines.append(line)
        return lines
