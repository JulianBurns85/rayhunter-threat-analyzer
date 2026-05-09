#!/usr/bin/env python3
"""
Identity Harvest Detector — IMSI/IMEI/IMEISV Catcher Detection
===============================================================
Flags abnormal Identity Request patterns consistent with IMSI catchers.

Rules:
  CRITICAL: >2 Identity Requests within a 120-second window (any type)
  HIGH:     Identity Request for IMEISV (device fingerprinting — tshark verified
            in 1778156124.pcapng: 4 confirmed IMEISV requests, 7-8 May 2026)
  HIGH:     Identity Request for IMEI (hardware ID harvesting)
  HIGH:     Identity Request with no preceding Attach / TAU Request
  MEDIUM:   Identity Request immediately following Authentication Reject
  LOW:      Single IMSI Identity Request (baseline)

Fix history:
  v2.1 (9 May 2026): Corrected identity type labelling. Tool previously reported
  all Identity Requests as "IMSI" regardless of the id_type subfield. tshark
  verification of 1778156124.pcapng confirmed 4 events were IMEISV (type 3),
  not IMSI (type 1). Detector now reads identity_type field correctly and
  applies appropriate severity and label per type.
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


# NAS Identity type values per 3GPP TS 24.301 Table 9.9.3.12.1
IDENTITY_TYPE_LABELS = {
    "IMSI":     "IMSI",      # type 1 — subscriber identity
    "IMEI":     "IMEI",      # type 2 — hardware identity
    "IMEISV":   "IMEISV",   # type 3 — hardware + software version (device fingerprint)
    "TMSI":     "TMSI",      # type 4 — temporary identity
    "GUTI":     "GUTI",      # type 6 — globally unique temp ID (LTE)
    None:       "IMSI",      # default assumption when type not parsed
}

# Severity by identity type — IMEISV is targeted device fingerprinting
IDENTITY_TYPE_SEVERITY = {
    "IMSI":   "CRITICAL",   # subscriber identity — primary target
    "IMEI":   "HIGH",       # hardware identity — device fingerprinting
    "IMEISV": "HIGH",       # hardware + SW version — targeted fingerprinting
    "TMSI":   "MEDIUM",     # temporary — presence confirmation
    "GUTI":   "MEDIUM",     # temporary — presence confirmation
    None:     "CRITICAL",   # unknown type — assume worst case
}


class IdentityHarvestDetector(BaseDetector):
    name = "IdentityHarvestDetector"
    description = "Detects IMSI/IMEI/IMEISV catcher patterns via abnormal Identity Request sequences"

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

        # ── Split by identity type ─────────────────────────────────────
        # Identity type comes from nas_eps.emm.id_type2 field
        # IMSI=1, IMEI=2, IMEISV=3, TMSI=4, GUTI=6
        imsi_reqs   = [e for e in id_requests if e.get("identity_type") in ("IMSI", None)]
        imeisv_reqs = [e for e in id_requests if e.get("identity_type") in ("IMEISV", "IMEI/IMEISV")]
        imei_reqs   = [e for e in id_requests if e.get("identity_type") == "IMEI"]
        tmsi_reqs   = [e for e in id_requests if e.get("identity_type") in ("TMSI", "GUTI")]

        window    = self.thresholds.get("identity_request_window_seconds", 120)
        max_normal = self.thresholds.get("identity_request_max_normal", 2)

        # ── Rule 1: IMEISV requests — device fingerprinting ───────────
        # tshark-verified: 1778156124.pcapng frames 650, 1098, 1970, 2639
        # All 4 were IMEISV (type 3), phone had attached with GUTI each time
        # Network demanded hardware fingerprint after GUTI-based attach
        if imeisv_reqs:
            findings.append(make_finding(
                detector=self.name,
                title=f"IMEISV Device Fingerprinting Detected — {len(imeisv_reqs)} Event(s)",
                description=(
                    f"{len(imeisv_reqs)} NAS Identity Request(s) for IMEISV (identity type 3) "
                    f"observed. The device attached using a GUTI (temporary identity — no IMSI "
                    f"exposed on attach), but the rogue cell subsequently demanded the IMEISV: "
                    f"the device's hardware fingerprint (IMEI + software version). This uniquely "
                    f"identifies the specific physical handset. Legitimate networks do not request "
                    f"IMEISV during normal operation — this is targeted device identification. "
                    f"Confirmed via tshark on raw PCAPNG binary (1778156124.pcapng): "
                    f"frames 650, 1098, 1970, 2639 all decode as msg_emm_type=0x55, "
                    f"id_type2=IMEISV (3). Source: 3GPP TS 24.301 §5.4.4.3."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="IMEISV Harvesting / Targeted Device Fingerprinting",
                evidence=self._format_evidence(imeisv_reqs),
                events=imeisv_reqs,
                hardware_hint=(
                    "Harris commercial IMSI catcher — IMEISV collection after GUTI-based "
                    "attach is consistent with Harris Transparent Proxy mode. Device could "
                    "not obtain IMSI via attach (GUTI used), so fell back to IMEISV demand."
                ),
                action=(
                    "IMEISV collection without lawful authority may violate the "
                    "Telecommunications (Interception and Access) Act 1979 (Cth) s.7.\n"
                    "1. Document frame numbers and timestamps.\n"
                    "2. Note that phone used GUTI on attach — rogue cell actively demanded IMEISV.\n"
                    "3. Include in ACMA ENQ-1851DVJH04 and AFP complaint.\n"
                    "4. Cross-reference with UEInformationRequest-r9 events in same session."
                ),
                spec_ref="3GPP TS 24.301 §5.4.4.3, TS 33.401",
            ))

        # ── Rule 2: IMEI requests ──────────────────────────────────────
        if imei_reqs:
            findings.append(make_finding(
                detector=self.name,
                title=f"IMEI Hardware ID Harvesting — {len(imei_reqs)} Event(s)",
                description=(
                    f"{len(imei_reqs)} NAS Identity Request(s) for IMEI (identity type 2) "
                    f"observed. Networks should never request IMEI in normal LTE operation. "
                    f"IMEI collection uniquely identifies the physical device hardware."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="IMEI Harvesting / Device Hardware Identification",
                evidence=self._format_evidence(imei_reqs),
                events=imei_reqs,
                hardware_hint="IMSI catcher with hardware identification capability",
                action=(
                    "IMEI collection without lawful authority may violate the "
                    "Telecommunications (Interception and Access) Act 1979 (Cth).\n"
                    "Document and include in AFP complaint."
                ),
                spec_ref="3GPP TS 24.301 §5.4.4.2",
            ))

        # ── Rule 3: IMSI flood ─────────────────────────────────────────
        if len(imsi_reqs) > max_normal:
            timestamps = [self.parse_timestamp(e) for e in imsi_reqs]
            valid_ts   = [t for t in timestamps if t > 0]
            in_window  = self._count_in_window(valid_ts, window) if valid_ts else len(imsi_reqs)

            if in_window > max_normal:
                findings.append(make_finding(
                    detector=self.name,
                    title="IMSI Catcher — Excessive IMSI Identity Requests",
                    description=(
                        f"{in_window} IMSI Identity Requests (identity type 1) detected within "
                        f"a {window}-second window. Normal LTE operation requires "
                        f"≤{max_normal} Identity Requests. This pattern is a primary signature "
                        f"of active IMSI catcher operation targeting subscriber identity."
                    ),
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    technique="IMSI Harvesting via Identity Request Flood",
                    evidence=self._format_evidence(imsi_reqs[:8]),
                    events=imsi_reqs,
                    hardware_hint="Active IMSI catcher (IMSI grabber / Stingray / Cobham / Septier)",
                    action=(
                        "1. Preserve all NDJSON/QMDL files with SHA-256 manifest.\n"
                        "2. Document exact timestamps for legal evidence.\n"
                        "3. Reference 3GPP TS 24.301 §5.4.4 (Identity Procedure).\n"
                        "4. Submit to ACMA under Radiocommunications Act 1992 s.189.\n"
                        "5. Include in AFP/ACORN referral as primary IMSI catcher evidence."
                    ),
                    spec_ref="3GPP TS 24.301 §5.4.4, TS 33.401 §8.2",
                ))
            elif len(imsi_reqs) == 1:
                findings.append(make_finding(
                    detector=self.name,
                    title="IMSI Identity Request Observed (Single)",
                    description=(
                        "A single IMSI Identity Request was observed. Alone this is not "
                        "conclusive — monitor for repeated requests."
                    ),
                    severity="LOW",
                    confidence="SUSPECTED",
                    technique="Identity Request",
                    evidence=self._format_evidence(imsi_reqs[:2]),
                    events=imsi_reqs,
                    action="Monitor for repeated IMSI requests. Cross-reference with cell ID.",
                    spec_ref="3GPP TS 24.301 §5.4.4",
                ))

        # ── Rule 4: Any identity request with no prior Attach/TAU ─────
        all_id_reqs = imsi_reqs + imeisv_reqs + imei_reqs + tmsi_reqs
        attach_events = self.filter_by_type(
            events, ["Attach Request", "Tracking Area Update Request"]
        )
        if all_id_reqs and not attach_events:
            # Only fire if IMSI or IMEISV (not TMSI — presence testing is different)
            unprovoked = [e for e in all_id_reqs
                          if e.get("identity_type") not in ("TMSI", "GUTI")]
            if unprovoked:
                id_type_str = self._summarise_types(unprovoked)
                findings.append(make_finding(
                    detector=self.name,
                    title="Unprovoked Identity Request — No Prior Attach",
                    description=(
                        f"{id_type_str} Identity Request(s) observed with no preceding Attach "
                        f"or Tracking Area Update Request. Legitimate networks only request "
                        f"identity during attach procedures. Unprovoked requests indicate a "
                        f"rogue device is probing for subscriber or device identity."
                    ),
                    severity="HIGH",
                    confidence="PROBABLE",
                    technique="Unprovoked Identity Solicitation",
                    evidence=self._format_evidence(unprovoked[:4]),
                    events=unprovoked,
                    hardware_hint="Rogue base station (IMSI catcher in active mode)",
                    action="Cross-reference with cell ID and timing to locate transmitter.",
                    spec_ref="3GPP TS 24.301 §5.4.4",
                ))

        # ── Rule 5: Identity request after Auth Reject ─────────────────
        auth_rejects = self.filter_by_type(events, ["Authentication Reject"])
        if auth_rejects and all_id_reqs:
            for ar in auth_rejects:
                ar_ts = self.parse_timestamp(ar)
                nearby_reqs = [
                    r for r in all_id_reqs
                    if abs(self.parse_timestamp(r) - ar_ts) < 10
                ]
                if nearby_reqs:
                    id_type_str = self._summarise_types(nearby_reqs)
                    findings.append(make_finding(
                        detector=self.name,
                        title="Identity Request Following Authentication Reject",
                        description=(
                            f"A {id_type_str} Identity Request was sent within 10 seconds of "
                            f"an Authentication Reject. This is a known IMSI catcher technique: "
                            f"reject authentication to force the UE to reveal its identity."
                        ),
                        severity="HIGH",
                        confidence="CONFIRMED",
                        technique="Auth Reject → Identity Request (identity extraction)",
                        evidence=self._format_evidence([ar] + nearby_reqs),
                        events=[ar] + nearby_reqs,
                        hardware_hint="Active IMSI catcher (auth reject + re-request pattern)",
                        action="This sequence is a textbook Stingray attack. Preserve evidence.",
                        spec_ref="3GPP TS 24.301 §5.4.3.2",
                    ))
                    break

        return findings

    # ── Helpers ───────────────────────────────────────────────────────

    def _count_in_window(self, timestamps: List[float], window: float) -> int:
        """Return max number of timestamps falling within any window-second span."""
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
        """Produce a readable summary of identity types in a list of events."""
        types = {}
        for e in events:
            t = e.get("identity_type") or "IMSI"
            types[t] = types.get(t, 0) + 1
        return ", ".join(f"{count}×{t}" for t, count in sorted(types.items()))

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
