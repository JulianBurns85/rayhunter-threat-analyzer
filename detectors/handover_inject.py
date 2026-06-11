#!/usr/bin/env python3
"""
Handover Inject Detector
========================
Detects injected handover commands — RRC Connection Reconfiguration with
mobilityControlInfo present but no preceding MeasurementReport from the UE.

v2.5 INTEGRITY CORRECTION (12 Jun 2026)
=======================================
MeasurementReport is an UPLINK (UE -> eNB) message. Many QMDL/diag captures are
downlink-biased and do not reliably log UL-DCCH, so the *absence* of a captured
MeasurementReport before a handover does NOT prove the handover was injected —
it may simply mean the report wasn't in the capture. The previous logic treated
that absence as CONFIRMED CRITICAL injection (finding [3]).

This version:
  * Keeps the existing payload guard (flag alone never confirms a handover).
  * If the WHOLE capture contains zero MeasurementReports, declares the UL
    measurement channel un-captured and reports INFO ("cannot assess"), never
    CRITICAL.
  * Requires independent corroboration (EEA0 selection or a forced redirect in
    the same/adjacent session) before a missing-measurement handover can rise to
    CRITICAL. Otherwise it caps at SUSPECTED/MEDIUM.
  * Notes when target cells are plausibly legitimate neighbours.

Reference: 3GPP TS 36.331 §5.3.5; TS 33.401 §8.3.
"""

from typing import List, Dict
from .base import BaseDetector, make_finding


class HandoverInjectDetector(BaseDetector):
    name = "HandoverInjectDetector"
    description = "Detects injected handover commands and LTE ProSe proximity tracking"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []
        findings.extend(self._detect_handover_inject(events))
        findings.extend(self._detect_prose_tracking(events))
        return findings

    def _detect_handover_inject(self, events: List[Dict]) -> List[Dict]:
        findings = []

        candidates = [
            e for e in events
            if e.get("has_mobility_control")
            and "reconfigur" in str(e.get("msg_type", "")).lower()
        ]

        def _has_handover_payload(e) -> bool:
            tpci = e.get("target_pci"); t304 = e.get("t304"); tearfcn = e.get("target_earfcn")
            has_target = tpci not in (None, "", "?")
            has_timer  = t304 not in (None, "", "?", 0)
            has_freq   = tearfcn not in (None, "", "?")
            return has_target and (has_timer or has_freq)

        verified   = [e for e in candidates if _has_handover_payload(e)]
        unverified = [e for e in candidates if not _has_handover_payload(e)]

        if unverified and not verified:
            findings.append(make_finding(
                detector=self.name,
                title="Reconfiguration flagged as handover but IE not decoded",
                description=(
                    f"{len(unverified)} event(s) carried has_mobility_control=True but no "
                    f"decoded mobilityControlInfo payload. Parser-flag/decode mismatch, NOT "
                    f"a confirmed handover."
                ),
                severity="INFO", confidence="SUSPECTED",
                technique="Data-quality check — unverified handover flag",
                evidence=self._fmt(unverified), events=unverified,
                action=("1. Decode the flagged frames in Wireshark and confirm whether "
                        "mobilityControlInfo is present.\n2. If absent, fix the parser flag.\n"
                        "3. Do not cite as handover injection until corroborated."),
                spec_ref="3GPP TS 36.331 5.3.5.4 (mobilityControlInfo)",
            ))

        reconfig_with_mci = verified
        if not reconfig_with_mci:
            return findings

        # ── UL measurement-channel availability check ────────────────────
        meas_reports = [e for e in events if e.get("has_measreport")]
        meas_timestamps = sorted([self.parse_timestamp(e) for e in meas_reports if self.parse_timestamp(e) > 0])

        if not meas_timestamps:
            # No MeasurementReports anywhere => UL not captured => cannot assess.
            findings.append(make_finding(
                detector=self.name,
                title="Handover(s) present — UL MeasurementReport channel NOT captured",
                description=(
                    f"{len(reconfig_with_mci)} decoded handover command(s) observed, but the "
                    f"capture contains ZERO MeasurementReports. MeasurementReport is an uplink "
                    f"(UE->eNB) message; its total absence means the UL-DCCH was not captured, "
                    f"so 'handover without preceding measurement' CANNOT be assessed from this "
                    f"data and is NOT evidence of injection. Re-capture with uplink, or decode "
                    f"the measConfig to confirm measurements were configured."
                ),
                severity="INFO", confidence="SUSPECTED",
                technique="Capture-completeness check (uplink measurement channel absent)",
                evidence=self._fmt(reconfig_with_mci), events=reconfig_with_mci,
                action=(
                    "1. Confirm whether the capture includes UL-DCCH.\n"
                    "2. Decode RRCConnectionReconfiguration measConfig — if measurements were "
                    "configured, subsequent handovers are expected and legitimate.\n"
                    "3. Do NOT cite as injected handover without uplink data."
                ),
                spec_ref="3GPP TS 36.331 §5.3.5",
                hardware_hint="Inconclusive — capture lacks uplink measurement channel.",
            ))
            return findings

        # Some measurement reports exist; check each handover for a prior one.
        injected = []
        for reconfig in reconfig_with_mci:
            rts = self.parse_timestamp(reconfig)
            has_prior = any(0 < rts - mt < 5.0 for mt in meas_timestamps)
            if not has_prior:
                injected.append(reconfig)

        if not injected:
            return findings

        # Independent corroboration: EEA0 or forced redirect anywhere in capture.
        corroborated = any(
            str(e.get("cipher_alg", "")).lower() == "eea0"
            or e.get("has_geran_redirect")
            or e.get("has_redirect")
            for e in events
        )

        if corroborated:
            findings.append(make_finding(
                detector=self.name,
                title="Injected Handover — mobilityControlInfo Without MeasurementReport (corroborated)",
                description=(
                    f"{len(injected)} handover command(s) lacked a preceding MeasurementReport "
                    f"AND the capture independently shows a cipher/redirect attack indicator. "
                    + (self._target_summary(injected) or "Target cell parameters not extracted.")
                ),
                severity="CRITICAL", confidence="PROBABLE",
                technique="Forced Handover Injection (corroborated by cipher/redirect)",
                evidence=self._fmt(injected), events=injected,
                hardware_hint="Active rogue eNodeB with handover injection capability.",
                action=("1. Document each handover with timestamp and target cell.\n"
                        "2. Cross-reference the corroborating EEA0/redirect event timestamps.\n"
                        "3. Cite 3GPP TS 36.331 §5.3.5 and the corroborating indicator together."),
                spec_ref="3GPP TS 36.331 §5.3.5, TS 33.401 §8.3",
            ))
        else:
            findings.append(make_finding(
                detector=self.name,
                title="Handover(s) Without Captured MeasurementReport — UNCONFIRMED",
                description=(
                    f"{len(injected)} RRC Reconfiguration(s) with mobilityControlInfo had no "
                    f"MeasurementReport within 5s before them. Some measurement reports exist "
                    f"in the capture, but a missing report per-handover can result from capture "
                    f"gaps, measConfig set earlier in the session, or normal blind/intra-freq "
                    f"handover. No independent cipher/redirect corroboration found, so this is "
                    f"a lead, not a confirmed attack. "
                    + (self._target_summary(injected) or "")
                ),
                severity="MEDIUM", confidence="SUSPECTED",
                technique="Possible Handover Injection (uncorroborated)",
                evidence=self._fmt(injected), events=injected,
                action=("1. Decode the session measConfig to see if measurements were configured.\n"
                        "2. Verify target PCIs/EARFCNs are foreign (not legitimate neighbours).\n"
                        "3. Escalate only if corroborated by EEA0 or redirect."),
                spec_ref="3GPP TS 36.331 §5.3.5",
                hardware_hint="Inconclusive without corroboration.",
            ))

        return findings

    def _detect_prose_tracking(self, events: List[Dict]) -> List[Dict]:
        findings = []
        prose_events = [e for e in events if e.get("has_prose")]
        if not prose_events:
            prose_events = [
                e for e in events
                if any("prose" in str(a).lower() or "proximity" in str(a).lower()
                       for a in e.get("harness_alerts", []))
            ]
        if prose_events:
            # Downgraded from CONFIRMED: many parsers set has_prose from a flag that
            # is not the actual reportProximityConfig-r9 IE. Require decode confirmation.
            decoded = [e for e in prose_events if e.get("prose_ie_decoded")]
            confidence = "CONFIRMED" if decoded else "SUSPECTED"
            severity   = "HIGH" if decoded else "MEDIUM"
            findings.append(make_finding(
                detector=self.name,
                title="LTE ProSe Proximity Config (reportProximityConfig-r9)"
                      + ("" if decoded else " — flag only, IE not decoded"),
                description=(
                    f"{len(prose_events)} RRC message(s) flagged with ProSe proximity reporting. "
                    + ("IE decode-confirmed." if decoded else
                       "Set from a parser flag without confirming the reportProximityConfig-r9 "
                       "IE in the decode — verify before citing.")
                ),
                severity=severity, confidence=confidence,
                technique="LTE ProSe Proximity Tracking (3GPP TS 36.331 §6.3.6)",
                evidence=self._fmt(prose_events), events=prose_events,
                hardware_hint="Modified eNodeB with ProSe capability (if IE confirmed).",
                action=("1. Decode the RRC frame and confirm reportProximityConfig-r9 is present.\n"
                        "2. Only cite as tracking if the IE is in the decode, not just the flag."),
                spec_ref="3GPP TS 36.331 §6.3.6, TS 36.300 §22 (ProSe), TS 33.303",
            ))
        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts   = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg  = e.get("msg_type", "RRC Connection Reconfiguration")
            tpci = e.get("target_pci", "?")
            tearfcn = e.get("target_earfcn", "?")
            t304 = e.get("t304", "")
            rnti = e.get("new_rnti", "")
            mci  = "MCI=YES" if e.get("has_mobility_control") else ""
            prose = "PROSE=YES" if e.get("has_prose") else ""
            src  = e.get("source_file", "")
            extras = ""
            if t304 not in ("", None):  extras += f" T304={t304}ms"   # FIX: was {t304}00ms
            if rnti:  extras += f" C-RNTI={rnti}"
            lines.append(f"[{ts}] {msg} targetPCI={tpci} EARFCN={tearfcn}{extras} {mci} {prose} ({src})")
        return lines

    def _target_summary(self, events: List[Dict]) -> str:
        targets = {}
        for e in events:
            pci = e.get("target_pci"); earfcn = e.get("target_earfcn")
            if pci and earfcn:
                targets[(pci, earfcn)] = targets.get((pci, earfcn), 0) + 1
        if not targets:
            return ""
        parts = [f"PCI={p} EARFCN={f} ({c}x)" for (p, f), c in sorted(targets.items())]
        return "Target cell(s): " + ", ".join(parts)
