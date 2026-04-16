#!/usr/bin/env python3
"""
Handover Inject Detector
========================
Detects injected handover commands — RRC Connection Reconfiguration with
mobilityControlInfo present but no preceding MeasurementReport from the UE.

In normal LTE operation:
  UE → MeasurementReport → eNodeB → RRCConnectionReconfiguration (with MCI)

A rogue eNodeB skips the MeasurementReport and sends MCI directly, forcing
the device to hand over to an attacker-controlled cell.
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

        # Find RRC Reconfigurations with mobilityControlInfo
        reconfig_with_mci = [
            e for e in events
            if e.get("has_mobility_control")
            and (
                "RRC Connection Reconfiguration" in str(e.get("msg_type", ""))
                or e.get("has_mobility_control")
            )
        ]

        if not reconfig_with_mci:
            return findings

        # Find MeasurementReports
        meas_reports = [e for e in events if e.get("has_measreport")]
        meas_timestamps = sorted([self.parse_timestamp(e) for e in meas_reports])

        # For each handover, check if there was a MeasReport within 5 seconds before it
        injected = []
        for reconfig in reconfig_with_mci:
            reconfig_ts = self.parse_timestamp(reconfig)
            has_prior_measreport = any(
                0 < reconfig_ts - mt < 5.0
                for mt in meas_timestamps
                if mt > 0
            )
            if not has_prior_measreport or not meas_timestamps:
                injected.append(reconfig)

        max_without = self.thresholds.get("handover_max_without_measreport", 2)

        if len(injected) > max_without:
            findings.append(make_finding(
                detector=self.name,
                title="Injected Handover — mobilityControlInfo Without MeasurementReport",
                description=(
                    f"{len(injected)} RRC Connection Reconfiguration message(s) contained "
                    f"mobilityControlInfo (handover command) with no preceding MeasurementReport "
                    f"from the UE. In legitimate LTE: UE reports measurements THEN network "
                    f"triggers handover. A rogue eNodeB skips this to force the device "
                    f"to hand over to an attacker-controlled cell without the UE's consent."
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
                technique="Forced Handover Injection (mobilityControlInfo without MeasurementReport)",
                evidence=self._fmt(injected),
                events=injected,
                hardware_hint=(
                    "Active rogue eNodeB with LTE handover injection capability. "
                    "This is advanced attack infrastructure (not consumer hardware)."
                ),
                action=(
                    "1. Document each injected handover with timestamp and Cell ID.\n"
                    "2. Cross-reference target cell ID — this is likely the secondary rogue cell.\n"
                    "3. Cite 3GPP TS 36.331 §5.3.5 (handover procedure) in evidence.\n"
                    "4. This requires a rogue eNodeB with full LTE stack — report to AFP.\n"
                    "5. Correlate with null-cipher events after the handover."
                ),
                spec_ref="3GPP TS 36.331 §5.3.5, TS 33.401 §8.3",
            ))
        elif injected:
            findings.append(make_finding(
                detector=self.name,
                title="Suspicious Handover Without MeasurementReport",
                description=(
                    f"{len(injected)} RRC Reconfiguration(s) with mobilityControlInfo "
                    f"observed with no preceding MeasurementReport. "
                    f"Could indicate injected handover or missing log data."
                ),
                severity="MEDIUM",
                confidence="SUSPECTED",
                technique="Possible Handover Injection",
                evidence=self._fmt(injected),
                events=injected,
                action=(
                    "Correlate with cipher downgrade events. If combined with EEA0, "
                    "this confirms injected handover to a rogue cell."
                ),
                spec_ref="3GPP TS 36.331 §5.3.5",
            ))

        return findings

    def _detect_prose_tracking(self, events: List[Dict]) -> List[Dict]:
        """
        Detect LTE ProSe (Device-to-Device) proximity tracking configuration.
        reportProximityConfig-r9 in RRC Connection Reconfiguration enables the
        network to track when the UE is physically near another specific device.
        """
        findings = []
        prose_events = [e for e in events if e.get("has_prose")]

        if not prose_events:
            # Also check harness alerts
            prose_events = [
                e for e in events
                if any("prose" in str(a).lower() or "proximity" in str(a).lower()
                       for a in e.get("harness_alerts", []))
            ]

        if prose_events:
            findings.append(make_finding(
                detector=self.name,
                title="LTE ProSe Proximity Tracking Config (reportProximityConfig-r9)",
                description=(
                    f"{len(prose_events)} RRC message(s) contain reportProximityConfig-r9, "
                    f"which enables LTE ProSe (Device-to-Device) proximity reporting. "
                    f"This IE instructs the UE to report when it is physically near another "
                    f"device — enabling real-time physical location tracking without GPS. "
                    f"This was documented in your CIRS-20260331-141 investigation."
                ),
                severity="HIGH",
                confidence="CONFIRMED",
                technique="LTE ProSe Proximity Tracking (3GPP TS 36.331 §6.3.6 reportProximityConfig-r9)",
                evidence=self._fmt(prose_events),
                events=prose_events,
                hardware_hint=(
                    "Modified eNodeB with ProSe configuration capability. "
                    "Typically requires carrier-grade equipment or compromised network infrastructure."
                ),
                action=(
                    "1. Document the RRC Reconfiguration packet containing reportProximityConfig-r9.\n"
                    "2. This IE is not used in normal commercial operation — its presence is anomalous.\n"
                    "3. Cite 3GPP TS 36.331 §6.3.6 and TS 36.300 §22 (ProSe) in evidence.\n"
                    "4. Report to ACMA — proximity tracking by a rogue network device may constitute\n"
                    "   surveillance under the Privacy Act 1988 (Cth) and TIA Act 1979.\n"
                    "5. Include in AFP/ACORN referral as evidence of targeted tracking."
                ),
                spec_ref="3GPP TS 36.331 §6.3.6, TS 36.300 §22 (ProSe), TS 33.303",
            ))

        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg = e.get("msg_type", "?")
            cell = e.get("cell_id", "?")
            earfcn = e.get("earfcn", "?")
            mci = "MCI=YES" if e.get("has_mobility_control") else ""
            prose = "PROSE=YES" if e.get("has_prose") else ""
            src = e.get("source_file", "")
            lines.append(f"[{ts}] {msg} cell={cell} EARFCN={earfcn} {mci} {prose} ({src})")
        return lines
