#!/usr/bin/env python3
"""
Handover Inject Detector
========================
Detects injected handover commands ? RRC Connection Reconfiguration with
mobilityControlInfo present and valid timestamps, evaluated per source_file.
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

        verified = [e for e in candidates if _has_handover_payload(e)]
        unverified = [e for e in candidates if not _has_handover_payload(e)]

        if unverified and not verified:
            findings.append(make_finding(
                detector=self.name,
                title="Reconfiguration flagged as handover but IE not decoded",
                description=(
                    f"{len(unverified)} event(s) carried has_mobility_control=True but no "
                    f"decoded mobilityControlInfo payload."
                ),
                severity="INFO", confidence="SUSPECTED",
                technique="Data-quality check ? unverified handover flag",
                evidence=self._fmt(unverified), events=unverified,
                spec_ref="3GPP TS 36.331 5.3.5.4 (mobilityControlInfo)",
            ))

        timed_verified = []
        for e in verified:
            rts = self.parse_timestamp(e)
            if rts is not None and rts > 0:
                timed_verified.append((e, rts))

        if not timed_verified:
            return findings

        # Group by source_file so corroboration and UL measurement availability are per-file
        by_file: Dict[str, List[tuple]] = {}
        for e, rts in timed_verified:
            src = str(e.get("source_file") or "__default__")
            by_file.setdefault(src, []).append((e, rts))

        for src, file_handovers in by_file.items():
            file_events = [
                ev for ev in events
                if str(ev.get("source_file") or "__default__") == src
            ]
            file_meas = [ev for ev in file_events if ev.get("has_measreport")]
            file_meas_ts = sorted([
                t for t in (self.parse_timestamp(ev) for ev in file_meas)
                if t is not None and t > 0
            ])

            if not file_meas_ts:
                ho_evs = [e for e, _ in file_handovers]
                findings.append(make_finding(
                    detector=self.name,
                    title=f"Handover injection not assessable ? no MeasurementReports in {src}",
                    description=(
                        f"{len(ho_evs)} decoded handover command(s) observed in {src}, "
                        f"but {src} contains zero MeasurementReports."
                    ),
                    severity="INFO", confidence="SUSPECTED",
                    technique="Capture-completeness check (uplink measurement channel absent)",
                    evidence=self._fmt(ho_evs), events=ho_evs,
                    spec_ref="3GPP TS 36.331 ?5.3.5",
                ))
                continue

            injected = []
            for reconfig, rts in file_handovers:
                has_prior = any(0 < rts - mt < 5.0 for mt in file_meas_ts)
                if not has_prior:
                    injected.append(reconfig)

            if not injected:
                continue

            corroborated = any(
                str(ev.get("cipher_alg", "")).lower() == "eea0"
                or bool(ev.get("has_geran_redirect"))
                or bool(ev.get("has_redirect"))
                for ev in file_events
            )

            if corroborated:
                findings.append(make_finding(
                    detector=self.name,
                    title="Injected Handover ? mobilityControlInfo Without MeasurementReport (corroborated)",
                    description=(
                        f"{len(injected)} handover command(s) in {src} lacked a preceding "
                        f"MeasurementReport AND {src} shows a cipher/redirect indicator. "
                        + (self._target_summary(injected) or "")
                    ),
                    severity="CRITICAL", confidence="PROBABLE",
                    technique="Forced Handover Injection (corroborated by cipher/redirect)",
                    evidence=self._fmt(injected), events=injected,
                    spec_ref="3GPP TS 36.331 ?5.3.5, TS 33.401 ?8.3",
                ))
            else:
                findings.append(make_finding(
                    detector=self.name,
                    title="Handover(s) Without Captured MeasurementReport ? UNCONFIRMED",
                    description=(
                        f"{len(injected)} RRC Reconfiguration(s) in {src} had no "
                        f"MeasurementReport within 5s before them."
                    ),
                    severity="MEDIUM", confidence="SUSPECTED",
                    technique="Possible Handover Injection (uncorroborated)",
                    evidence=self._fmt(injected), events=injected,
                    spec_ref="3GPP TS 36.331 ?5.3.5",
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
            decoded = [e for e in prose_events if e.get("prose_ie_decoded")]
            confidence = "CONFIRMED" if decoded else "SUSPECTED"
            severity = "HIGH" if decoded else "MEDIUM"
            findings.append(make_finding(
                detector=self.name,
                title="LTE ProSe Proximity Config (reportProximityConfig-r9)"
                      + ("" if decoded else " ? flag only, IE not decoded"),
                description=f"{len(prose_events)} RRC message(s) flagged with ProSe proximity reporting.",
                severity=severity, confidence=confidence,
                technique="LTE ProSe Proximity Tracking (3GPP TS 36.331 ?6.3.6)",
                evidence=self._fmt(prose_events), events=prose_events,
                spec_ref="3GPP TS 36.331 ?6.3.6, TS 36.300 ?22 (ProSe), TS 33.303",
            ))
        return findings

    def _fmt(self, events: List[Dict]) -> List[str]:
        lines = []
        for e in events[:6]:
            ts      = e.get("timestamp") or e.get("raw", {}).get("packet_timestamp", "?")
            msg     = e.get("msg_type", "RRC Connection Reconfiguration")
            tpci    = e.get("target_pci", "?")
            tearfcn = e.get("target_earfcn", "?")
            t304    = e.get("t304", "")
            rnti    = e.get("new_rnti", "")
            mci     = "MCI=YES" if e.get("has_mobility_control") else ""
            prose   = "PROSE=YES" if e.get("has_prose") else ""
            src     = e.get("source_file", "")
            extras  = ""
            if t304 not in ("", None):
                extras += f" T304={t304}ms"
            if rnti:
                extras += f" C-RNTI={rnti}"
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
