#!/usr/bin/env python3
"""
AuthenticationAbsenceDetector — Flags sessions with anomalously low auth rates.

Refactored from new_detectors.py to use BaseDetector + make_finding().
Place in: detectors/auth_absence.py

References:
  - 3GPP TS 24.301 §5.4.3 (EPS Authentication)
  - 3GPP TS 33.401 §6.1 (Authentication framework)
  - Tucker et al. (NDSS 2025) — causal vs. correlated indicators
"""

from typing import List, Dict
from .base import BaseDetector, make_finding

CRITICAL_THRESHOLD = 0.10   # < 10% auth rate
HIGH_THRESHOLD     = 0.50
MEDIUM_THRESHOLD   = 0.80
MIN_CONNECTIONS    = 5


class AuthenticationAbsenceDetector(BaseDetector):
    """
    Detects sessions where authentication rate is anomalously low.

    IMSI catchers acting as MitM proxies may skip authentication entirely
    or authenticate only on initial connection, producing rates far below
    the expected ≥90% for legitimate Attach procedures.
    """

    name        = "AuthenticationAbsenceDetector"
    description = "Flags sessions with anomalously low NAS authentication rates"

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        smc_count        = 0
        auth_req_count   = 0
        auth_resp_count  = 0
        attach_count     = 0
        service_req_count= 0

        for ev in events:
            mt = str(ev.get("msg_type", "") or ev.get("msg", "")).lower()
            if "securitymodecommand" in mt and "complete" not in mt:
                smc_count += 1
            elif "authentication request" in mt or "authenticationrequest" in mt:
                auth_req_count += 1
            elif "authentication response" in mt or "authenticationresponse" in mt:
                auth_resp_count += 1
            elif "attach request" in mt or "attachrequest" in mt:
                attach_count += 1
            elif "service request" in mt or "servicerequest" in mt:
                service_req_count += 1

        total = smc_count
        if total < MIN_CONNECTIONS:
            return findings

        completed_auth  = min(auth_req_count, auth_resp_count)
        auth_rate       = completed_auth / total if total > 0 else 1.0
        unauthenticated = total - completed_auth

        if auth_rate >= MEDIUM_THRESHOLD:
            return findings

        if   auth_rate < CRITICAL_THRESHOLD: severity, confidence = "CRITICAL", "CONFIRMED"
        elif auth_rate < HIGH_THRESHOLD:     severity, confidence = "HIGH",     "PROBABLE"
        else:                                severity, confidence = "MEDIUM",   "SUSPECTED"

        description = (
            f"{completed_auth}/{total} connections authenticated "
            f"({auth_rate*100:.1f}%). "
            f"{unauthenticated} connections reached SecurityModeCommand "
            f"without Authentication Request/Response. "
        )
        if attach_count > 0:
            description += (
                f"{attach_count} Attach procedures observed — legitimate networks "
                f"authenticate ≥90% of Attach procedures. "
            )
        if service_req_count > 0:
            description += (
                f"{service_req_count} Service Requests (may legitimately skip auth "
                f"via NAS security context reuse per TS 24.301 §5.4.3.2). "
            )

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Authentication Absence — {auth_rate*100:.1f}% auth rate "
                f"({completed_auth}/{total} connections)"
            ),
            description=description,
            severity=severity,
            confidence=confidence,
            technique="Authentication bypass / NAS security context exploitation",
            evidence=[
                f"Total connections (SMC): {total}",
                f"Authenticated: {completed_auth} ({auth_rate*100:.1f}%)",
                f"Unauthenticated: {unauthenticated}",
                f"Attach procedures: {attach_count}",
                f"Service Requests: {service_req_count}",
            ],
            events=[],
            action=(
                "Compare auth rate against legitimate baseline (≥90% for Attach). "
                "Cross-reference with carrier records for eNB authentication policy. "
                "Verify with tshark: count Authentication Request vs SecurityModeCommand."
            ),
            spec_ref="3GPP TS 24.301 §5.4.3, TS 33.401 §6.1",
            hardware_hint="Active IMSI catcher in MitM transparent proxy mode",
        ))

        return findings
