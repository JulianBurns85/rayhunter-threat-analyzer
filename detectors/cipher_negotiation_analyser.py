#!/usr/bin/env python3
"""
CipherNegotiationSequenceAnalyser — cipher negotiation profiling.

v2.5 INTEGRITY CORRECTION (12 Jun 2026)
=======================================
The previous PATTERNS list classified the *legitimate* LTE attach sequence
(ATTACH -> SMC -> SMC_DONE -> ATTACH_OK) as "Harris Transparent Proxy", and
treated normal attach/release and IMEISV identity requests as IMSI-harvest.
This produced finding [5] ("EEA0 Rate: 0% — 6 Attack Patterns") on a capture
set whose every SecurityModeCommand used AES (EEA2/EIA2). A 0% EEA0 rate is
EXCULPATORY, not an attack.

This version:
  * Reports a clean, encrypted, completed attach as a HEALTHY baseline (INFO),
    not an attack.
  * Only flags GENUINELY anomalous sequences:
      - EEA0/EIA0 actually selected in an SMC (null cipher/integrity),
      - an IMSI (not IMEISV) Identity Request *before* security activation,
      - a network-originated Authentication Reject / Attach Reject harvest.
  * Splits Authentication Reject (network->UE, can be hostile) from
    Authentication Failure (UE->network MAC/synch failure, which is the UE
    *catching* a fake base station — never scored as the network attacking).
  * Distinguishes IMEISV identity requests (routine) from IMSI requests.

Reference: 3GPP TS 33.401 §8.2; TS 24.301 §5.4.x.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.base import BaseDetector, make_finding


SESSION_GAP_S = 300.0

MSG_MAP = {
    "rrcconnectionsetup":          "RRC_SETUP",
    "rrcconnectionsetupcomplete":  "RRC_SETUP",
    "securitymodecommand":         "SMC",
    "securitymodecomplete":        "SMC_DONE",
    "securitymodereject":          "SMC_REJECT",
    "identityrequest":             "IDENTITY",
    "attachrequest":               "ATTACH",
    "attachaccept":                "ATTACH_OK",
    "attachreject":                "ATTACH_REJECT",
    "rrcconnectionrelease":        "RELEASE",
    "authenticationrequest":       "AUTH",
    "authenticationreject":        "AUTH_REJECT",     # network -> UE
    "authenticationfailure":       "AUTH_FAILURE",    # UE -> network (NOT an attack)
    "security mode command":       "SMC",
    "security mode complete":      "SMC_DONE",
    "security mode reject":        "SMC_REJECT",
    "identity request":            "IDENTITY",
    "attach request":              "ATTACH",
    "attach accept":               "ATTACH_OK",
    "attach reject":               "ATTACH_REJECT",
    "rrc connection release":      "RELEASE",
    "rrc connection setup":        "RRC_SETUP",
    "authentication request":      "AUTH",
    "authentication reject":       "AUTH_REJECT",
    "authentication failure":      "AUTH_FAILURE",
    "auth reject":                 "AUTH_REJECT",
}


def _identity_is_imsi(ev: Dict, raw_msg: str) -> bool:
    """
    True only for an IMSI Identity Request. IMEISV/IMEI/GUTI requests are routine
    and must NOT be scored as identity harvest.
    """
    idt = str(ev.get("identity_type") or ev.get("id_type") or "").lower()
    if "imsi" in idt:
        return True
    if any(t in idt for t in ("imeisv", "imei", "guti", "tmsi")):
        return False
    # Fall back to raw text only if it explicitly says IMSI and not IMEISV.
    return ("imsi" in raw_msg) and ("imeisv" not in raw_msg)


class CipherNegotiationSequenceAnalyser(BaseDetector):

    name = "CipherNegotiationSequenceAnalyser"
    description = (
        "Cipher negotiation profiling — flags genuine null-cipher / "
        "pre-security IMSI exposure; treats encrypted completed attaches as healthy"
    )

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []

        norm_events = []
        for e in events:
            ts  = self._get_ts(e)
            msg = str(e.get("message_type") or e.get("msg_type") or "").lower()
            norm = None
            for pattern, norm_type in MSG_MAP.items():
                if pattern in msg:
                    norm = norm_type
                    break
            # EEA0 is only meaningful when *selected* in an SMC.
            eea0 = False
            if norm == "SMC":
                alg = str(e.get("cipher_alg") or e.get("cipher") or "").lower()
                eea0 = (alg == "eea0") or (e.get("encryption") == "none")
            if ts and norm:
                norm_events.append({
                    "ts": ts, "type": norm, "eea0": eea0,
                    "imsi": (norm == "IDENTITY" and _identity_is_imsi(e, msg)),
                    "raw": msg,
                })

        if not norm_events:
            return []
        norm_events.sort(key=lambda x: x["ts"])

        # Sessionise
        sessions = []
        current = [norm_events[0]]
        for ev in norm_events[1:]:
            if ev["ts"] - current[-1]["ts"] <= SESSION_GAP_S:
                current.append(ev)
            else:
                sessions.append(current); current = [ev]
        sessions.append(current)

        # ── Statistics ────────────────────────────────────────────────
        smc_events = [e for e in norm_events if e["type"] == "SMC"]
        eea0_smcs  = [e for e in smc_events if e["eea0"]]
        eea0_ratio = len(eea0_smcs) / len(smc_events) if smc_events else 0.0

        imsi_pre_security = 0   # IMSI identity request before any SMC in a session
        auth_reject_harvest = 0 # network AUTH_REJECT -> IDENTITY(IMSI)
        completed_encrypted = 0 # ATTACH..SMC..SMC_DONE..ATTACH_OK, no EEA0
        ue_caught_fake = 0      # AUTH_FAILURE present (UE rejected network)

        for s in sessions:
            seq  = [e["type"] for e in s]
            has_eea0 = any(e["eea0"] for e in s)
            # completed encrypted attach (healthy)
            if (("ATTACH" in seq or "RRC_SETUP" in seq)
                    and "SMC" in seq and "SMC_DONE" in seq
                    and not has_eea0):
                completed_encrypted += 1
            # IMSI before security
            if "SMC" in seq:
                idx_smc = seq.index("SMC")
            else:
                idx_smc = len(seq)
            for i, e in enumerate(s):
                if e["type"] == "IDENTITY" and e["imsi"] and i < idx_smc:
                    imsi_pre_security += 1
            # auth-reject harvest (network reject then IMSI identity)
            if "AUTH_REJECT" in seq:
                ar_idx = seq.index("AUTH_REJECT")
                if any(e["type"] == "IDENTITY" and e["imsi"] for e in s[ar_idx:]):
                    auth_reject_harvest += 1
            if "AUTH_FAILURE" in seq:
                ue_caught_fake += 1

        anomalies = len(eea0_smcs) + imsi_pre_security + auth_reject_harvest

        # ── Verdict ───────────────────────────────────────────────────
        if anomalies == 0:
            # Nothing hostile. Report the cipher posture honestly.
            if not smc_events:
                return []
            evidence = [
                f"Sessions reconstructed: {len(sessions)}",
                f"SecurityModeCommand events: {len(smc_events)}",
                f"EEA0 (null-cipher) selections: 0 (0%)",
                f"Completed ENCRYPTED attaches (healthy): {completed_encrypted}",
                f"IMSI Identity Requests before security: 0",
                f"Network Authentication-Reject harvests: 0",
                "",
                "ASSESSMENT: cipher negotiation is consistent with a legitimate,",
                "encrypted LTE network. A 0% EEA0 rate is the EXPECTED, healthy",
                "result and is exculpatory — it is not an attack signature.",
            ]
            if ue_caught_fake:
                evidence.append(
                    f"NOTE: {ue_caught_fake} Authentication Failure(s) present "
                    f"(UE->network). These are the UE rejecting the network and would "
                    f"INDICATE a fake base station if seen — none scored as attacks here."
                )
            findings.append(make_finding(
                detector=self.name,
                title=f"Cipher Negotiation — CLEAN (EEA0 0%, {completed_encrypted} encrypted attaches)",
                description=(
                    f"Across {len(sessions)} reconstructed sessions and "
                    f"{len(smc_events)} SecurityModeCommand events, EEA0 null-cipher "
                    f"was selected 0 times and no pre-security IMSI exposure or "
                    f"network authentication-reject harvest was observed. This cipher "
                    f"posture is consistent with a legitimate encrypted LTE network."
                ),
                severity="INFO",
                confidence="CONFIRMED",
                technique="Cipher negotiation posture assessment (exculpatory baseline)",
                evidence=evidence,
                hardware_hint="Consistent with legitimate carrier encryption (AES EEA2/EIA2).",
                action=(
                    "1. No cipher-based attack indicator. Do NOT cite as an attack.\n"
                    "2. Retain as the encrypted-baseline reference for this capture set."
                ),
                spec_ref="3GPP TS 33.401 §8.2",
            ))
            return findings

        # ── Genuine anomalies present ─────────────────────────────────
        evidence = [
            f"Sessions reconstructed: {len(sessions)}",
            f"SecurityModeCommand events: {len(smc_events)}",
            f"EEA0 (null-cipher) selections: {len(eea0_smcs)} ({eea0_ratio:.0%})",
            f"IMSI Identity Requests before security: {imsi_pre_security}",
            f"Network Authentication-Reject harvests: {auth_reject_harvest}",
            "",
        ]
        if eea0_smcs:
            evidence.append(f"EEA0 selected in {len(eea0_smcs)} SMC(s) — null encryption.")
        if imsi_pre_security:
            evidence.append(f"{imsi_pre_security} IMSI request(s) before security activation.")
        if auth_reject_harvest:
            evidence.append(f"{auth_reject_harvest} network Auth-Reject -> IMSI harvest sequence(s).")

        severity = "CRITICAL" if (eea0_smcs or imsi_pre_security) else "HIGH"
        confidence = "CONFIRMED" if anomalies >= 3 else "PROBABLE"

        findings.append(make_finding(
            detector=self.name,
            title=(
                f"Cipher/Identity Anomaly — EEA0 {eea0_ratio:.0%}, "
                f"{imsi_pre_security} pre-security IMSI, {auth_reject_harvest} reject-harvest"
            ),
            description=(
                f"{anomalies} genuine cipher/identity anomaly indicator(s) across "
                f"{len(sessions)} sessions: {len(eea0_smcs)} EEA0 SMC selection(s), "
                f"{imsi_pre_security} pre-security IMSI request(s), "
                f"{auth_reject_harvest} network auth-reject harvest sequence(s). "
                f"These are byte-level attack indicators, not inferred from completed "
                f"encrypted attaches."
            ),
            severity=severity,
            confidence=confidence,
            technique="Cipher/identity anomaly detection (EEA0 selection, pre-security IMSI, reject-harvest)",
            evidence=evidence,
            hardware_hint="Active rogue eNodeB capability indicated by null-cipher / pre-security identity exposure.",
            action=(
                "1. Decode each flagged SMC/Identity frame in tshark and attach as exhibit.\n"
                "2. EEA0 selection: confirm cipheringAlgorithm=eea0 in the SecurityModeCommand.\n"
                "3. Pre-security IMSI: confirm Identity Request type=IMSI before SMC.\n"
                "4. Correlate timestamps with serving-cell ECI/PCI/EARFCN."
            ),
            spec_ref="3GPP TS 33.401 §8.2; TS 24.301 §5.4.x",
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
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
        except (ValueError, OSError):
            return None
