#!/usr/bin/env python3
"""
RF Signature Library Lookup
============================
Loads the Australian RF Signature Library YAML and provides lookup functions
to classify detected cells as AUTHORISED, WATCHLIST, ROGUE, or UNKNOWN.

Purpose: Reduce false positives by whitelisting known legitimate operators
         and protecting authorised law enforcement operations from
         misidentification as rogue infrastructure.

Integration: Called from main.py before flagging any cell as rogue.
             If a cell returns AUTHORISED, suppress the rogue alert.
             If WATCHLIST, log but reduce severity.
             If ROGUE, confirm and escalate.
             If UNKNOWN, flag for manual review.

Author: Julian Burns — Cranbourne East VIC 2026
"""

import yaml
import os
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Library path resolution ────────────────────────────────────────────────────
# Looks for the YAML in the intelligence/ subdirectory relative to this file
_THIS_DIR = Path(__file__).parent
_DEFAULT_LIBRARY_PATH = _THIS_DIR / "intelligence" / "au_rf_signature_library.yaml"


class RFSignatureLibrary:
    """
    Loads and queries the Australian RF Signature Library.

    Usage:
        lib = RFSignatureLibrary()
        result = lib.lookup_cell(mcc="505", mnc="01", ci=137713155, tac=12385)
        print(result["verdict"])  # ROGUE / AUTHORISED / WATCHLIST / UNKNOWN
    """

    def __init__(self, library_path: Optional[str] = None):
        self.library_path = Path(library_path) if library_path else _DEFAULT_LIBRARY_PATH
        self._library = None
        self._rogue_cids: set = set()
        self._authorised_carriers: list = []
        self._loaded = False
        self._load()

    def _load(self):
        """Load and parse the YAML signature library."""
        if not self.library_path.exists():
            logger.warning(
                f"[RFSigLib] Library not found at {self.library_path} — "
                f"all cells will return UNKNOWN. "
                f"Place au_rf_signature_library.yaml in intelligence/ directory."
            )
            return

        try:
            with open(self.library_path, "r", encoding="utf-8") as f:
                self._library = yaml.safe_load(f)

            # Build fast lookup sets from rogue signatures
            for sig in self._library.get("rogue_signatures", []):
                for tac_group in sig.get("known_cids", {}).values():
                    for entry in tac_group:
                        self._rogue_cids.add(int(entry["ci"]))

            # Build carrier lookup list
            self._authorised_carriers = self._library.get("cellular_lte_signatures", [])

            self._loaded = True
            logger.info(
                f"[RFSigLib] Loaded — "
                f"{len(self._rogue_cids)} known rogue CIDs, "
                f"{len(self._authorised_carriers)} authorised carrier profiles"
            )

        except Exception as e:
            logger.error(f"[RFSigLib] Failed to load library: {e}")

    def lookup_cell(
        self,
        mcc: Optional[str] = None,
        mnc: Optional[str] = None,
        ci: Optional[int] = None,
        tac: Optional[int] = None,
        earfcn: Optional[int] = None,
    ) -> dict:
        """
        Look up a detected cell against the signature library.

        Returns:
            dict with keys:
                verdict     : AUTHORISED | WATCHLIST | ROGUE | UNKNOWN
                reason      : human-readable explanation
                operator    : matched operator name (if known)
                signature_id: matched signature ID (if applicable)
                confidence  : HIGH | MEDIUM | LOW
        """
        if not self._loaded:
            return self._result("UNKNOWN", "Signature library not loaded", confidence="LOW")

        ci_int = int(ci) if ci is not None else None

        # ── Step 1: Check known rogue CIDs first ──────────────────────────────
        if ci_int is not None and ci_int in self._rogue_cids:
            return self._result(
                verdict="ROGUE",
                reason=f"CID {ci_int} is in confirmed rogue database (zero OpenCelliD hits, "
                       f"active IMSI catcher investigation Cranbourne East 2026)",
                operator="UNKNOWN — rogue platform",
                signature_id="HARRIS_HAILSTORM_VIC_001",
                confidence="HIGH",
            )

        # ── Step 2: Check against authorised carrier profiles ─────────────────
        if mcc and mnc:
            carrier_match = self._match_carrier(mcc, mnc, earfcn)
            if carrier_match:
                # Carrier MCC/MNC matches — but is the CID in OpenCelliD?
                # If we have no CID info, assume authorised
                if ci_int is None:
                    return self._result(
                        verdict="AUTHORISED",
                        reason=f"MCC={mcc} MNC={mnc} matches {carrier_match['name']}",
                        operator=carrier_match.get("operator", "Unknown carrier"),
                        signature_id=carrier_match.get("id"),
                        confidence="MEDIUM",
                    )

                # CID provided but NOT in rogue list — likely legitimate
                # Mark as AUTHORISED with note to cross-reference OpenCelliD
                return self._result(
                    verdict="AUTHORISED",
                    reason=(
                        f"MCC={mcc} MNC={mnc} matches {carrier_match['name']}. "
                        f"CID={ci_int} not in rogue database. "
                        f"Recommend OpenCelliD cross-reference to confirm."
                    ),
                    operator=carrier_match.get("operator", "Unknown carrier"),
                    signature_id=carrier_match.get("id"),
                    confidence="MEDIUM",
                )

        # ── Step 3: MCC/MNC matches known carrier but CID not in rogue list ───
        # Could be a new legitimate tower or an undocumented rogue
        if mcc == "505":
            return self._result(
                verdict="WATCHLIST",
                reason=(
                    f"MCC=505 (Australian carrier) but MNC={mnc} not matched or "
                    f"CID={ci_int} not in rogue database. "
                    f"Recommend OpenCelliD cross-reference."
                ),
                operator="Australian carrier — unverified",
                confidence="LOW",
            )

        # ── Step 4: Unknown — not in any database ─────────────────────────────
        return self._result(
            verdict="UNKNOWN",
            reason=f"Cell not found in RF signature library. MCC={mcc} MNC={mnc} CID={ci_int}",
            confidence="LOW",
        )

    def _match_carrier(self, mcc: str, mnc: str, earfcn: Optional[int] = None) -> Optional[dict]:
        """Match MCC/MNC against known authorised carrier profiles."""
        mnc_str = str(mnc).zfill(2)
        for carrier in self._authorised_carriers:
            if (
                str(carrier.get("mcc", "")) == str(mcc)
                and str(carrier.get("mnc", "")).zfill(2) == mnc_str
            ):
                return carrier
        return None

    def is_rogue_cid(self, ci: int) -> bool:
        """Quick boolean check — is this CID in the confirmed rogue database?"""
        return int(ci) in self._rogue_cids

    def is_authorised_carrier(self, mcc: str, mnc: str) -> bool:
        """Quick boolean check — is this MCC/MNC a known legitimate carrier?"""
        return self._match_carrier(mcc, mnc) is not None

    def get_rogue_cids(self) -> set:
        """Return the full set of known rogue CIDs."""
        return self._rogue_cids.copy()

    def summary(self) -> str:
        """Return a one-line summary of library status."""
        if not self._loaded:
            return "RF Signature Library: NOT LOADED"
        return (
            f"RF Signature Library v{self._library.get('metadata', {}).get('version', '?')} — "
            f"{len(self._rogue_cids)} rogue CIDs — "
            f"{len(self._authorised_carriers)} carrier profiles — "
            f"Region: {self._library.get('metadata', {}).get('region', 'Unknown')}"
        )

    @staticmethod
    def _result(
        verdict: str,
        reason: str,
        operator: str = "",
        signature_id: str = "",
        confidence: str = "MEDIUM",
    ) -> dict:
        return {
            "verdict": verdict,
            "reason": reason,
            "operator": operator,
            "signature_id": signature_id,
            "confidence": confidence,
        }


# ── Singleton instance ─────────────────────────────────────────────────────────
# Import this in main.py: from rf_signature_lookup import rf_lib
# Then call: result = rf_lib.lookup_cell(mcc=..., mnc=..., ci=..., tac=...)
rf_lib = RFSignatureLibrary()


# ── CLI test ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(rf_lib.summary())
    print()

    test_cases = [
        # Known rogue CIDs
        {"mcc": "505", "mnc": "01", "ci": 137713155, "tac": 12385, "label": "Known rogue Telstra CID"},
        {"mcc": "505", "mnc": "03", "ci": 8409357,   "tac": 30336, "label": "Known rogue Vodafone CID"},
        {"mcc": "505", "mnc": "01", "ci": 8666381,   "tac": 30336, "label": "Post-ACMA rogue CID"},
        # Legitimate carriers
        {"mcc": "505", "mnc": "01", "ci": 999999999,  "tac": 1234,  "label": "Legitimate Telstra cell (hypothetical)"},
        {"mcc": "505", "mnc": "02", "ci": 888888888,  "tac": 5678,  "label": "Legitimate Optus cell (hypothetical)"},
        {"mcc": "505", "mnc": "03", "ci": 777777777,  "tac": 9012,  "label": "Legitimate Vodafone cell (hypothetical)"},
        # Unknown
        {"mcc": "001", "mnc": "01", "ci": 123456,     "tac": 1111,  "label": "Unknown MCC/MNC"},
    ]

    for tc in test_cases:
        result = rf_lib.lookup_cell(
            mcc=tc["mcc"], mnc=tc["mnc"], ci=tc["ci"], tac=tc["tac"]
        )
        verdict = result["verdict"]
        icon = {"ROGUE": "🚨", "AUTHORISED": "✅", "WATCHLIST": "⚠️", "UNKNOWN": "❓"}.get(verdict, "?")
        print(f"{icon} [{verdict}] {tc['label']}")
        print(f"   {result['reason']}")
        print()
