# Rayhunter Threat Analyzer — Integrity Correction Pass (v2.5)
**Date:** 12 Jun 2026
**Basis:** 11 QMDL captures decoded independently via SCAT → GSMTAP → tshark.
**Verifier:** `verify_fixes.py` (run it; it checks the bytes, not this document).

Every fix below corrects a detector that was reporting a *legitimate* behaviour
as an attack. None of them suppress real attack indicators — `verify_fixes.py`
fails loudly if a genuine EEA0 selection, redirect, or IMSI request ever appears.

---

## 1. `config.yaml` — the root cause (highest leverage)

**Bug:** `known_rogue_cids` was pre-loaded with the legitimate Telstra macro
sectors (137713155/165/175/195, 8409357/367/387/397, etc.). `main.py:855` feeds
this list straight into `ShannonImsParser(rogue_cids=...)`, which then "finds"
those CIDs in the bugreport — i.e. the list confirms itself. Circular.

**Fix:**
- `known_rogue_cids: []` — empty. A CID only earns a place by *byte-level attack
  behaviour* (redirect / EEA0 selected / IMSI-before-security / NAS reject), not
  by being on a list.
- Moved the old entries to `watchlist_cids` (INFO-only leads, history preserved).
- De-salted `known_rogue_earfcns`: 450/550/1275/1406/1550/3148/9410 are standard
  Telstra band EARFCNs and were guaranteeing false positives. Only 16384 retained,
  flagged PENDING verification.
- MNC kept at `001` (Telstra); added a pointer to find the MNC=03 mislabel (see §6).

**ACTION REQUIRED:** check `DEFAULT_ROGUE_CIDS` in `main.py` — if it also contains
these CIDs, empty it too, or the Shannon parser falls back to it when config is empty.

---

## 2. `cipher_negotiation_analyser.py` — produced false finding [5]

**Bug:** its `PATTERNS` table classified the *normal* LTE attach sequence
(`ATTACH → SMC → SMC_DONE → ATTACH_OK`) as "Harris Transparent Proxy", and treated
normal attach/release and IMEISV identity requests as IMSI harvest. Result:
"EEA0 Rate: 0% — 6 Attack Patterns" on a capture where every SMC used AES. A 0%
EEA0 rate is **exculpatory**.

**Fix:**
- A completed *encrypted* attach is now reported as a HEALTHY baseline (INFO).
- Only genuine anomalies flag: EEA0 actually selected, IMSI (not IMEISV) request
  before security, or network Auth-Reject → IMSI harvest.
- Split `Authentication Reject` (network→UE, can be hostile) from
  `Authentication Failure` (UE→network — the UE *catching* a fake BTS; never
  scored as the network attacking).
- IMEISV identity requests no longer count as harvest.

---

## 3. `cid_rotation.py` — produced false findings [24]/[25]

**Bug:** flagged numerically-adjacent CIDs as "synthetic rotation". But
`ECI = eNB_ID × 256 + sector`, so a real macro's sectors are adjacent **by design**.
137713155/165/175/195 = eNB 537942, sectors 3/13/23/43 — one macro. `main.py`
already had to RECONCILE this away after the fact.

**Fix:**
- Compute `eNB_ID = cid // 256` for every CID in a cluster.
- All-same-eNB → "Multi-sector macro (NOT rotation)", INFO, explicitly excluded.
- Only multi-eNB clusters survive, and even then only as an INFO-level *lead*
  requiring behavioural corroboration.

---

## 4. `handover_inject.py` — produced false finding [3]

**Bug:** treated the absence of a `MeasurementReport` before a handover as
CONFIRMED CRITICAL injection. But MeasurementReport is an **uplink** message;
DL-biased captures often don't log it, so its absence proves nothing.
(The file already had a good payload guard — that part was kept.)

**Fix:**
- If the whole capture has **zero** MeasurementReports → UL channel not captured →
  INFO ("cannot assess"), never CRITICAL.
- A missing-measurement handover only reaches CRITICAL if independently
  corroborated by an EEA0 selection or a redirect in the same capture; otherwise
  caps at MEDIUM/SUSPECTED.
- ProSe finding downgraded to SUSPECTED unless the `reportProximityConfig-r9` IE
  is actually decoded (not just a parser flag).
- Fixed `_fmt` T304 display bug (`{t304}00ms` → `{t304}ms`).

---

## 5. `cipher_downgrade.py` — NO CHANGE NEEDED

Already correctly fixed at v2.1 (only fires on genuine EEA0). It stayed silent on
these captures because there is no null cipher. Leave it as-is.

---

## 6. The `MNC=03 (Vodafone AU)` label (finding [20]) — NOT in the uploaded files

The cell-summary / SIB1-PLMN decoder that prints this was not among the uploaded
files, so it's not patched here. **Diagnosis:** every captured cell's SIB1 PLMN
decodes to MCC 505 / MNC **01 = Telstra** (confirmed in both the bugreport and the
QMDL). The `MNC=03` is either a PLMN-digit mis-decode or a TAC→carrier guess table
(TAC 30336 is a Telstra TAC here — TAC numbers are not carrier IDs).

Find it:
```
grep -rniE "vodafone|mnc.?=.?3|carrier_name|plmn_name|30336" .
```
The MNC must be read from the SIB1 `plmn-Identity` MCC/MNC digits, never inferred
from TAC. Querying OpenCelliD with `mnc=003` for these cells returns "not found"
for real Telstra cells — manufacturing false "unregistered/rogue" results.

---

## How to apply

1. Back up `C:\RH\rayhunter-threat-analyzer` first.
2. Drop the four corrected files into place (same paths as the originals).
3. Replace `config.yaml`. Empty `DEFAULT_ROGUE_CIDS` in `main.py` if present (§1).
4. Fix the MNC decoder (§6).
5. Run: `python verify_fixes.py --pcap-dir <your pcaps>`  → expect **RESULT: CLEAN**.
6. Re-run `main.py` on the June files. The CRITICAL banner should collapse; the
   genuine MEASURED tier should remain and read clean.

## Note on intent
These fix **detector correctness**, not the verdict. If a corrected detector still
fires on something real, it fires — `verify_fixes.py` is the guard that proves the
captures are clean rather than that the detectors were silenced. The goal is output
that survives an adversarial read by AFP's own analyst.
