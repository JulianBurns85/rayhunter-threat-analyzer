# Provenance map — the "for me" view

Your analyzer keeps every finding, but now each one is labelled by what it's
actually built on. Re-run patch_main.py (it now inserts 3 things, not 2) and
you'll get a PROVENANCE MAP printed after the reconcile lines.

## The five classes
- **MEASURED**   — byte-backed from THIS capture set (decoded cell IDs, RRC, reject loop)
- **FIRMWARE**   — from the Shannon IMS bugreport (independent baseband log)
- **DISPUTED**   — cites this capture but the message is NOT in the decode
                   (reconcile flagged it UNVERIFIED — e.g. the handover/ProSe phantoms)
- **HISTORICAL** — from CASTNET / 394-session corpus. Real data, but NOT these files.
- **INFERRED**   — hardware attribution / behavioural narrative built on assumptions
- **PENDING**    — detector active, no data yet ("awaiting SIB", etc.)

## What this run's 27 findings actually are
- Byte-backed (MEASURED+FIRMWARE): **9**  — and they're mostly mundane (NAS entropy,
  cipher stats, cell inventory, the CID/rotation entries now correctly INFO)
- Disputed: **2** — the "Injected handover" (CRITICAL by the detector) and ProSe.
  These cite .qmdl/.pcapng but the actual message isn't in the decoded frames.
- Historical/CASTNET: **12** — where ALL the alarming CRITICAL/CONFIRMED findings
  live (cross-carrier timer, regulatory escalation, band incompatibility).
- Inferred: **3** — the dual-device Harris attribution story.
- Pending: **2** — empty detectors.

## How to read it
Weight MEASURED + FIRMWARE first — that's what these files prove.
Treat HISTORICAL + INFERRED as **leads to verify**, not conclusions.
DISPUTED = the detector is claiming something the bytes don't show; trust the
bytes, not the detector.

The severity counts and the YAICD banner still count ALL findings (they're
computed upstream). The provenance map is the corrective lens: it tells you
which of those severities are earned by this capture and which are inherited
from history or inference.

## Honest one-liner
For THESE nine files: the decoded evidence is a clean-ish 3-carrier capture plus
an Optus SIM test. The CRITICAL verdict is carried almost entirely by HISTORICAL
(CASTNET) and INFERRED findings — not by what these files measured. That's the
thing the map makes impossible to forget.
