# rayhunter-threat-analyzer — correctness patch set (June 2026)

Verified against the Jun 7-11 nine-file corpus by independent ASN.1 decode
(pycrate) of the raw QMDL DIAG B0C0 frames. ~11,400 events decoded; 97%
rrcConnectionReject.

## Modules
| File | Role |
|------|------|
| `cell_identity.py` | eNB-aware Novel-CID + CID-rotation detectors; per-PLMN baseline allowlist. |
| `reconcile.py`     | Post-detector pass: downgrades sector-rotation FPs, caps novel-CID, quarantines phantom handover/ProSe. |
| `corpus_guard.py`  | Report gate: provenance, falsifiability, phantom-message, **count-overflow (CASTNET)**, **geo-provenance**. |
| `MAIN_PY_WIRING.md`| Exact two-edit wiring for main.py + source-tagging plan. |

## Failure modes corrected
| # | v4.3 findings | Root cause | Fix |
|---|---|---|---|
| 1 | [14][15][16][17] | Sectors of one eNB read as rogue CID rotation. ECI=(eNB<<8)\|sector. | reconcile + cell_identity |
| 2 | [3][9] | Cited mobilityControlInfo/ProSe msgs that don't exist (0 reconfig decoded). | reconcile quarantine + guard phantom-msg |
| 3 | [4][10] | 97% rrcConnectionReject loop (unprovisioned SIM) scored as harvest loop. | (interpretive — see ground truth) |
| 4 | YAICD block | EEA0=0% AND "no 2G downgrade" counted as positive. Unfalsifiable. | guard falsifiability |
| 5 | [1][2][8][25] | CASTNET history + May data summed into per-capture totals (13,845 / 9,425). | guard count-overflow + source-tagging |
| 6 | [25][7] | Location claims with 0 TA samples / no in-capture measurement. | guard geo-provenance |

## GPS note
GPS is intentionally OFF in firmware (operator knows transmitter locations).
The guard does NOT treat missing GPS as a fault. Geo claims are policed by
measurement-or-source-tag instead: a finding needs an in-capture TA-sample/RSRP
reading OR an explicit `source="known_location"` tag to pass.

## Ground truth for THIS corpus
- 8,920 rrcConnectionReject (97%) — SIM-not-provisioned signature (Optus SIM in
  Vodafone unit + carrier-hop churn). Not a harvest loop.
- 0 rrcConnectionReconfiguration, 0 mobilityControlInfo, 0 ProSe IEs.
- LTE-only; no 2G/3G frames. NAS encrypted post-security.
- Cells = ordinary multi-sector macros, 3 carriers (Telstra 537942,
  Vodafone 32849/33853, Optus 85705).
- Verdict: CLEAN capture + successful new-carrier (Optus) SIM test.

## Rollout
1. Drop the 3 .py files in repo root (done).
2. Apply the 2 main.py edits (MAIN_PY_WIRING.md).
3. Run on Jun 7-11 set; watch reconcile + guard fire in console.
4. Build baseline from that clean set (build_baseline.py snippet in wiring doc).
5. Source-tag the 4 CASTNET detectors (paste base.py + one detector for exact lines).
