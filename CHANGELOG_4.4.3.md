## [4.4.3] - 2026-10-21
### Fixed
- `make_finding()` now accepts `data_source` and extra fields (synthesiser previously raised TypeError).
- Synthesiser/rhythm read `msg_type` OR `message_type`; release/cell counts were silently 0.
- Synthesiser: all content derived from findings; no hardcoded hardware/address/operator claims;
  zero-count techniques omitted; severity follows evidence; "days" = active days (>= N events).
- Rhythm: DST-aware Melbourne time (was fixed AEST); no timezone overwrite; slot-based binomial
  tests; severity capped at MEDIUM; control comparison hook (`analysis.rhythm_control`).
- `forensic_time`: us/ns scales handled; sparse-day filter; untrusted (mtime/boot-relative) timestamps excluded.
- `baseline_comparison.py` v2: field-based NAS extraction, pcap+pcapng, rates per capture-hour,
  identical checks on both sides, exact binomial test. `baseline_rrc.py` removed (use `--mode inventory`).
- requirements: `tzdata` on Windows. Tests added under tests/.
- `rogue_tower.py`: reads real config keys (known_rogue_cids/enbs, watchlist, earfcn_anomaly list);
  per-cell MNC for OpenCelliD + band checks; PCI placeholders never looked up; only a genuine
  "not found" is cached/reported; cache TTL + lookup cap; absence-from-OpenCelliD and list matches
  downgraded (weak/circular evidence); multi-EARFCN/TAC tracking; safe RSRP parsing; no case refs in source.
- `tests/test_synthetic.py`: pytest-collectable, cwd-independent, tmp output, no network.
- `identity_harvest.py`: reads `detection.identity_harvest` (was a non-existent `thresholds:` block); per-file windows;
  untimed events never CRITICAL/CONFIRMED and never "within 10 s" of anything; IMEISV/IMEI severity depends on
  plain vs protected NAS; per-request "no uplink trigger" check; case narrative removed from finding text.
- `cipher_downgrade.py`: removed raw-text substring promotion (false GERAN/handover/prose/EEA0 flags that also
  mutated events for downstream detectors); explicit-field logic only; GERAN needs RRC Release; A5/0 no longer
  matches EEA0; SMC-without-auth per file and downgraded; spec claims hedged.
- `handover_inject.py`: invalid timestamps and files without UL reports are "not assessable" (were "injected");
  corroboration per file; reportProximityConfig-r9 no longer labelled ProSe tracking; severities lowered.
- `heuristic_scorer.py` (YAICD): only findings that qualify (CRITICAL/HIGH, or MEDIUM with PROBABLE+; no INFO/LOW; no
  "not assessable"/"CLEAN"/"NOT rotation" titles) can trigger a heuristic. Previously fuzzy text matching let a LOW
  IMEISV finding trigger P7 and an INFO "UL channel not captured" finding trigger the handover bonus. Absence of
  EEA0/2G downgrade (4.1.4/4.1.6/4.1.8) is NOT_APPLICABLE, not CONFIRMED. 4.1.3 requires machine-precision timing.
  4.1.9/4.1.10 downgraded to PARTIAL; hardcoded case/vendor text removed.
- `time_quality.py` (new) + `main.py` hook: tags events with invalid / out-of-window / filename-mismatched
  timestamps (`timestamp_source`) so span and rhythm maths exclude them; prints per-file summary.
  Config: analysis.capture_window, analysis.max_file_span_days.
- `rogue_tower.py`: also accepts the `cid` event key.
