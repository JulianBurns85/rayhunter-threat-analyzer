# main.py wiring — exact edits

Two inserts. Nothing is deleted; existing detectors keep running and are
audited afterward. Both edits are in the `main()` function.

## EDIT 1 — reconciliation pass (after run_analysis, before reporting)

Find this block (~line 753-763):

```python
    start   = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    print()
    print("-" * 64)
    print("PHASE 2 -- REPORTING")
    print("-" * 64)

    reporter = ThreatReporter(cfg)
    report   = reporter.build_report(results, elapsed)
```

Insert the reconciliation between `elapsed = ...` and the `print()`:

```python
    start   = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    # -- Reconciliation pass (eNB-aware correction of CID/handover/ProSe) -----
    from reconcile import reconcile_findings
    results["findings"], _recon_log = reconcile_findings(
        results.get("findings", []),
        results.get("events", []),
        baseline_path=cfg.get("intelligence", {}).get(
            "cell_baseline", "intelligence/db/cell_baseline.json"),
    )
    for _line in _recon_log:
        print(_line)

    print()
    print("-" * 64)
    print("PHASE 2 -- REPORTING")
    print("-" * 64)

    reporter = ThreatReporter(cfg)
    report   = reporter.build_report(results, elapsed)
```

## EDIT 2 — guard gate (just before the JSON is written, ~line 908)

Find:

```python
        json_out = json.dumps(report, indent=2, default=str)
```

Insert immediately ABOVE it:

```python
    # -- Corpus guard: provenance / count-overflow / geo-provenance audit -----
    # NOTE: does NOT use GPS-presence (GPS is intentionally off in firmware).
    try:
        from corpus_guard import (check_provenance, check_event_count_overflow,
                                   check_geo_provenance, check_falsifiability)
        import re as _re
        _decoded = len(results.get("events", []))      # Phase-1 decoded total
        _blob = json.dumps(report, default=str)
        _dates = sorted(set(_re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", _blob)))

        # findings as (title, evidence) pairs, shape-tolerant
        def _pair(f):
            g = (lambda k: (f.get(k) if isinstance(f, dict) else getattr(f, k, "")))
            title = str(g("title") or g("label") or g("name") or "")
            ev = " ".join(str(g(k) or "") for k in
                          ("evidence", "details", "description", "summary"))
            src = g("source") or g("source_tag")
            return title, ev, src
        _fs = [_pair(f) for f in results.get("findings", [])]

        _issues = []
        _issues += check_event_count_overflow([(t, e) for t, e, _ in _fs], _decoded)
        _issues += check_geo_provenance(_fs)
        if _dates:
            _issues += check_provenance(_blob, _dates[0], _dates[-1],
                                        gps_present=True)  # neutralise GPS branch
        if _issues:
            print(f"\n  [GUARD] {len(_issues)} issue(s) — report stamped UNVERIFIED:")
            for _code, _msg in _issues:
                print(f"     [{_code}] {_msg}")
            report["provenance_audit"] = {"status": "UNVERIFIED",
                                          "issues": [list(i) for i in _issues]}
        else:
            report["provenance_audit"] = {"status": "CLEAN", "issues": []}
    except Exception as _exc:
        print(f"  [WARN] corpus_guard error: {_exc}")

        json_out = json.dumps(report, indent=2, default=str)
```

The count-overflow check uses `len(results["events"])` — the same decoded total
Phase 1 prints as "Total events". Any finding citing more events than that
(e.g. CASTNET's 9,425 / 13,845 summed in) gets flagged. Passing
`gps_present=True` deliberately disables the old GPS heuristic, since you run
GPS off on purpose; geo claims are now policed by `check_geo_provenance`
(needs an in-capture TA-sample/RSRP measurement OR a `source` tag) instead.

## Source-tagging (the real root fix for CASTNET bleed-through)

The guard catches overflow at the boundary, but the clean fix is upstream: the
CASTNET-fed detectors (`CrossCarrierTimerCorrelator`, `RegulatoryEscalationScorer`,
`AttackIntensityScorer`, `RegulatoryEventCorrelator`) should stamp every finding
they emit with `source="castnet"`, and any location finding derived from your
known transmitter positions with `source="known_location"`. Two benefits:

  1. The geo check passes those findings cleanly (they're honestly sourced).
  2. The report can render "observed in THIS capture" separately from
     "corroborated against CASTNET history" — which is what a reviewer needs.

Minimal change in each of those detectors: wherever they build a finding dict/
object, add `finding["source"] = "castnet"`. If they share a base `Finding`
class (base.py), add a `source: str = "capture"` field there and override it in
the four CASTNET detectors. Paste base.py + one CASTNET detector and I'll give
exact lines.

## config.yaml — optional, makes the baseline path explicit

Under the `intelligence:` section add:

```yaml
intelligence:
  cell_baseline: intelligence/db/cell_baseline.json
```

## Build the baseline (one-time, from KNOWN-CLEAN captures only)

```python
# build_baseline.py — run once over verified-clean dirs
from cell_identity import BaselineStore
import json, glob, re

bs = BaselineStore(path="intelligence/db/cell_baseline.json")
for nd in glob.glob(r"C:\RH\CLEAN_CAPTURES\**\*.ndjson", recursive=True):
    for line in open(nd, encoding="utf-8"):
        m = re.search(r"CID:\s*(\d+),\s*TAC:\s*(\d+),\s*PLMN:\s*([\d-]+)", line)
        if m:
            cid, tac, plmn = int(m.group(1)), m.group(2), m.group(3)
            bs.observe(plmn, tac, cid)
bs.save()
print("baseline written:", sum(len(cb.seen_cids)
      for t in bs.data.values() for cb in t.values()), "CIDs")
```

Run it on the Jun 7-11 set first (verified clean) to seed Telstra eNB 537942,
Vodafone 32849/33853, Optus 85705. After that, novel-CID alarms only fire for
genuinely unseen towers.
