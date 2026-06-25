# main.py wiring — FINAL (matches base.py make_finding schema)

Findings are plain dicts from make_finding(): keys detector, title,
description, severity, severity_score, confidence, confidence_score, technique,
evidence (LIST[str]), event_count, recommended_action, spec_reference.

Two inserts in main(), nothing deleted.

## EDIT 1 — reconciliation (after `elapsed = time.time() - start`, ~line 755)

```python
    start   = time.time()
    results = run_analysis(files, cfg, args.verbose)
    elapsed = time.time() - start

    # -- Reconciliation: eNB-aware CID correction + phantom-msg quarantine ----
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
```

## EDIT 2 — guard gate (immediately ABOVE `json_out = json.dumps(...)`, ~line 908)

```python
    # -- Corpus guard (schema-aware; GPS-off is NOT treated as a fault) -------
    try:
        from corpus_guard import (check_event_count_field, check_geo_provenance,
                                   check_source_tags, check_provenance)
        import re as _re
        _decoded = len(results.get("events", []))
        _fs = results.get("findings", [])
        _blob = json.dumps(report, default=str)
        _dates = sorted(set(_re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", _blob)))

        _issues = []
        _issues += check_event_count_field(_fs, _decoded)
        _issues += check_geo_provenance(
            [(f.get("title",""), " ".join(f.get("evidence",[])
              if isinstance(f.get("evidence"), list) else [str(f.get("evidence",""))]),
              f.get("source")) for f in _fs])
        _issues += check_source_tags(_fs)
        if _dates:
            _issues += check_provenance(_blob, _dates[0], _dates[-1], gps_present=True)

        if _issues:
            print(f"\n  [GUARD] {len(_issues)} issue(s) — report stamped UNVERIFIED:")
            for _code, _msg in _issues:
                print(f"     [{_code}] {_msg}")
            report["provenance_audit"] = {"status":"UNVERIFIED",
                                          "issues":[list(i) for i in _issues]}
        else:
            report["provenance_audit"] = {"status":"CLEAN","issues":[]}
    except Exception as _exc:
        print(f"  [WARN] corpus_guard error: {_exc}")

        json_out = json.dumps(report, indent=2, default=str)
```

(Original `json_out = ...` stays at its indent; the snippet ends with it for paste convenience.)

## Then (separate step): source-tag the 4 CASTNET detectors — see SOURCE_TAGGING.md
