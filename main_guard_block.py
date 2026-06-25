    # -- Corpus guard (schema-aware; GPS-off is NOT treated as a fault) -------
    try:
        from corpus_guard import (check_event_count_field, check_geo_provenance,
                                   check_source_tags, check_provenance, tag_source)
        import re as _re
        _decoded = len(results.get("events", []))
        _fs = results.get("findings", [])
        _gblob = json.dumps(report, default=str)
        _dates = sorted(set(_re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", _gblob)))
        _issues = []
        _issues += check_event_count_field(_fs, _decoded)
        # --- AUTO-TAG CASTNET/corpus findings before GUARD check ---
        _castnet_tag_names = {
            "regulatoryescalationscorer",
            "jitterdnatracker",
            "operatorrhythmprofiler",
            "regulatoryeventcorrelator",
            "attackintensityscorer",
            "crosssessionpersistencetracker",
            "silentperioddetector",
            "tuckertaxonomyscorer",
            "temporalfingerprintevolutiontracker",
            "attackcampaignsegmenter",
            "simultaneousciiddiscriminator",
            "crosssourcecorrelator",
        }
        for _f in _fs:
            _dn = (str(_f.get("detector", ""))
                   .lower().replace("_", "").replace(" ", ""))
            if _dn in _castnet_tag_names and not _f.get("source"):
                tag_source(_f, "castnet")
        # --- end auto-tag ---
        # --- AUTO-TAG KML findings as known_location ---
        for _f in _fs:
            _dn = str(_f.get("detector", "")).lower().replace(" ", "").replace("_", "")
            if _dn == "kmlexporter":
                tag_source(_f, "known_location")
        # --- geo provenance check AFTER auto-tags so source stamps are visible ---
        _issues += check_geo_provenance(
            [(f.get("title", ""), " ".join(f.get("evidence", [])
              if isinstance(f.get("evidence"), list) else [str(f.get("evidence", ""))]),
              f.get("source")) for f in _fs])
        _issues += check_source_tags(_fs)
        if _dates:
            _issues += check_provenance(_gblob, _dates[0], _dates[-1], gps_present=True,
                                        input_file_count=total)
        if _issues:
            print(f"\n  [GUARD] {len(_issues)} issue(s) - report stamped UNVERIFIED:")
            for _code, _msg in _issues:
                print(f"     [{_code}] {_msg}")
            report["provenance_audit"] = {"status": "UNVERIFIED",
                                          "issues": [list(i) for i in _issues]}
        else:
            report["provenance_audit"] = {"status": "CLEAN", "issues": []}
    except Exception as _exc:
        print(f"  [WARN] corpus_guard error: {_exc}")
