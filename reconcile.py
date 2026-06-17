"""
reconcile.py — post-detector reconciliation for rayhunter-threat-analyzer.

Operates on the make_finding() dict schema from base.py:
  detector, title, description, severity, severity_score, confidence,
  confidence_score, technique, evidence (LIST[str]), event_count,
  hardware_hint, recommended_action, spec_reference, found_at.

Runs AFTER the detector loop, BEFORE report build. Corrects three verified
false-positive classes and keeps severity_score / confidence_score coherent.
Shape-tolerant and never raises into the pipeline.

Wire-in (main.py, after run_analysis):
    from reconcile import reconcile_findings
    results["findings"], _log = reconcile_findings(
        results["findings"], results["events"],
        baseline_path=cfg.get("intelligence", {}).get(
            "cell_baseline", "intelligence/db/cell_baseline.json"))
    for _l in _log: print(_l)
"""

import re
from cell_identity import decompose_eci, BaselineStore

SEVERITY_SCORE = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
CONFIDENCE_SCORE = {"CONFIRMED": 3, "PROBABLE": 2, "SUSPECTED": 1}


def _extract_cids(blob):
    """Catch 'CID=NNN' and 'Rotating CIDs: N, N, N' list forms. CID context only."""
    cids = set()
    for m in re.finditer(r"CID[s]?[=:\s]*([\d,\s]+)", blob, re.I):
        for tok in re.findall(r"\d{4,}", m.group(1)):
            cids.add(int(tok))
    for m in re.finditer(r"\bCID[=:\s]*(\d{4,})", blob, re.I):
        cids.add(int(m.group(1)))
    return sorted(cids)


def _blob(f):
    """Flatten the human-readable fields of a make_finding() dict to one string."""
    parts = []
    for k in ("title", "description", "technique", "recommended_action"):
        v = f.get(k)
        if v:
            parts.append(str(v))
    ev = f.get("evidence")
    if isinstance(ev, list):
        parts.extend(str(x) for x in ev)
    elif ev:
        parts.append(str(ev))
    return "\n".join(parts)


def _downgrade(f, severity=None, confidence=None, note=None, source=None):
    """Apply a downgrade while keeping the *_score fields coherent."""
    if severity:
        f["severity"] = severity
        f["severity_score"] = SEVERITY_SCORE.get(severity, 0)
    if confidence:
        f["confidence"] = confidence
        f["confidence_score"] = CONFIDENCE_SCORE.get(confidence, 0)
    if source:
        f["source"] = source
    if note:
        f["reconciliation"] = note


def reconcile_findings(findings, events, baseline_path):
    """Returns (findings, log_lines)."""
    log = []
    baseline = BaselineStore(path=baseline_path)

    # Independent ground truth: do parsed events contain reconfig / MCI / ProSe?
    ev_blob = "".join(str(e) for e in events[:200000]).lower()
    has_reconfig = ("reconfigur" in ev_blob) or ("mobilitycontrolinfo" in ev_blob)
    has_prose = ("proximit" in ev_blob) or ("reportproximityconfig" in ev_blob)

    # known eNB-IDs per (plmn,tac) from baseline, for novel-CID sector check
    known_enbs = {}
    for plmn, tacs in baseline.data.items():
        for tac, cb in tacs.items():
            s = known_enbs.setdefault((str(plmn), str(tac)), set())
            for cid in cb.seen_cids:
                s.add(decompose_eci(int(cid))[0])

    # Load known rogue eNBs from config.yaml ? bypass sector-consistency downgrade
    try:
        import yaml as _yaml, pathlib as _pl
        _cfg_raw = _yaml.safe_load(_pl.Path("config.yaml").read_text(encoding="utf-8"))
        _known_rogue_enbs = set(
            int(e) for e in
            _cfg_raw.get("detection", {}).get("rogue_tower", {}).get("known_rogue_enbs", [])
        )
    except Exception:
        _known_rogue_enbs = set()

    for f in findings:
        name = str(f.get("detector", "")).lower()
        blob = _blob(f)
        low = blob.lower()
        cids = _extract_cids(blob)
        plmn_m = re.search(r"\b(505-0\d)", blob)
        plmn = plmn_m.group(1) if plmn_m else None
        tac_m = re.search(r"TAC[=:\s]*(\d+)", blob, re.I)
        tac = tac_m.group(1) if tac_m else None

        # --- 1: CID 'rotation' that is really sectors of one eNB --------------
        if ("rotation" in name or "rotation" in low) and len(cids) >= 2:
            enbs = {decompose_eci(c)[0] for c in cids}
            if len(enbs) == 1:
                enb = next(iter(enbs))
                if enb in _known_rogue_enbs:
                    log.append(f"  [RECONCILE] CID-rotation BYPASS: eNB {enb} on known_rogue_enbs -- suppressed.")
                    continue
                sectors = sorted({decompose_eci(c)[1] for c in cids})
                _downgrade(f, severity="INFO", confidence="SUSPECTED",
                    note=(f"DOWNGRADED: all CIDs share eNB-ID {enb} "
                          f"(sectors {sectors}). Single multi-sector macro cell, "
                          f"not identifier rotation."))
                log.append(f"  [RECONCILE] CID-rotation downgraded: one eNB "
                           f"({enb}), sectors {sectors} — normal macro.")

        # --- 2: novel CID = new sector of a known tower, or cap novelty -------
        if "novel" in name or "novel cell" in low:
            for c in cids:
                enb = decompose_eci(c)[0]
                if plmn and tac and enb in known_enbs.get((plmn, tac), set()):
                    _downgrade(f, severity="INFO", confidence="SUSPECTED",
                        note=f"DOWNGRADED: CID {c} is a new sector of known eNB {enb}.")
                    log.append(f"  [RECONCILE] Novel-CID {c} downgraded: "
                               f"known eNB {enb}, new sector.")
                elif f.get("severity") in ("CRITICAL", "HIGH"):
                    _downgrade(f, severity="INFO", confidence="SUSPECTED",
                        note=("CAPPED at INFO: novel CID needs OpenCelliD/ACMA "
                              "register check before rogue classification. "
                              "New-carrier first contact is the common benign cause."))
                    log.append(f"  [RECONCILE] Novel-CID {c} capped to INFO "
                               f"(verify against register).")

        # --- 3: phantom handover / ProSe -------------------------------------
        is_handover = "handover" in name or "mobilitycontrolinfo" in low
        is_prose = "prose" in name or "proximit" in low
        if is_handover and not has_reconfig:
            _downgrade(f, confidence="SUSPECTED",
                note=("QUARANTINED: no rrcConnectionReconfiguration / "
                      "mobilityControlInfo in decoded events. ASN.1-verify before use."))
            f["verification_status"] = "UNVERIFIED"
            log.append("  [RECONCILE] Handover-inject quarantined "
                       "(no reconfig in events).")
        if is_prose and not has_prose:
            _downgrade(f, confidence="SUSPECTED",
                note="QUARANTINED: no proximity/ProSe IE in decoded events.")
            f["verification_status"] = "UNVERIFIED"
            log.append("  [RECONCILE] ProSe finding quarantined "
                       "(no proximity IE in events).")

    if not log:
        log.append("  [RECONCILE] No CID/handover/ProSe corrections needed.")
    return findings, log
