"""
corpus_guard.py — provenance & internal-consistency validator for
                  rayhunter-threat-analyzer reports.

PURPOSE
-------
Three failure modes were observed in the v4.3 run on the June 7-11 corpus.
This harness flags all three BEFORE a report can be trusted or submitted:

  A. CORPUS BLEED-THROUGH
     Findings cited evidence (dates, session counts, locations) that does NOT
     exist in the input file set — e.g. May-25 co-presence windows, a 394-session
     corpus, a 76.9h blackout, "74 Prendergast Ave" — in a report whose inputs
     were 9 files dated Jun 7-11 with zero GPS. Conclusions must be supported by
     the bytes actually in the input set.

  B. ABSENCE-SCORED-AS-PRESENCE
     The YAICD block credited "EEA0 Null-Cipher Present (Active MitM)" while the
     detail finding said EEA0 rate = 0%. A score that increments on both presence
     AND absence of a signal is unfalsifiable. Flag any indicator asserted present
     whose own evidence says the count is zero.

  C. PHANTOM-MESSAGE FINDINGS
     Findings [3]/[9] cited rrcConnectionReconfiguration / mobilityControlInfo /
     ProSe messages that an independent ASN.1 decode shows DO NOT EXIST in the
     capture. Any finding whose message type isn't present in the decoded
     message-type census is quarantined.
"""

import re, json, datetime as dt


def _dates_in(text):
    return set(re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", text))


def check_provenance(report_text, input_date_min, input_date_max,
                     gps_present: bool):
    """A. flag evidence dates outside the input window, and geo claims w/o GPS."""
    issues = []
    lo = dt.date.fromisoformat(input_date_min)
    hi = dt.date.fromisoformat(input_date_max)
    for d in sorted(_dates_in(report_text)):
        try: dd = dt.date.fromisoformat(d)
        except ValueError: continue
        if dd < lo or dd > hi:
            issues.append(("BLEED_THROUGH",
                f"Finding cites {d}, outside input window {input_date_min}..{input_date_max}"))
    if not gps_present:
        for kw in ["547m", "Prendergast", "KML", "movement corridor",
                   "distance ring", "TA distance", "geolocat"]:
            if kw.lower() in report_text.lower():
                issues.append(("GEO_WITHOUT_GPS",
                    f"Geographic claim ('{kw}') but all GPS inputs are empty"))
    # corpus-size tells
    for m in re.finditer(r"(\d{2,4})[ -]session", report_text):
        if int(m.group(1)) > 9:
            issues.append(("BLEED_THROUGH",
                f"Cites {m.group(1)}-session corpus; input set is 9 files"))
            break
    return issues


def check_falsifiability(indicator_text, detail_findings):
    """B. flag indicators marked present whose evidence says count==0 / rate 0%."""
    issues = []
    # detail_findings: list of (title, evidence_text)
    joined = "\n".join(t + "\n" + e for t, e in detail_findings)
    if re.search(r"EEA0.*0%|null[- ]?cipher.*\b0\b", joined, re.I) and \
       re.search(r"EEA0 Null-?Cipher Present", indicator_text, re.I):
        issues.append(("UNFALSIFIABLE",
            "YAICD credits 'EEA0 Null-Cipher Present' but detail says EEA0 = 0%"))
    if re.search(r"No Forced 2G Downgrade", indicator_text, re.I):
        issues.append(("UNFALSIFIABLE",
            "Counts ABSENCE of 2G downgrade as a positive indicator "
            "('transparent proxy') — present->catcher, absent->catcher"))
    return issues


def check_phantom_messages(claimed_msg_types, decoded_census: dict):
    """
    C. claimed_msg_types: set of RRC message names the report asserts it found
       decoded_census: {msgtype: count} from an independent ASN.1 decode
    Flag any claimed type with zero decoded occurrences.
    """
    issues = []
    for mt in claimed_msg_types:
        present = any(mt.lower() in k.lower() and v > 0
                      for k, v in decoded_census.items())
        if not present:
            issues.append(("PHANTOM_MESSAGE",
                f"Report cites '{mt}' but ASN.1 decode finds 0 in corpus"))
    return issues


def run_all(report_text, *, input_date_min, input_date_max, gps_present,
            indicator_text, detail_findings, claimed_msg_types, decoded_census):
    out = []
    out += check_provenance(report_text, input_date_min, input_date_max, gps_present)
    out += check_falsifiability(indicator_text, detail_findings)
    out += check_phantom_messages(claimed_msg_types, decoded_census)
    return out


# =============================================================================
# v2 additions (June 2026) — CASTNET count overflow + measurement-backed geo
# These replace reliance on the old GPS-presence heuristic, which false-fires
# when GPS is intentionally disabled in firmware (operator already knows the
# transmitter locations).
# =============================================================================

def check_event_count_overflow(findings, decoded_frame_count, tolerance=1.10):
    """
    Flag any finding asserting an event/detection count that exceeds what was
    actually decoded from the input file set. This catches CASTNET (or any
    external store) being summed into per-capture totals.

    findings: iterable of (title, evidence_text)
    decoded_frame_count: int — total frames/events decoded from THIS input set
                         (e.g. sum of Phase-1 per-file event counts)
    """
    issues = []
    cap = int(decoded_frame_count * tolerance)
    num = re.compile(
        r"(?:([\d][\d,]{2,})\s*(?:attack events|events analysed|events|"
        r"CASTNET detections|detections))"
        r"|(?:(?:attack events|events analysed|events|CASTNET detections|"
        r"detections)[:\s]*([\d][\d,]{2,}))", re.I)
    for title, ev in findings:
        for m in num.finditer(ev + " " + title):
            val = int((m.group(1) or m.group(2)).replace(",", ""))
            if val > cap:
                issues.append(("COUNT_OVERFLOW",
                    f"'{title[:50]}' cites {val:,} events but only "
                    f"{decoded_frame_count:,} decoded from input set "
                    f"(+{tolerance:.0%} tol). Likely external/CASTNET data "
                    f"summed into capture totals — tag source or separate."))
                break
    return issues


def check_geo_provenance(findings):
    """
    A geographic/location claim must either carry an in-capture measurement
    (TA / RSRP / GPS fix) OR be explicitly source-tagged (known_location,
    castnet, opencellid). GPS being off is NOT itself a problem; an unsourced
    distance/coordinate claim is.

    findings: iterable of (title, evidence_text, source_tag_or_None)
    """
    issues = []
    geo_kw = re.compile(r"\b(\d{2,4}\s*m\b|metres|meters|coordinate|lat\b|"
                        r"lon\b|address|distance ring|movement corridor|"
                        r"\bKML\b|geolocat)", re.I)
    # A real in-capture measurement = RSRP, a GPS fix, or TA WITH a positive
    # sample count. A bare "TA=7" value alone does not substantiate a distance.
    meas_kw = re.compile(r"\b(RSRP|GPS fix|TA distance samples?\s*[:=]\s*[1-9])",
                         re.I)
    ok_sources = {"known_location", "operator_known", "castnet",
                  "opencellid", "register"}
    for item in findings:
        title, ev = item[0], item[1]
        src = item[2] if len(item) > 2 else None
        blob = title + "\n" + ev
        if not geo_kw.search(blob):
            continue
        has_meas = bool(meas_kw.search(blob))
        # explicit "0 samples" defeats any measurement claim
        if re.search(r"TA distance samples?\s*[:=]\s*0\b", blob, re.I):
            has_meas = False
        tagged = (str(src).lower() in ok_sources) if src else False
        if not has_meas and not tagged:
            issues.append(("GEO_UNSOURCED",
                f"'{title[:50]}' makes a location claim with no in-capture "
                f"measurement (TA/RSRP/GPS) and no source tag. If derived from "
                f"known transmitter locations, tag source='known_location'."))
    return issues


# =============================================================================
# v3 additions — schema-aware (base.py make_finding) checks
# =============================================================================

def check_event_count_field(findings, decoded_frame_count, tolerance=1.10):
    """
    Schema-aware overflow check: reads the make_finding() 'event_count' field
    directly instead of scraping text. Flags any finding whose event_count
    exceeds what was decoded from the input set (CASTNET data summed in).

    findings: list of make_finding() dicts
    """
    issues = []
    cap = int(decoded_frame_count * tolerance)
    for f in findings:
        ec = f.get("event_count", 0) or 0
        if ec > cap:
            issues.append(("COUNT_OVERFLOW",
                f"'{f.get('detector','?')}' event_count={ec:,} exceeds "
                f"{decoded_frame_count:,} decoded from input set "
                f"(+{tolerance:.0%} tol). External/CASTNET data summed in — "
                f"tag source or separate."))
    return issues


def tag_source(finding, source):
    """
    Stamp a make_finding() dict with provenance. Use in CASTNET-fed detectors:
        return [tag_source(f, "castnet") for f in findings]
    Valid sources: capture, castnet, known_location, opencellid, register, bugreport.
    """
    finding["source"] = source
    return finding


def check_source_tags(findings):
    """
    Flag findings that draw on external data (by detector name or evidence text)
    but carry no source tag — so CASTNET-derived findings can't silently read as
    fresh capture output. Advisory (INFO), not a hard fail.
    """
    issues = []
    # Only the detectors that actually read the CASTNET store / multi-session corpus.
    castnet_detectors = {
        "crosscarriertimercorrelator", "regulatoryescalationscorer",
        "behavioralrhythmfingerprinter", "operatorrhythmprofiler",
        "attackintensityscorer", "attackcampaignsegmenter",
        "crosssessionpersistencetracker", "jitterdnatracker",
        "silentperioddetector", "regulatoryeventcorrelator", "tuckertaxonomyscorer",
    }
    strong_markers = ("castnet", "394-session", "394 session", "corpus baseline",
                      "detection density", "sessions analysed")
    for f in findings:
        name = str(f.get("detector", "")).lower().replace("_", "").replace(" ", "")
        blob = " ".join(f.get("evidence", []) if isinstance(f.get("evidence"), list)
                        else [str(f.get("evidence", ""))]).lower()
        hits_castnet = name in castnet_detectors or any(m in blob for m in strong_markers)
        if hits_castnet and not f.get("source"):
            issues.append(("UNTAGGED_SOURCE",
                f"'{f.get('detector','?')}' appears to use external/CASTNET data "
                f"but has no source tag. Add tag_source(f, 'castnet')."))
    return issues
