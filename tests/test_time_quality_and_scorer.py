import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from time_quality import audit_and_tag
from forensic_time import trusted_timestamp
from detectors.heuristic_scorer import HeuristicScorerDetector

B = 1_792_071_242   # 2026-10-15

def ev(t, f="1792071242.pcapng"):
    return {"timestamp": t, "source_file": f}

def test_tags_out_of_window_and_filename_mismatch():
    evs = [ev(B + 100), ev(B + 40 * 86400), ev(1_700_000_000), ev(None), ev(B + 5, "29.pcapng")]
    audit_and_tag(evs, {})
    ok = [trusted_timestamp(e) for e in evs]
    assert ok == [True, False, False, False, True]
    assert evs[1]["timestamp_source"] == "filename_mismatch" and evs[2]["timestamp_source"] == "out_of_window"

def test_parser_set_source_is_preserved():
    e = ev(B + 1); e["timestamp_source"] = "mtime"
    audit_and_tag([e], {})
    assert e["timestamp_source"] == "mtime"

def F(title, sev, conf, det="X", **k):
    d = dict(title=title, severity=sev, confidence=conf, detector=det, description="", technique="", evidence=[])
    d.update(k); return d

def score(findings):
    return HeuristicScorerDetector({}).analyze([], findings)

def test_low_info_findings_cannot_trigger_yaicd():
    out = score([F("IMEISV Identity Request(s) — 68 Event(s)", "LOW", "SUSPECTED", "IdentityHarvestDetector", event_count=68),
                 F("Handover(s) present — UL MeasurementReport channel NOT captured", "INFO", "SUSPECTED", "HandoverInjectDetector"),
                 F("Multi-sector macro (NOT rotation) — TAC=1 eNB=2", "INFO", "SUSPECTED", "CIDRotationDetector"),
                 F("Cipher Negotiation — CLEAN (EEA0 0%)", "INFO", "CONFIRMED")])
    assert out.yaicd_formal_score == 0 and not out.yaicd_detected
    assert "P7_imeisv_harvest" not in out.triggered_params and "P_handover_inject" not in out.triggered_params

def test_absence_is_not_scored_as_confirmed():
    out = score([])
    by = {h.heuristic_id: h.status for h in out.heuristics}
    assert by["4.1.4"] == "NOT_APPLICABLE" and by["4.1.6"] == "NOT_APPLICABLE" and by["4.1.8"] == "NOT_APPLICABLE"
    assert out.confirmed_count == 0

def test_qualifying_findings_still_score():
    out = score([F("Repeated IMSI Identity Requests", "HIGH", "PROBABLE", "IdentityHarvestDetector", event_count=6)])
    assert "P7_imeisv_harvest" in out.triggered_params
