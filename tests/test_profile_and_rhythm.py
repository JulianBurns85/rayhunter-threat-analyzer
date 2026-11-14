import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detectors.operational_profile_synthesiser import OperationalProfileSynthesiser
from detectors.operator_rhythm import OperatorRhythmProfiler, binom_sf

BASE = 1_790_000_000  # 2026-09 UTC

def evs(days=8, per=60):
    return [{"timestamp": BASE + d * 86400 + i * 60, "msg_type": "X", "cell_id": "137713155"}
            for d in range(days) for i in range(per)]

def test_synth_no_hardcoded_claims_and_no_zero_lines():
    s = OperationalProfileSynthesiser({})
    s.set_findings([])
    f = s.analyze(evs())[0]
    text = "\n".join(f["evidence"])
    assert f["severity"] == "LOW" and "Harris" not in text and ": 0 event" not in text

def test_synth_uses_findings():
    s = OperationalProfileSynthesiser({})
    s.set_findings([{"detector": "WalletInspectorDetector", "title": "Pre-security IMSI request",
                     "severity": "HIGH", "confidence": "CONFIRMED", "event_count": 28}])
    f = s.analyze(evs())[0]
    assert f["severity"] == "HIGH" and f["confidence"] == "PROBABLE"   # no control -> not CONFIRMED
    assert "28 event(s)" in "\n".join(f["evidence"])

def test_rhythm_needs_days_and_caps_severity():
    r = OperatorRhythmProfiler({})
    assert r.analyze(evs(days=3)) == []
    out = r.analyze(evs(days=10))
    assert out and out[0]["severity"] in ("LOW", "MEDIUM") and out[0]["confidence"] != "CONFIRMED"

def test_binom():
    assert abs(binom_sf(0, 10, .5) - 1) < 1e-12 and abs(binom_sf(10, 10, .5) - 0.5 ** 10) < 1e-12
