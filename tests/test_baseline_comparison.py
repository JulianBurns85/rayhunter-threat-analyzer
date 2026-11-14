import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import baseline_comparison as bc

def rows():
    return [["1790000000.0", "85", "1", "0", "Identity request"],
            ["1790000010.0", "85", "2", "0", "Identity request"],
            ["1790000020.0", "82", "", "", "Authentication request"],
            ["1790000030.0", "", "", "", "RRCConnectionRelease"],
            ["1790003600.0", "0x55", "0x1", "0", "Identity request"]]

def test_parse():
    m = bc.parse_rows(rows())
    c = m["counts"]
    assert c["identity_request"] == 3 and c["identity_request_imsi"] == 2
    assert c["identity_request_imsi_plain"] == 2 and c["auth_request"] == 1 and c["rrc_release"] == 1
    assert m["duration_s"] == 3600.0

def test_compare_flags_only_real_excess():
    base = {"counts": {k: 0 for k in bc.COUNT_METRICS}, "hours": 5.0}
    inv = {"counts": {k: 0 for k in bc.COUNT_METRICS}, "hours": 5.0}
    base["counts"]["identity_request_imsi_plain"] = 1
    inv["counts"]["identity_request_imsi_plain"] = 30
    base["counts"]["auth_request"] = 40
    inv["counts"]["auth_request"] = 42
    r = {x["metric"]: x for x in bc.compare_profiles(base, inv)["metrics"]}
    assert r["identity_request_imsi_plain"]["flag"] == "EXCEEDS_BASELINE"
    assert r["auth_request"]["flag"] == "consistent"
