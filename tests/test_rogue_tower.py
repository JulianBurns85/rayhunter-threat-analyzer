import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detectors.rogue_tower import RogueTowerDetector

def cfg(tmp):
    return {"network": {"mcc": "505", "mnc": "001"},
            "opencellid": {"enabled": False, "cache_file": str(tmp / "c.json")},
            "detection": {"rogue_tower": {"known_rogue_cids": ["137713155"], "known_rogue_enbs": [33853],
                                          "watchlist_cids": ["21940490"]},
                          "earfcn_anomaly": {"known_rogue_earfcns": [16384]}}}

def ev(cid, mnc="001", earfcn=9350, rsrp=-80, **k):
    return dict(cell_id=cid, mcc="505", mnc=mnc, earfcn=earfcn, tac="12385", rsrp=rsrp,
                timestamp="2026-10-09T10:00:00+00:00", **k)

def test_list_rules_now_fire_but_are_not_confirmed(tmp_path):
    d = RogueTowerDetector(cfg(tmp_path))
    f = d.analyze([ev("137713155"), ev("8666381", mnc="003"), ev("21940490")])
    titles = [x["title"] for x in f]
    assert any("137713155 is on the analyst rogue list" in t for t in titles)
    assert any("8666381 is on the analyst rogue list" in t for t in titles)   # via eNB 33853
    assert any("Watchlist cell 21940490" in t for t in titles)
    assert all(x["severity"] != "CRITICAL" for x in f)

def test_vodafone_cell_checked_against_vodafone_bands(tmp_path):
    d = RogueTowerDetector(cfg(tmp_path))
    f = d.analyze([ev("8409357", mnc="003", earfcn=3500)])   # B8: valid for Vodafone, not Telstra
    assert not any("outside" in x["title"] for x in f)
    f = d.analyze([ev("137713155", mnc="001", earfcn=3500)])
    assert any("outside Telstra" in x["title"] for x in f)

def test_pci_placeholder_never_looked_up(tmp_path):
    c = cfg(tmp_path); c["opencellid"]["enabled"] = True; c["opencellid"]["api_key"] = "x"
    d = RogueTowerDetector(c)
    called = []
    d._lookup_opencellid = lambda *a, **k: called.append(a) or "NOT_FOUND"
    d.analyze([dict(pci=42, earfcn=9350, mcc="505", mnc="001", timestamp="2026-10-09T10:00:00+00:00")])
    assert called == []

def test_bad_rsrp_does_not_crash_and_multi_earfcn_tracked(tmp_path):
    d = RogueTowerDetector(cfg(tmp_path))
    f = d.analyze([ev("999", rsrp="N/A"), ev("999", earfcn=16384)])
    assert any("16384" in x["title"] for x in f)

def test_opencellid_errors_not_cached_as_not_found(tmp_path, monkeypatch):
    import requests
    c = cfg(tmp_path); c["opencellid"].update(enabled=True, api_key="tok")
    d = RogueTowerDetector(c)
    class R:
        def __init__(s, j): s.j = j
        def json(s): return s.j
    monkeypatch.setattr(requests, "get", lambda *a, **k: R({"status": "error", "message": "Invalid token"}))
    assert d._lookup_opencellid("1", "505", "003", "1") == {}
    assert d._cell_cache == {}
    monkeypatch.setattr(requests, "get", lambda *a, **k: R({"status": "error", "message": "Cell not found"}))
    assert d._lookup_opencellid("1", "505", "003", "1") == "NOT_FOUND"
