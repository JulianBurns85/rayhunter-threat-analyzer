import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detectors.identity_harvest import IdentityHarvestDetector
from detectors.cipher_downgrade import CipherDowngradeDetector
from detectors.handover_inject import HandoverInjectDetector

B = 1_790_000_000
def ev(t=0, mt=None, f="a.pcap", **k):
    d = dict(timestamp=(B + t) if t is not None else None, msg_type=mt, source_file=f, raw={})
    d.update(k); return d

CFG = {"detection": {"identity_harvest": {"window_seconds": 60, "max_requests": 1}}}

def test_identity_reads_detection_config():
    d = IdentityHarvestDetector(CFG)
    assert d.window == 60 and d.max_normal == 1

def test_identity_untimed_flood_is_not_critical_confirmed():
    evs = [ev(None, "Identity Request", identity_type="IMSI", timestamp=None) for _ in range(5)]
    f = IdentityHarvestDetector({}).analyze(evs)
    assert f and all(x["severity"] != "CRITICAL" and x["confidence"] != "CONFIRMED" for x in f)

def test_identity_windows_are_per_file():
    evs = [ev(i * 1000, "Identity Request", identity_type="IMSI", f=f"{i}.pcap") for i in range(5)]
    assert not any("Repeated" in x["title"] for x in IdentityHarvestDetector({}).analyze(evs))
    evs = [ev(i, "Identity Request", identity_type="IMSI") for i in range(5)]
    assert any("Repeated" in x["title"] for x in IdentityHarvestDetector({}).analyze(evs))

def test_identity_no_case_narrative_and_protected_imeisv_low():
    evs = [ev(1, "Identity Request", identity_type="IMEISV", security_header_type=2)]
    f = IdentityHarvestDetector({}).analyze(evs)
    text = str(f)
    assert "Harris" not in text and "ENQ-" not in text and "1778156124" not in text
    assert f[0]["severity"] == "LOW"

def test_untimed_auth_reject_not_matched_to_untimed_request():
    evs = [ev(None, "Authentication Reject", timestamp=None), ev(None, "Identity Request", identity_type="IMSI", timestamp=None)]
    assert not any("Authentication Reject" in x["title"] for x in IdentityHarvestDetector({}).analyze(evs))

def test_cipher_raw_text_cannot_create_findings_or_mutate():
    e1 = ev(1, "UE Capability Information", raw={"x": "geran handover proximity eea0 eia0"})
    e2 = ev(2, "Security Mode Command", raw={"replayed_ue_security_capabilities": "eea0 eia0 eea1 eia1"})
    f = CipherDowngradeDetector({}).analyze([e1, e2])
    assert not any(x["severity"] in ("CRITICAL", "HIGH") for x in f)
    assert not e1.get("has_geran_redirect") and not e1.get("has_mobility_control") and not e1.get("has_prose")
    assert not e2.get("cipher_alg")

def test_cipher_explicit_selection_and_release_redirect_still_detected():
    evs = [ev(1, "Security Mode Command", cipher_alg="EEA0", integrity_alg="EIA0"),
           ev(2, "RRC Connection Release", has_geran_redirect=True)]
    t = [x["title"] for x in CipherDowngradeDetector({}).analyze(evs)]
    assert any("Null Cipher" in x for x in t) and any("GERAN" in x for x in t)

def test_cipher_geran_flag_on_non_release_ignored_and_eea0_not_a50():
    evs = [ev(1, "SIB7", has_geran_redirect=True), ev(2, "Security Mode Command", cipher_alg="EEA0", integrity_alg="EIA2", layer="NAS")]
    t = [x["title"] for x in CipherDowngradeDetector({}).analyze(evs)]
    assert not any("GERAN" in x or "A5/0" in x for x in t)

def mci(t, f="a.pcap"):
    return ev(t, "RRC Connection Reconfiguration", f=f, has_mobility_control=True, target_pci=7, t304=100, target_earfcn=9350)

def test_handover_invalid_timestamp_not_injected():
    evs = [ev(5, None, has_measreport=True), mci(None), ]
    evs[1]["timestamp"] = None
    f = HandoverInjectDetector({}).analyze(evs)
    assert not any("Without Captured" in x["title"] or "Injected" in x["title"] for x in f)

def test_handover_corroboration_is_per_file():
    evs = [ev(0, None, has_measreport=True, f="a.pcap"), mci(100, "a.pcap"),
           ev(50, "Security Mode Command", cipher_alg="EEA0", f="other.pcap")]
    f = HandoverInjectDetector({}).analyze(evs)
    assert any("UNCONFIRMED" in x["title"] for x in f) and not any("corroborated" in x["title"] for x in f)

def test_handover_unassessable_when_file_has_no_reports():
    evs = [ev(0, None, has_measreport=True, f="b.pcap"), mci(100, "a.pcap")]
    f = HandoverInjectDetector({}).analyze(evs)
    assert any("not assessable" in x["title"] for x in f)
    assert not any("UNCONFIRMED" in x["title"] for x in f)
