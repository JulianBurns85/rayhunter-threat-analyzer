"""Regression tests for false-positive fixes (commit 9ebcdd2)."""

from detectors.attach_detach_analyser import AttachDetachCycleAnalyser
from detectors.flash_catch import FlashCatchDetector
from detectors.paging_volume_anomaly import PagingVolumeAnomalyDetector
from detectors.rrc_periodicity import RRCPeriodicityDetector
from parsers.pcap_parser import PcapParser


def test_imeisv_identity_request_not_counted_as_imsi_paging_flood():
    """Routine IMEISV (type 3) Identity Requests must not trigger HIGH Pre-Harvest Floods."""
    detector = PagingVolumeAnomalyDetector({})
    base = 1700000000.0
    events = [
        *[{"message_type": "Paging", "timestamp": base + i * 30.0} for i in range(10)],
        *[{"message_type": "Paging", "timestamp": base + 400.0 + i * 2.0, "paging_identity": "s-tmsi"} for i in range(12)],
        {"message_type": "Identity Request", "identity_type": "IMEISV", "id_type": "3", "timestamp": base + 430.0},
    ]
    findings = detector.analyze(events)
    assert not any(f.get("severity") in ("HIGH", "CRITICAL") for f in findings)


def test_attach_detach_dedup_and_per_file_pairing():
    """Sub-1.0s NAS wrappers collapse to 1 event, and cross-file Attach/Detach pairs do not fire."""
    deduped = AttachDetachCycleAnalyser._dedup_ts([100.0, 100.25, 100.8, 105.0, 105.4], window_s=1.0)
    assert deduped == [100.0, 105.0]

    detector = AttachDetachCycleAnalyser({})
    base = 1700000000.0
    events = [
        {"msg_type": "Attach Request", "timestamp": base, "source_file": "a.pcapng"},
        {"msg_type": "Attach Request", "timestamp": base + 0.2, "source_file": "a.pcapng"},
        {"msg_type": "Detach Request", "timestamp": base + 10.0, "source_file": "b.pcapng"},
    ]
    findings = detector.analyze(events)
    assert not any(f.get("severity") == "CRITICAL" for f in findings)


def test_flashcatch_requires_score_3_of_4():
    """Brief cell reselection (score=2/4) is ignored; score>=3/4 still fires."""
    detector = FlashCatchDetector({})
    base = 1700000000.0
    home_events = []
    for idx, cid in enumerate(("100", "101", "102")):
        for i in range(10):
            home_events.append({
                "cid": cid, "enb": "1", "band": "B28",
                "timestamp": base + idx * 100.0 + i * 5.0,
            })

    reselection = [
        {"cid": "200", "enb": "2", "band": "B3", "timestamp": base + 500.0},
        {"cid": "200", "enb": "2", "band": "B3", "timestamp": base + 500.5},
    ]
    assert detector.analyze(home_events + reselection) == []

    displacement = [
        {"cid": "300", "enb": "3", "band": "B28", "timestamp": base + 600.0},
        {"cid": "300", "enb": "3", "band": "B28", "timestamp": base + 600.4},
    ]
    findings = detector.analyze(home_events + displacement)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_rrc_periodicity_requires_machine_precision_sd():
    """210.2s intervals with organic jitter (SD >= 200ms) are ignored; tight SD (< 200ms) fires."""
    detector = RRCPeriodicityDetector({})

    t = 1700000000.0
    organic_events = [{"message_type": "RRCConnectionRelease", "timestamp": t}]
    for delta in (208.1, 212.4, 209.0, 211.7):
        t += delta
        organic_events.append({"message_type": "RRCConnectionRelease", "timestamp": t})
    assert detector.analyze(organic_events) == []

    t = 1700010000.0
    metronomic_events = [{"message_type": "RRCConnectionRelease", "timestamp": t}]
    for delta in (210.20, 210.21, 210.19, 210.20):
        t += delta
        metronomic_events.append({"message_type": "RRCConnectionRelease", "timestamp": t})
    findings = detector.analyze(metronomic_events)
    assert any(f.get("severity") == "CRITICAL" for f in findings)


def test_raw_0x55_nas_id_type2_decoding():
    """Raw 0x55 NAS Identity Request bytes must decode id_type2: 1=IMSI, 3=IMEISV, missing=UNKNOWN."""
    parser = PcapParser({})
    # Standard 16-byte GSMTAP v2 header (version=2, hdr_len=4 words, type=0x0d LTE NAS)
    gsmtap_hdr = b"\x02\x04\x0d\x00" + (b"\x00" * 12)

    ev_imsi = parser._extract_gsmtap_basic(gsmtap_hdr + b"\x07\x55\x01", "test.pcap", 1700000000.0)
    assert ev_imsi is not None and ev_imsi.get("msg_type") == "Identity Request"
    assert ev_imsi.get("identity_type") == "IMSI"

    ev_imeisv = parser._extract_gsmtap_basic(gsmtap_hdr + b"\x07\x55\x03", "test.pcap", 1700000000.0)
    assert ev_imeisv is not None and ev_imeisv.get("msg_type") == "Identity Request"
    assert ev_imeisv.get("identity_type") == "IMEISV"

    ev_trunc = parser._extract_gsmtap_basic(gsmtap_hdr + b"\x07\x55", "test.pcap", 1700000000.0)
    assert ev_trunc is not None and ev_trunc.get("msg_type") == "Identity Request"
    assert ev_trunc.get("identity_type") == "UNKNOWN"
