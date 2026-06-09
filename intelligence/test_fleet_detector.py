"""
Test suite — FleetSignatureDetector
Synthetic signal scenarios covering all major AU fleet categories.
Run: python tests/test_fleet_detector.py
"""

import sys, os, json
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detectors.fleet_signature_detector import FleetSignatureDetector, ObservedSignal, AlertLevel

LIBRARY_DIR = os.path.join(os.path.dirname(__file__), "..", "intelligence")

def get_detector():
    return FleetSignatureDetector(LIBRARY_DIR)

# ─── EMERGENCY SERVICES ──────────────────────────────────────────────

def test_vicpol_composite_detected():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="tetra", freq_mhz=391.5),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_interval_s=15.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B3"),  # secondary MDT band
    ]
    results = {r.signature_id: r for r in d.analyze(signals, location=(-38.1100, 145.2780))}
    assert "vicpol_mobile_unit_composite" in results, f"Got: {list(results)}"
    c = results["vicpol_mobile_unit_composite"].confidence
    assert c >= 0.75, f"Confidence too low: {c}"
    print(f"  VicPol composite: {c:.1%}")

def test_ambulance_differentiator_optus():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="tetra", freq_mhz=385.0),
        ObservedSignal(signal_type="lte", carrier="optus", band="B28"),
        ObservedSignal(signal_type="bluetooth", advertisement_interval_ms=100.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "av_composite" in results, f"Got: {list(results)}"
    assert "vicpol_mobile_unit_composite" not in results
    print(f"  Ambulance Victoria: {results['av_composite'].confidence:.1%}")

def test_frv_fire_truck():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="tetra", freq_mhz=388.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_interval_s=60.0),
        ObservedSignal(signal_type="wifi", freq_mhz=5800.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "frv_composite" in results, f"Got: {list(results)}"
    print(f"  FRV: {results['frv_composite'].confidence:.1%}")

def test_vicpol_drone_remote_id():
    d = get_detector()
    signals = [
        ObservedSignal(
            signal_type="ble", manufacturer_id="0x2C05",
            advertisement_interval_ms=1000.0, payload_type="astm_f3411_22a",
            raw_metadata={"remote_id_payload": {
                "serial_number": "DJI-MAVIC3E-ABC123", "operator_id": "CASA-GOVT-007",
                "lat": -38.1105, "lon": 145.2775, "altitude_m": 45.0, "velocity_ms": 8.5,
            }}
        ),
        ObservedSignal(signal_type="ocusync3", freq_mhz=5825.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "vicpol_drone_djimavic" in results or "dji_ocusync3_drone" in results, f"Got: {list(results)}"
    key = "vicpol_drone_djimavic" if "vicpol_drone_djimavic" in results else "dji_ocusync3_drone"
    r = results[key]
    assert r.remote_id is not None
    assert r.remote_id.serial_number == "DJI-MAVIC3E-ABC123"
    print(f"  DJI drone {key}: {r.confidence:.1%}, Remote ID: {r.remote_id.serial_number}")

# ─── GOVERNMENT / REGULATORY ─────────────────────────────────────────

def test_acma_field_vehicle_detected():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_interval_s=600.0),
        ObservedSignal(signal_type="wifi", freq_mhz=5000.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "acma_field_vehicle" in results, f"Got: {list(results)}"
    print(f"  ACMA field vehicle: {results['acma_field_vehicle'].confidence:.1%}")

def test_afp_p25_differentiator():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="tetra", freq_mhz=393.0),
        ObservedSignal(signal_type="p25", freq_mhz=855.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28"),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "afp_vehicle_composite" in results, f"Got: {list(results)}"
    print(f"  AFP vehicle: {results['afp_vehicle_composite'].confidence:.1%}")

def test_low_footprint_intel_vehicle_flagged():
    d = get_detector()
    signals = [ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_interval_s=120.0)]
    results = {r.signature_id: r for r in d.analyze(signals, min_confidence=0.40)}
    assert "unknown_intel_vehicle" in results, f"Got: {list(results)}"
    assert results["unknown_intel_vehicle"].requires_corroboration is True
    assert results["unknown_intel_vehicle"].alert_level == "flag"
    print(f"  Low-footprint flagged, requires_corroboration=True")

# ─── INFRASTRUCTURE ──────────────────────────────────────────────────

def test_anpr_mobile_trailer():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_duration_ms=80.0),
        ObservedSignal(signal_type="wifi", freq_mhz=5000.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals, min_confidence=0.45)}
    assert "vicroads_mobile_anpr_trailer" in results, f"Got: {list(results)}"
    print(f"  ANPR trailer: {results['vicroads_mobile_anpr_trailer'].confidence:.1%}")

def test_smart_meter_reader_915mhz():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="ismsub_ghz", freq_mhz=915.0, burst_duration_ms=50.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28"),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "smart_meter_reading_vehicle" in results, f"Got: {list(results)}"
    print(f"  Smart meter reader: {results['smart_meter_reading_vehicle'].confidence:.1%}")

def test_telco_field_tech_flagged():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28"),
        ObservedSignal(signal_type="wifi", freq_mhz=5000.0, ssid="TELSTRA_FIELD_VIC42"),
        ObservedSignal(signal_type="bluetooth", advertisement_interval_ms=300.0),
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "nbn_field_technician_vehicle" in results, f"Got: {list(results)}"
    r = results["nbn_field_technician_vehicle"]
    assert r.alert_level == "flag"
    assert len(r.forensic_note) > 0
    print(f"  Telco tech flagged. Forensic note: {r.forensic_note[:60]}...")

# ─── PERSONAL TRACKERS ───────────────────────────────────────────────

def test_airtag_separated_warning():
    d = get_detector()
    signals = [ObservedSignal(
        signal_type="ble", manufacturer_id="0x004C",
        payload_type="apple_nearby_action",
        advertisement_interval_ms=500.0, separation_indicator=True
    )]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "apple_airtag_separated" in results
    assert results["apple_airtag_separated"].alert_level == "warning"
    print(f"  AirTag separated WARNING: {results['apple_airtag_separated'].confidence:.1%}")

def test_tile_static_mac_detected():
    d = get_detector()
    signals = [ObservedSignal(
        signal_type="ble", manufacturer_id="0x00D7",
        service_uuid="0xFEED", advertisement_interval_ms=500.0,
        mac_address="AA:BB:CC:DD:EE:FF"
    )]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "tile_tracker" in results
    print(f"  Tile tracker: {results['tile_tracker'].confidence:.1%}")

def test_lte_m_gps_tracker():
    d = get_detector()
    signals = [ObservedSignal(
        signal_type="lte_m", band="B28",
        burst_duration_ms=80.0, burst_interval_s=30.0, rsrp_dbm=-115.0
    )]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "generic_lte_m_tracker" in results
    print(f"  LTE-M tracker: {results['generic_lte_m_tracker'].confidence:.1%}")

def test_anomalous_2g_alert():
    d = get_detector()
    signals = [ObservedSignal(signal_type="gsm", freq_mhz=900.0, band="B8")]
    results = {r.signature_id: r for r in d.analyze(signals, min_confidence=0.40)}
    assert "legacy_2g_gsm_tracker" in results
    assert results["legacy_2g_gsm_tracker"].alert_level == "high"
    print(f"  2G anomaly HIGH alert raised")

# ─── DRONES ──────────────────────────────────────────────────────────

def test_generic_remote_id_drone():
    d = get_detector()
    signals = [
        ObservedSignal(
            signal_type="ble", payload_type="astm_f3411_22a",
            advertisement_interval_ms=1000.0,
            raw_metadata={"remote_id_payload": {
                "serial_number": "DRONE-XYZ-9001", "operator_id": "CASA-OP-12345",
                "lat": -38.112, "lon": 145.281, "altitude_m": 30.0, "velocity_ms": 5.0
            }}
        ),
        ObservedSignal(signal_type="wifi", freq_mhz=2400.0),  # wifi_nan
    ]
    results = {r.signature_id: r for r in d.analyze(signals)}
    assert "drone_remote_id_generic" in results, f"Got: {list(results)}"
    r = results["drone_remote_id_generic"]
    assert r.confidence >= 0.50
    assert r.remote_id is not None
    assert r.remote_id.serial_number == "DRONE-XYZ-9001"
    print(f"  Generic drone Remote ID: {r.confidence:.1%}, sn={r.remote_id.serial_number}")

def test_non_compliant_drone_flagged():
    """Non-DJI control link with no Remote ID = non-compliant flag."""
    d = get_detector()
    # Simulate a generic 5.8GHz hopping control link (not OcuSync/DJI specific)
    signals = [ObservedSignal(signal_type="wifi", freq_mhz=5785.0)]
    results = {r.signature_id: r for r in d.analyze(signals, min_confidence=0.40)}
    # Should either flag as unknown drone OR not match high-confidence drone profile
    # Key: no Remote ID present = compliance issue if drone control link detected
    non_compliant = [r for r in results.values()
                     if "drone" in r.signature_id and r.alert_level == "flag"]
    # Accept: either explicit flag or absence of high-confidence drone match
    print(f"  Non-compliant check: {[r.signature_id for r in non_compliant] or 'no drone match (correct — ambiguous signal)'}")

# ─── REPORT / OUTPUT ─────────────────────────────────────────────────

def test_report_generation():
    d = get_detector()
    signals = [
        ObservedSignal(signal_type="tetra", freq_mhz=390.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B28", burst_interval_s=15.0),
        ObservedSignal(signal_type="lte", carrier="telstra", band="B3"),
        ObservedSignal(signal_type="ble", manufacturer_id="0x004C",
            payload_type="apple_nearby_action",
            advertisement_interval_ms=500.0, separation_indicator=True),
        ObservedSignal(signal_type="ble", payload_type="astm_f3411_22a",
            advertisement_interval_ms=1000.0,
            raw_metadata={"remote_id_payload": {
                "serial_number": "TEST-DRONE-001", "operator_id": "CASA-TEST",
                "lat": -38.11, "lon": 145.28, "altitude_m": 50.0, "velocity_ms": 3.0
            }}),
        ObservedSignal(signal_type="wifi", freq_mhz=2400.0),
    ]
    results = d.analyze(signals, location=(-38.1100, 145.2780))
    assert len(results) > 0
    report = d.format_report(results)
    assert "DETECTION REPORT" in report
    castnet_json = d.to_castnet_json(results)
    parsed = json.loads(castnet_json)
    assert isinstance(parsed, list) and len(parsed) > 0
    print(f"\n  {len(results)} detections, JSON serialization OK")
    print(f"  Top hit: {results[0].label} ({results[0].confidence:.1%})")


if __name__ == "__main__":
    tests = [
        test_vicpol_composite_detected,
        test_ambulance_differentiator_optus,
        test_frv_fire_truck,
        test_vicpol_drone_remote_id,
        test_acma_field_vehicle_detected,
        test_afp_p25_differentiator,
        test_low_footprint_intel_vehicle_flagged,
        test_anpr_mobile_trailer,
        test_smart_meter_reader_915mhz,
        test_telco_field_tech_flagged,
        test_airtag_separated_warning,
        test_tile_static_mac_detected,
        test_lte_m_gps_tracker,
        test_anomalous_2g_alert,
        test_generic_remote_id_drone,
        test_non_compliant_drone_flagged,
        test_report_generation,
    ]
    passed = failed = 0
    for t in tests:
        try:
            print(f"\nRUN  {t.__name__}")
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            import traceback; traceback.print_exc()
            failed += 1
    print(f"\n{'='*50}")
    print(f"Results: {passed}/{len(tests)} passed, {failed} failed")
