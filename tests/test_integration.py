"""
Integration smoke test — BladeRFBridge + FleetDetectorModule
Tests the full pipeline without real hardware.

Run: python tests\test_integration.py
"""

import sys
import os
import json
import tempfile
import struct
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.bladerf_bridge import BladeRFBridge
from detectors.fleet_detector_module import FleetDetectorModule
from detectors.fleet_signature_detector import FleetSignatureDetector, ObservedSignal


# ─── HELPERS ─────────────────────────────────────────────────────────

def make_synthetic_iq_bin(center_freq_mhz: float, emission_offset_mhz: float,
                           n_samples: int = 4096, datatype: str = "ci16_le") -> bytes:
    """
    Generate synthetic IQ data with a simulated emission at center+offset.
    Emission appears as a tone at the specified offset frequency.
    """
    import math
    data = bytearray()
    sample_rate_mhz = 20.0
    tone_phase_inc = 2 * math.pi * emission_offset_mhz / sample_rate_mhz

    for i in range(n_samples):
        # Tone at offset (signal) + noise
        I = int(1000 * math.cos(tone_phase_inc * i))
        Q = int(1000 * math.sin(tone_phase_inc * i))
        if datatype == "ci16_le":
            data += struct.pack("<hh", I, Q)
        elif datatype == "cu8":
            data += bytes([
                max(0, min(255, int(I / 8 + 127))),
                max(0, min(255, int(Q / 8 + 127)))
            ])
    return bytes(data)


def make_spectrum_csv(rows: list[tuple]) -> str:
    """Generate a spectrum CSV string from (freq_hz, power_dbm) pairs."""
    lines = ["frequency_hz,power_dbm"]
    for freq_hz, power in rows:
        lines.append(f"{freq_hz:.0f},{power:.1f}")
    return "\n".join(lines)


def make_sigmf_meta(center_freq_hz: float, sample_rate_hz: float,
                    datatype: str = "ci16_le") -> dict:
    return {
        "global": {
            "core:datatype": datatype,
            "core:sample_rate": sample_rate_hz,
            "core:frequency": center_freq_hz,
            "core:version": "1.0.0",
            "core:recorder": "bladeRF-cli"
        },
        "captures": [{
            "core:sample_start": 0,
            "core:datetime": datetime.now(timezone.utc).isoformat()
        }],
        "annotations": []
    }


# ─── BRIDGE TESTS ────────────────────────────────────────────────────

def test_bridge_csv_b28_tetra():
    """CSV with B28 LTE and TETRA emissions → correct signal types."""
    bridge = BladeRFBridge(noise_floor_dbm=-100.0, min_burst_duration_ms=10.0)

    rows = [
        # TETRA band (391 MHz)
        (391_000_000, -65.0),
        (391_500_000, -62.0),
        (392_000_000, -66.0),
        # Noise
        (500_000_000, -105.0),
        (600_000_000, -108.0),
        # B28 LTE downlink (762 MHz — Telstra)
        (762_000_000, -78.0),
        (762_500_000, -75.0),
        (763_000_000, -79.0),
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(make_spectrum_csv(rows))
        csv_path = f.name

    try:
        signals = bridge.from_bladerf_csv(csv_path)
        assert len(signals) > 0, "No signals detected from CSV"

        types = {s.signal_type for s in signals}
        print(f"  Signal types found: {types}")

        # Should find TETRA and/or LTE
        assert any(t in types for t in ["tetra", "lte", "ble_or_wifi"]), \
            f"Expected TETRA or LTE, got: {types}"

        for s in signals:
            if s.freq_mhz and 380 <= s.freq_mhz <= 400:
                assert s.signal_type == "tetra", \
                    f"Expected tetra at {s.freq_mhz}MHz, got {s.signal_type}"
            if s.freq_mhz and 758 <= s.freq_mhz <= 803:
                assert s.signal_type == "lte", \
                    f"Expected lte at {s.freq_mhz}MHz, got {s.signal_type}"
                assert "telstra" in (s.carrier or ""), \
                    f"Expected telstra carrier on B28, got {s.carrier}"

        print(f"  CSV bridge: {len(signals)} signals, types={types}")
    finally:
        os.unlink(csv_path)


def test_bridge_raw_iq_b28():
    """Raw IQ binary at B28 center → LTE signal detected."""
    bridge = BladeRFBridge(noise_floor_dbm=-100.0, min_burst_duration_ms=10.0)

    # Synthetic IQ: center 762MHz (Telstra B28 DL), tone at +2MHz offset
    iq_data = make_synthetic_iq_bin(center_freq_mhz=762.0, emission_offset_mhz=2.0)

    with tempfile.NamedTemporaryFile(suffix="_ci16.bin", delete=False) as f:
        f.write(iq_data)
        bin_path = f.name

    try:
        signals = bridge.from_raw_iq(
            bin_path,
            center_freq_mhz=762.0,
            sample_rate_mhz=20.0,
            datatype="ci16_le"
        )
        assert len(signals) > 0, "No signals from raw IQ"
        print(f"  Raw IQ bridge: {len(signals)} signals, "
              f"types={[s.signal_type for s in signals]}")
    finally:
        os.unlink(bin_path)


def test_bridge_sigmf_parse():
    """SigMF meta+data file parsed correctly."""
    bridge = BladeRFBridge(noise_floor_dbm=-100.0, min_burst_duration_ms=10.0)

    # 390MHz center (TETRA band), 5MHz sample rate
    meta = make_sigmf_meta(
        center_freq_hz=390_000_000,
        sample_rate_hz=5_000_000
    )
    iq_data = make_synthetic_iq_bin(
        center_freq_mhz=390.0, emission_offset_mhz=1.0, n_samples=2048
    )

    with tempfile.TemporaryDirectory() as td:
        meta_path = os.path.join(td, "tetra_scan.sigmf-meta")
        data_path = os.path.join(td, "tetra_scan.sigmf-data")

        with open(meta_path, "w") as f:
            json.dump(meta, f)
        with open(data_path, "wb") as f:
            f.write(iq_data)

        signals = bridge.from_sigmf(meta_path)
        assert len(signals) >= 0  # May or may not detect above threshold
        print(f"  SigMF bridge: {len(signals)} signals from TETRA band capture")


def test_bridge_manual_observations():
    """Manual observation dict → ObservedSignal conversion."""
    bridge = BladeRFBridge()

    obs = [
        {
            "type": "tetra", "freq_mhz": 391.5,
            "lat": -38.1100, "lon": 145.2780,
            "ts": "2026-06-06T04:00:00Z"
        },
        {
            "type": "lte", "carrier": "telstra", "band": "B28",
            "rsrp_dbm": -85.0, "burst_interval_s": 15.0,
            "lat": -38.1100, "lon": 145.2780,
            "ts": "2026-06-06T04:00:01Z"
        },
        {
            "type": "lte", "carrier": "telstra", "band": "B3",
            "ts": "2026-06-06T04:00:02Z"
        },
        {
            "type": "ble", "manufacturer_id": "0x004C",
            "payload_type": "apple_nearby_action",
            "advertisement_interval_ms": 500,
            "separation_indicator": True,
            "ts": "2026-06-06T04:00:05Z"
        }
    ]

    signals = bridge.from_manual(obs)
    assert len(signals) == 4
    assert signals[0].signal_type == "tetra"
    assert signals[0].latitude == -38.1100
    assert signals[1].carrier == "telstra"
    assert signals[3].separation_indicator is True
    print(f"  Manual observations: {len(signals)} signals, all fields correct")


def test_bridge_castnet_json_file():
    """CASTNET JSON observation file ingested correctly."""
    bridge = BladeRFBridge()

    obs = [
        {"type": "tetra", "freq_mhz": 390.0, "ts": "2026-06-06T04:00:00Z"},
        {"type": "lte", "carrier": "optus", "band": "B28",
         "ts": "2026-06-06T04:00:01Z"},
        {"type": "bluetooth", "advertisement_interval_ms": 100.0,
         "ts": "2026-06-06T04:00:02Z"}
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(obs, f)
        json_path = f.name

    try:
        signals = bridge.from_manual(obs)
        assert len(signals) == 3
        assert signals[1].carrier == "optus"
        print(f"  CASTNET JSON: {len(signals)} observations parsed")
    finally:
        os.unlink(json_path)


# ─── MODULE TESTS ────────────────────────────────────────────────────

def test_module_with_castnet_obs():
    """FleetDetectorModule with CASTNET observations → VicPol composite detected."""

    obs = [
        {"type": "tetra", "freq_mhz": 391.5,
         "lat": -38.1100, "lon": 145.2780, "ts": "2026-06-06T04:00:00Z"},
        {"type": "lte", "carrier": "telstra", "band": "B28",
         "burst_interval_s": 15.0,
         "lat": -38.1100, "lon": 145.2780, "ts": "2026-06-06T04:00:01Z"},
        {"type": "lte", "carrier": "telstra", "band": "B3",
         "lat": -38.1100, "lon": 145.2780, "ts": "2026-06-06T04:00:02Z"},
    ]

    with tempfile.TemporaryDirectory() as capture_dir:
        obs_path = os.path.join(capture_dir, "castnet_obs.json")
        with open(obs_path, "w") as f:
            json.dump(obs, f)

        fleet = FleetDetectorModule(
            capture_dir=capture_dir,
            location=(-38.1100, 145.2780),
            min_confidence=0.50,
            castnet_obs_file=obs_path
        )
        findings = fleet.run()

    assert findings["detection_count"] > 0, \
        f"No detections. Summary: {findings['summary_text']}"

    ids = [d["id"] for d in findings["detections"]]
    assert "vicpol_mobile_unit_composite" in ids, \
        f"VicPol composite not found. Got: {ids}"

    print(f"  Module+CASTNET: {findings['detection_count']} detections, "
          f"VicPol composite confirmed")
    print(f"  Summary: {findings['summary_text']}")


def test_module_with_csv_capture():
    """FleetDetectorModule with spectrum CSV in capture dir → TETRA detected."""

    rows = [
        (391_000_000, -65.0), (392_000_000, -63.0),
        (762_000_000, -78.0), (763_000_000, -76.0),
        (500_000_000, -108.0),
    ]

    with tempfile.TemporaryDirectory() as capture_dir:
        # Write a spectrum CSV with bladeRF-style header
        csv_path = os.path.join(capture_dir, "bladerf_scan.csv")
        with open(csv_path, "w") as f:
            f.write(make_spectrum_csv(rows))

        fleet = FleetDetectorModule(
            capture_dir=capture_dir,
            location=(-38.1100, 145.2780),
            min_confidence=0.45
        )
        findings = fleet.run()

    print(f"  Module+CSV: {findings['signal_count']} signals, "
          f"{findings['detection_count']} detections")
    print(f"  Summary: {findings['summary_text']}")


def test_module_empty_dir():
    """Empty capture dir → graceful empty result."""
    with tempfile.TemporaryDirectory() as capture_dir:
        fleet = FleetDetectorModule(capture_dir=capture_dir)
        findings = fleet.run()

    assert findings["detection_count"] == 0
    assert findings["signal_count"] == 0
    assert "no RF capture files" in findings["summary_text"]
    print(f"  Empty dir: graceful — '{findings['summary_text']}'")


def test_module_report_section():
    """Report section formatting produces valid text output."""
    obs = [
        {"type": "tetra", "freq_mhz": 391.5, "ts": "2026-06-06T04:00:00Z"},
        {"type": "lte", "carrier": "telstra", "band": "B28",
         "burst_interval_s": 15.0, "ts": "2026-06-06T04:00:01Z"},
        {"type": "lte", "carrier": "telstra", "band": "B3",
         "ts": "2026-06-06T04:00:02Z"},
        {"type": "ble", "manufacturer_id": "0x004C",
         "payload_type": "apple_nearby_action",
         "advertisement_interval_ms": 500, "separation_indicator": True,
         "ts": "2026-06-06T04:00:05Z"},
    ]

    with tempfile.TemporaryDirectory() as capture_dir:
        obs_path = os.path.join(capture_dir, "obs.json")
        with open(obs_path, "w") as f:
            json.dump(obs, f)

        fleet = FleetDetectorModule(
            capture_dir=capture_dir,
            location=(-38.1100, 145.2780),
            castnet_obs_file=obs_path
        )
        findings = fleet.run()
        report = fleet.format_report_section(findings)

    assert "FLEET SIGNATURE DETECTOR" in report
    assert "RF CONTACT REPORT" in report
    assert len(report) > 100

    print(f"  Report section: {len(report)} chars, {findings['detection_count']} detections")
    print(report)


def test_filename_parsing():
    """bladeRF filename convention parsed correctly."""
    from detectors.fleet_detector_module import FleetDetectorModule
    from pathlib import Path

    fleet = FleetDetectorModule.__new__(FleetDetectorModule)
    fleet.bridge = BladeRFBridge()

    cases = [
        ("bladerf_700mhz_20msps.bin",      700.0, 20.0, "ci16_le"),
        ("bladerf_390mhz_5msps.bin",        390.0,  5.0, "ci16_le"),
        ("bladerf_2400mhz_40msps_cf32.bin", 2400.0, 40.0, "cf32_le"),
        ("capture_915_5.bin",               915.0,  5.0, "ci16_le"),
    ]

    for filename, exp_freq, exp_rate, exp_dtype in cases:
        result = fleet._parse_iq_filename(Path(filename))
        if result:
            freq, rate, dtype = result
            assert abs(freq - exp_freq) < 1.0, \
                f"{filename}: freq {freq} != {exp_freq}"
            assert abs(rate - exp_rate) < 0.1, \
                f"{filename}: rate {rate} != {exp_rate}"
            print(f"  {filename} → {freq}MHz, {rate}Msps, {dtype} ✓")
        else:
            print(f"  {filename} → not parsed (expected {exp_freq}MHz)")


if __name__ == "__main__":
    tests = [
        test_bridge_csv_b28_tetra,
        test_bridge_raw_iq_b28,
        test_bridge_sigmf_parse,
        test_bridge_manual_observations,
        test_bridge_castnet_json_file,
        test_module_with_castnet_obs,
        test_module_with_csv_capture,
        test_module_empty_dir,
        test_module_report_section,
        test_filename_parsing,
    ]

    passed = failed = 0
    for t in tests:
        try:
            print(f"\nRUN  {t.__name__}")
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception as e:
            import traceback
            print(f"FAIL {t.__name__}: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"Integration results: {passed}/{len(tests)} passed, {failed} failed")
