"""
main_fleet_patch.py
Patch to add to your existing main.py — adds FleetDetectorModule to the pipeline.

INSTRUCTIONS:
1. Copy bladerf_bridge.py and fleet_detector_module.py into your detectors\ folder
2. Add the import block below to the top of your main.py
3. Add the run block below to your main analysis function, after existing detectors run
4. Done — fleet findings appear in every scan report automatically

─────────────────────────────────────────────────────────────────
STEP 1 — Add to imports at top of main.py:
─────────────────────────────────────────────────────────────────

    from detectors.fleet_detector_module import FleetDetectorModule

─────────────────────────────────────────────────────────────────
STEP 2 — Add to your main analysis function, after existing detectors:
─────────────────────────────────────────────────────────────────

    # ── Fleet Signature Detector ──────────────────────────────────
    fleet = FleetDetectorModule(
        capture_dir=args.dir,
        location=_get_location(args),       # None if no GPS
        min_confidence=0.50,
        castnet_obs_file=args.castnet_obs   # None if not provided
    )
    fleet_findings = fleet.run()
    fleet_report = fleet.format_report_section(fleet_findings)

    # Append to existing report output
    print(fleet_report)

    # Also write to JSON findings (if your pipeline does this)
    if hasattr(args, 'output_json') and args.output_json:
        with open(args.output_json, 'a') as f:
            json.dump({"fleet_detections": fleet_findings}, f, indent=2)

─────────────────────────────────────────────────────────────────
STEP 3 — Add --castnet-obs argument to your argparse block:
─────────────────────────────────────────────────────────────────

    parser.add_argument(
        '--castnet-obs',
        default=None,
        help='Path to CASTNET node observations JSON file'
    )
    parser.add_argument(
        '--gps-lat', type=float, default=None,
        help='GPS latitude for location-stamped detections'
    )
    parser.add_argument(
        '--gps-lon', type=float, default=None,
        help='GPS longitude for location-stamped detections'
    )

─────────────────────────────────────────────────────────────────
STEP 4 — Add this helper function to main.py:
─────────────────────────────────────────────────────────────────

    def _get_location(args):
        if hasattr(args, 'gps_lat') and args.gps_lat and args.gps_lon:
            return (args.gps_lat, args.gps_lon)
        return None

─────────────────────────────────────────────────────────────────
EXAMPLE COMMAND LINES after patching:
─────────────────────────────────────────────────────────────────

    # Standard corpus scan — fleet detector runs automatically on any
    # bladeRF captures found in the capture dir
    python main.py --dir D:\\MAY_2026_CAPTURES

    # With GPS location (Cranbourne East)
    python main.py --dir D:\\MAY_2026_CAPTURES ^
        --gps-lat -38.1100 --gps-lon 145.2780

    # With CASTNET node observations from Android
    python main.py --dir D:\\MAY_2026_CAPTURES ^
        --castnet-obs C:\\CASTNET\\observations.json ^
        --gps-lat -38.1100 --gps-lon 145.2780

─────────────────────────────────────────────────────────────────
BLADERF CAPTURE NAMING CONVENTION:
─────────────────────────────────────────────────────────────────

Name your bladeRF capture files so the bridge can auto-parse parameters:

    bladerf_{freq_mhz}mhz_{rate_msps}msps.bin

Examples:
    bladerf_700mhz_20msps.bin       ← B28 LTE scan
    bladerf_390mhz_5msps.bin        ← GRN TETRA scan
    bladerf_2400mhz_40msps.bin      ← BLE/WiFi 2.4GHz scan
    bladerf_5800mhz_40msps.bin      ← OcuSync3/WiFi 5.8GHz scan
    bladerf_915mhz_5msps.bin        ← ISM 915MHz (smart meters)

Or SigMF (preferred — carries metadata automatically):
    bladeRF-cli -e "rx config frequency=700000000 bandwidth=20000000 \\
                    n=4000000 format=sigmf file=b28_scan"
    → produces b28_scan.sigmf-meta + b28_scan.sigmf-data

─────────────────────────────────────────────────────────────────
CASTNET OBSERVATION JSON FORMAT (from Android node):
─────────────────────────────────────────────────────────────────

[
  {
    "type": "ble",
    "manufacturer_id": "0x004C",
    "advertisement_interval_ms": 500,
    "separation_indicator": true,
    "payload_type": "apple_nearby_action",
    "lat": -38.1100,
    "lon": 145.2780,
    "ts": "2026-06-06T04:30:00Z"
  },
  {
    "type": "tetra",
    "freq_mhz": 391.5,
    "lat": -38.1100,
    "lon": 145.2780,
    "ts": "2026-06-06T04:31:00Z"
  },
  {
    "type": "lte",
    "carrier": "telstra",
    "band": "B28",
    "rsrp_dbm": -85.0,
    "burst_interval_s": 15.0,
    "lat": -38.1100,
    "lon": 145.2780,
    "ts": "2026-06-06T04:31:02Z"
  }
]
"""

# ─────────────────────────────────────────────────────────────────────
# STANDALONE TEST — run this file directly to verify integration works
# python detectors\main_fleet_patch.py --dir D:\your\capture\dir
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    import os

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    from detectors.fleet_detector_module import FleetDetectorModule

    parser = argparse.ArgumentParser(
        description="FleetDetectorModule standalone test"
    )
    parser.add_argument(
        "--dir", required=True,
        help="Capture directory (same as main.py --dir)"
    )
    parser.add_argument("--castnet-obs", default=None)
    parser.add_argument("--gps-lat", type=float, default=-38.1100)
    parser.add_argument("--gps-lon", type=float, default=145.2780)
    parser.add_argument("--min-confidence", type=float, default=0.50)
    args = parser.parse_args()

    location = (args.gps_lat, args.gps_lon) if args.gps_lat else None

    fleet = FleetDetectorModule(
        capture_dir=args.dir,
        location=location,
        min_confidence=args.min_confidence,
        castnet_obs_file=args.castnet_obs
    )

    findings = fleet.run()
    report = fleet.format_report_section(findings)
    print(report)

    print(f"\nSummary: {findings['summary_text']}")
    print(f"Forensic flags: {len(findings['forensic_flags'])}")

    if findings["forensic_flags"]:
        print("\nFORENSIC FLAGS:")
        for flag in findings["forensic_flags"]:
            print(f"  [{flag['confidence']:.0%}] {flag['label']}")
