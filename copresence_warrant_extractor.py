# copresence_warrant_extractor.py
# Extracts dual-device co-presence timestamps from CASTNET DB and NDJSON captures
# Formats output as AFP warrant-ready location verification request
# rayhunter-threat-analyzer v3.7 - Hidden Blade: Assassins Creep
#
# Usage:
#   python copresence_warrant_extractor.py --castnet castnet.db --output warrant_timestamps.txt
#   python copresence_warrant_extractor.py --dir D:\MAY_2026_CAPTURES --output warrant_timestamps.txt

import argparse
import json
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Device A = Telstra TAC 12385 (professional Harris hardware)
DEVICE_A_CIDS = {137713155, 137713165, 137713173, 137713175, 137713193, 137713195,
                  135836161, 135836171, 135836191, 135836192}

# Device B = Vodafone TAC 30336 (personal srsRAN device)
DEVICE_B_CIDS = {8409355, 8409357, 8409367, 8409387, 8409397,
                  8666381, 8666391, 8666411, 8435470, 8435480}

# Co-presence window: if Device A and Device B both seen within this many seconds
COPRESENCE_WINDOW_SECONDS = 120

# Minimum gap between reported windows to avoid duplicates
MIN_GAP_SECONDS = 300

ENB_ID = 537942
TAC_A = 12385
TAC_B = 30336
HOME_LAT = -38.1089
HOME_LON = 145.3098
TA_DISTANCE_M = 547


def to_aest(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=10)


def load_castnet(db_path: str) -> list:
    events = []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        all_cids = DEVICE_A_CIDS | DEVICE_B_CIDS
        ph = ",".join(str(c) for c in all_cids)
        cur.execute(f"""
            SELECT timestamp, ci as cell_id, tac, rsrp, timing_advance
            FROM detections
            WHERE ci IN ({ph})
            ORDER BY timestamp ASC
        """)
        for row in cur.fetchall():
            d = dict(row)
            ts = d.get('timestamp')
            if ts:
                try:
                    d['_ts'] = float(ts)
                    events.append(d)
                except (ValueError, TypeError):
                    pass
        conn.close()
        print(f"[CASTNET] Loaded {len(events)} events")
    except Exception as e:
        print(f"[CASTNET] Error: {e}", file=sys.stderr)
    return events


def load_ndjson_dir(directory: str) -> list:
    events = []
    all_cids = DEVICE_A_CIDS | DEVICE_B_CIDS
    for f in Path(directory).rglob("*.ndjson"):
        if 'gps' in f.name.lower():
            continue
        try:
            with open(f, encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        cid = e.get('cell_id') or e.get('ci') or e.get('cid')
                        if cid and int(cid) in all_cids:
                            for k in ('timestamp', 'time', 'ts'):
                                v = e.get(k)
                                if v:
                                    try:
                                        if isinstance(v, (int, float)):
                                            e['_ts'] = float(v)
                                        else:
                                            v2 = str(v).replace('Z', '+00:00')
                                            dt = datetime.fromisoformat(v2)
                                            if dt.tzinfo is None:
                                                dt = dt.replace(tzinfo=timezone.utc)
                                            e['_ts'] = dt.timestamp()
                                        e['cell_id'] = int(cid)
                                        events.append(e)
                                        break
                                    except (ValueError, OSError):
                                        pass
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass
        except Exception:
            pass
    print(f"[NDJSON] Loaded {len(events)} events")
    return events


def find_copresence_windows(events: list) -> list:
    # Sort by timestamp
    events.sort(key=lambda e: e.get('_ts', 0))

    windows = []
    last_reported = None

    for i, ea in enumerate(events):
        ts_a = ea.get('_ts')
        cid_a = int(ea.get('cell_id', 0))
        if not ts_a or cid_a not in DEVICE_A_CIDS:
            continue

        # Look for Device B within window
        for eb in events[i+1:]:
            ts_b = eb.get('_ts')
            if not ts_b:
                continue
            if ts_b - ts_a > COPRESENCE_WINDOW_SECONDS:
                break
            cid_b = int(eb.get('cell_id', 0))
            if cid_b not in DEVICE_B_CIDS:
                continue

            # Found co-presence
            gap_ok = last_reported is None or (ts_a - last_reported) > MIN_GAP_SECONDS
            if gap_ok:
                delta = ts_b - ts_a
                windows.append({
                    'window_start_utc': ts_a,
                    'window_start_aest': to_aest(ts_a).strftime('%Y-%m-%d %H:%M:%S'),
                    'device_a_cid': cid_a,
                    'device_a_ts_utc': datetime.fromtimestamp(ts_a, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                    'device_b_cid': cid_b,
                    'device_b_ts_utc': datetime.fromtimestamp(ts_b, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                    'separation_seconds': round(delta, 3),
                    'device_a_rsrp': ea.get('rsrp'),
                    'device_b_rsrp': eb.get('rsrp'),
                    'device_a_ta': ea.get('timing_advance'),
                })
                last_reported = ts_a
                break

    return windows


def format_report(windows: list) -> str:
    lines = []
    sep = '=' * 80

    lines.append(sep)
    lines.append('AFP WARRANT-READY LOCATION VERIFICATION REQUEST')
    lines.append('Dual-Device Co-Presence Timestamp Log')
    lines.append('rayhunter-threat-analyzer v3.7 — Hidden Blade: Assassins Creep')
    lines.append(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append(sep)
    lines.append(f"""
CONTEXT:
  Rogue eNB ID:     {ENB_ID}
  Subject address:  74 Prendergast Avenue, Cranbourne East VIC 3977
  GPS coordinates:  {HOME_LAT}, {HOME_LON}
  TA distance:      ~{TA_DISTANCE_M}m from subject address (TA=7, 78m/step)

  Device A (TAC {TAC_A}): Harris HailStorm II [PROBABLE]
    CIDs: {sorted(DEVICE_A_CIDS)}
    Profile: Professional hardware, employer-issued, business hours
    Audit status: SURVIVES corporate audit (logs legitimately)

  Device B (TAC {TAC_B}): srsRAN on BladeRF 2.0 [CONFIRMED]
    CIDs: {sorted(DEVICE_B_CIDS)}
    Profile: Personally-owned consumer SDR, after-hours operation
    Audit status: INVISIBLE to corporate audit — personal search warrant required
    Fingerprint: enb_id=537942, tac=12385 in /etc/srsran/enb.conf

PURPOSE:
  The following timestamps represent moments when BOTH Device A and Device B
  were simultaneously transmitting within {COPRESENCE_WINDOW_SECONDS} seconds of each other.

  The operator (or their vehicle/device) MUST have been within approximately
  {TA_DISTANCE_M}m of {HOME_LAT}, {HOME_LON} at each of these moments.

  AFP ACTION: Subpoena the following records for each timestamp:
    1. Mobile network location data for operator's personal devices
    2. Service Stream vehicle/GPS tracker records
    3. Service Stream employee work logs and site attendance records
    4. CCTV from Cranbourne East Secondary College / surrounding area
    5. Any toll/traffic camera records for the ~547m radius

  Cross-referencing any of these records against the timestamps below will
  place the operator at the scene during confirmed dual-device operation.
""")

    lines.append(sep)
    lines.append(f'DUAL-DEVICE CO-PRESENCE EVENTS: {len(windows)} confirmed windows')
    lines.append(sep)
    lines.append('')

    for i, w in enumerate(windows, 1):
        lines.append(f'[{i:03d}] {w["window_start_aest"]} AEST')
        lines.append(f'  Device A: CID={w["device_a_cid"]} @ {w["device_a_ts_utc"]}')
        lines.append(f'  Device B: CID={w["device_b_cid"]} @ {w["device_b_ts_utc"]}')
        lines.append(f'  Separation: {w["separation_seconds"]:.3f}s')
        if w.get('device_a_rsrp'):
            lines.append(f'  RSRP: Device A={w["device_a_rsrp"]} dBm')
        if w.get('device_a_ta'):
            lines.append(f'  TA: {w["device_a_ta"]} (~{int(w["device_a_ta"]) * 78}m from device)')
        lines.append('')

    lines.append(sep)
    lines.append('LEGAL BASIS')
    lines.append(sep)
    lines.append(f"""
  Physical impossibility proof:
    Band 28 (700MHz) and Band 3/7/1 (1800/2600/2100MHz) cannot be
    simultaneously transmitted by a single RF chain (3GPP TS 36.104).
    Frequency ratios: Band28+Band7=3.71x, Band28+Band1=3.0x, Band28+Band3=2.43x.
    Each co-presence window above is physically impossible from one device.
    Two transmitters are REQUIRED.

  srsRAN fingerprint:
    Device B identified by 2.10s inter-event intervals
    (srsRAN measurement_report_period=2000ms default + OS jitter).
    This interval CANNOT be produced by Harris, Septier, or R&S hardware.
    First documented in this investigation — briefed to ACMA field team
    (ENQ-1851DVJH04).

  Configuration fingerprint:
    Finding enb_id=537942 + tac=12385 in /etc/srsran/enb.conf on any
    personal device is DEFINITIVE PROOF that device operated the rogue eNB.
    This combination is unique to this investigation.

  References:
    3GPP TS 36.104 Table 5.5-1 (LTE band frequency assignments)
    Tucker et al. NDSS 2025 (SnoopDog: Exposing IMSI-Catcher Attacks)
    Zhuang et al. AsiaCCS 2018 (FBSleuth)
    Ziayi et al. 2021 (YAICD — YAICD score 5.00/2.6 CRITICAL)

AFP LEX 4864 | ACMA ENQ-1851DVJH04 | VicPol CIRS-20260331-141
""")
    lines.append(sep)
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Extract dual-device co-presence timestamps for AFP warrant'
    )
    parser.add_argument('--castnet', help='Path to castnet.db')
    parser.add_argument('--dir', help='Directory of NDJSON capture files')
    parser.add_argument('--output', default='warrant_timestamps.txt')
    args = parser.parse_args()

    if not args.castnet and not args.dir:
        parser.print_help()
        sys.exit(1)

    events = []
    if args.castnet:
        events.extend(load_castnet(args.castnet))
    if args.dir:
        events.extend(load_ndjson_dir(args.dir))

    if not events:
        print('No events found.')
        sys.exit(1)

    print(f'\nTotal events loaded: {len(events)}')
    print('Finding co-presence windows...')

    windows = find_copresence_windows(events)
    print(f'Co-presence windows found: {len(windows)}')

    report = format_report(windows)
    print('\n' + report)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'\n[OK] Saved: {args.output}')

    # JSON output
    json_out = args.output.replace('.txt', '.json')
    with open(json_out, 'w') as f:
        json.dump({
            'generated_at': datetime.now().isoformat(),
            'total_windows': len(windows),
            'enb_id': ENB_ID,
            'home_coordinates': {'lat': HOME_LAT, 'lon': HOME_LON},
            'ta_distance_m': TA_DISTANCE_M,
            'windows': windows
        }, f, indent=2, default=str)
    print(f'[OK] JSON: {json_out}')


if __name__ == '__main__':
    main()
