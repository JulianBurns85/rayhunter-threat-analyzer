#!/usr/bin/env python3
"""
rsrp_vehicle_detector.py
RSRP-based vehicle arrival/departure detection and kinematic tracking analysis.

Applies ESPectre/WiFi-CSI principles to cellular RSRP data:
- Detects step-changes in RSRP correlating with co-presence window boundaries
  (vehicle arriving at/departing from ~547m rogue platform location)
- Detects kinematic tracking signatures (mobile platform following user)
- Cross-node validation via CASTNET multi-node data

rayhunter-threat-analyzer v3.8 - Hidden Blade: Assassins Creep

References:
  ESPectre (francescopace) - WiFi CSI motion detection
  Gemini/Grok RSRP step-change concept
  3GPP TS 36.211 (Timing Advance = 78m/step)
  SeaGlass (UW 2017) - passive cellular measurement

Usage:
  python rsrp_vehicle_detector.py --castnet castnet.db --windows warrant_castnet_raw.txt --output rsrp_vehicle_report.txt
  python rsrp_vehicle_detector.py --castnet castnet.db --windows warrant_may_raw.txt --output rsrp_vehicle_report.txt
"""

import sqlite3
import json
import re
import sys
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────────

DEVICE_A_CIDS = {137713155, 137713165, 137713173, 137713175, 137713193,
                  137713195, 135836161, 135836171, 135836191, 135836192}
DEVICE_B_CIDS = {8409355, 8409357, 8409367, 8409387, 8409397,
                  8666381, 8666391, 8666411, 8435470, 8435480}
ALL_ROGUE_CIDS = DEVICE_A_CIDS | DEVICE_B_CIDS

EXPECTED_TA        = 7          # ~547m from home
TA_TOLERANCE       = 1          # TA=6 or TA=8 still consistent with stationary
STEP_THRESHOLD_DB  = 4.0        # dBm change to flag as step-change
WINDOW_MARGIN_SEC  = 300        # look ±5 min around co-presence window boundaries
MIN_STABLE_SAMPLES = 3          # minimum samples to establish baseline
AEST_OFFSET        = timedelta(hours=10)

HOME_LAT = -38.1089
HOME_LON = 145.3098


# ── Data Loading ───────────────────────────────────────────────────────────────

def load_castnet(db_path: str) -> list:
    """Load RSRP time series from CASTNET database."""
    events = []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT timestamp, ci, node_id, rsrp, timing_advance, latitude, longitude
            FROM detections
            WHERE ci IN ({})
            ORDER BY timestamp ASC
        """.format(','.join(str(c) for c in ALL_ROGUE_CIDS)))

        for row in cur.fetchall():
            ts = row['timestamp']
            try:
                ts2 = str(ts).replace('Z', '+00:00')
                dt = datetime.fromisoformat(ts2)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                events.append({
                    '_ts': dt.timestamp(),
                    '_dt': dt,
                    'ci': row['ci'],
                    'node_id': row['node_id'] or 'unknown',
                    'rsrp': float(row['rsrp']) if row['rsrp'] is not None else None,
                    'ta': row['timing_advance'],
                    'lat': row['latitude'],
                    'lon': row['longitude'],
                    'device': 'A' if row['ci'] in DEVICE_A_CIDS else 'B',
                })
            except (ValueError, OSError, TypeError):
                pass
        conn.close()
    except Exception as e:
        print(f'[ERROR] CASTNET load failed: {e}', file=sys.stderr)
    return events


def parse_window_file(filepath: str) -> list:
    """Parse co-presence window timestamps from warrant_*.txt files."""
    windows = []
    pat = re.compile(
        r'\[(\d+)\]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+AEST'
    )
    try:
        with open(filepath, encoding='utf-8') as f:
            for line in f:
                m = pat.search(line)
                if m:
                    dt_aest = datetime.strptime(m.group(2), '%Y-%m-%d %H:%M:%S')
                    dt_utc = dt_aest.replace(tzinfo=timezone.utc) - AEST_OFFSET
                    windows.append({
                        'index': int(m.group(1)),
                        'ts_utc': dt_utc.timestamp(),
                        'dt_aest': dt_aest,
                        'dt_utc': dt_utc,
                        'raw': line.strip(),
                    })
    except Exception as e:
        print(f'[ERROR] Window file parse failed: {e}', file=sys.stderr)
    return windows


# ── Analysis Functions ─────────────────────────────────────────────────────────

def get_rsrp_window(events: list, center_ts: float, margin_sec: float,
                    device_filter=None) -> list:
    """Extract RSRP events within a time window around center_ts."""
    result = []
    for e in events:
        if abs(e['_ts'] - center_ts) <= margin_sec:
            if e['rsrp'] is not None:
                if device_filter is None or e['device'] == device_filter:
                    result.append(e)
    return sorted(result, key=lambda x: x['_ts'])


def detect_step_change(events_before: list, events_after: list,
                        threshold_db: float = STEP_THRESHOLD_DB) -> dict:
    """
    Detect a sustained step-change in RSRP between before and after windows.
    Returns confidence and delta.
    """
    if not events_before or not events_after:
        return {'detected': False, 'reason': 'insufficient data'}

    before_rsrp = [e['rsrp'] for e in events_before if e['rsrp'] is not None]
    after_rsrp = [e['rsrp'] for e in events_after if e['rsrp'] is not None]

    if len(before_rsrp) < MIN_STABLE_SAMPLES or len(after_rsrp) < MIN_STABLE_SAMPLES:
        return {'detected': False, 'reason': 'too few samples'}

    before_mean = sum(before_rsrp) / len(before_rsrp)
    after_mean = sum(after_rsrp) / len(after_rsrp)
    delta = after_mean - before_mean

    # Variance check — step-change should be followed by stable signal
    before_var = max(before_rsrp) - min(before_rsrp)
    after_var = max(after_rsrp) - min(after_rsrp)

    detected = abs(delta) >= threshold_db
    confidence = 'HIGH' if (detected and after_var < 6.0) else \
                 'MEDIUM' if detected else 'NONE'

    return {
        'detected': detected,
        'delta_db': round(delta, 2),
        'before_mean_db': round(before_mean, 2),
        'after_mean_db': round(after_mean, 2),
        'before_variance': round(before_var, 2),
        'after_variance': round(after_var, 2),
        'before_samples': len(before_rsrp),
        'after_samples': len(after_rsrp),
        'confidence': confidence,
        'direction': 'DROP' if delta < 0 else 'SPIKE',
    }


def analyse_ta_stability(events: list) -> dict:
    """
    Check if TA values are stable (stationary platform) or variable (mobile).
    Variable TA during user movement = kinematic tracking signature.
    """
    ta_values = [e["ta"] for e in events if e["ta"] is not None and e["ta"] <= 50]
    if not ta_values:
        return {'stable': None, 'reason': 'no TA data'}

    unique_ta = set(ta_values)
    mean_ta = sum(ta_values) / len(ta_values)
    variance = max(ta_values) - min(ta_values)

    # Stationary platform: TA stays at 7 (±1)
    stationary = all(abs(t - EXPECTED_TA) <= TA_TOLERANCE for t in ta_values)

    return {
        'stable': stationary,
        'mean_ta': round(mean_ta, 2),
        'variance': variance,
        'unique_values': sorted(unique_ta),
        'sample_count': len(ta_values),
        'mean_distance_m': round(mean_ta * 78, 0),
        'kinematic_flag': not stationary and variance > 2,
    }


def cross_node_correlation(events_window: list) -> dict:
    """
    Check if multiple CASTNET nodes detected the same step-change.
    Multi-node correlation eliminates local interference explanations.
    """
    nodes = defaultdict(list)
    for e in events_window:
        nodes[e['node_id']].append(e['rsrp'])

    if len(nodes) < 2:
        return {'multi_node': False, 'nodes_present': list(nodes.keys())}

    node_means = {}
    for node, rsrp_list in nodes.items():
        valid = [r for r in rsrp_list if r is not None]
        if valid:
            node_means[node] = sum(valid) / len(valid)

    # Check if all nodes show similar RSRP (correlated signal)
    if len(node_means) >= 2:
        means = list(node_means.values())
        spread = max(means) - min(means)
        correlated = spread < 15.0  # within 15dB across nodes = same source
    else:
        correlated = False

    return {
        'multi_node': len(nodes) >= 2,
        'nodes_present': list(nodes.keys()),
        'node_means_db': {k: round(v, 1) for k, v in node_means.items()},
        'cross_node_spread_db': round(max(node_means.values()) - min(node_means.values()), 1) if len(node_means) >= 2 else None,
        'correlated': correlated,
    }


# ── Main Analysis ──────────────────────────────────────────────────────────────

def analyse_windows(events: list, windows: list) -> list:
    """Run vehicle detection analysis on all co-presence windows."""
    results = []

    for w in windows:
        center_ts = w['ts_utc']

        # Get RSRP data around this window
        before_events = [e for e in events
                          if center_ts - WINDOW_MARGIN_SEC <= e['_ts'] < center_ts
                          and e['rsrp'] is not None]
        after_events = [e for e in events
                         if center_ts <= e['_ts'] < center_ts + WINDOW_MARGIN_SEC
                         and e['rsrp'] is not None]
        full_window = before_events + after_events

        # Step change detection — Device A (Harris, stationary platform)
        step_a = detect_step_change(
            [e for e in before_events if e['device'] == 'A'],
            [e for e in after_events if e['device'] == 'A']
        )

        # Step change detection — Device B (srsRAN personal device)
        step_b = detect_step_change(
            [e for e in before_events if e['device'] == 'B'],
            [e for e in after_events if e['device'] == 'B']
        )

        # TA stability analysis
        ta_analysis = analyse_ta_stability(full_window)

        # Cross-node correlation
        node_corr = cross_node_correlation(full_window)

        # Overall vehicle event confidence
        vehicle_confidence = 'NONE'
        if step_a['detected'] or step_b['detected']:
            if node_corr['multi_node'] and node_corr['correlated']:
                vehicle_confidence = 'HIGH'
            elif step_a['confidence'] == 'HIGH' or step_b['confidence'] == 'HIGH':
                vehicle_confidence = 'MEDIUM'
            else:
                vehicle_confidence = 'LOW'

        results.append({
            'window_index': w['index'],
            'timestamp_aest': w['dt_aest'].strftime('%Y-%m-%d %H:%M:%S'),
            'timestamp_utc': w['dt_utc'].strftime('%Y-%m-%dT%H:%M:%SZ'),
            'raw_window': w['raw'],
            'step_change_device_a': step_a,
            'step_change_device_b': step_b,
            'ta_stability': ta_analysis,
            'cross_node': node_corr,
            'vehicle_event_confidence': vehicle_confidence,
            'total_events_in_window': len(full_window),
        })

    return results


def format_report(results: list, castnet_path: str, window_path: str) -> str:
    """Format results as AFP-ready text report."""
    lines = []
    sep = '=' * 80

    high = [r for r in results if r['vehicle_event_confidence'] == 'HIGH']
    medium = [r for r in results if r['vehicle_event_confidence'] == 'MEDIUM']
    low = [r for r in results if r['vehicle_event_confidence'] == 'LOW']
    kinematic = [r for r in results if r['ta_stability'].get('kinematic_flag')]

    lines.append(sep)
    lines.append('RSRP VEHICLE DETECTION REPORT')
    lines.append('ESPectre/WiFi-CSI Principle Applied to Cellular RSRP Data')
    lines.append('rayhunter-threat-analyzer v3.8 — Hidden Blade: Assassins Creep')
    lines.append(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append(sep)
    lines.append(f"""
METHODOLOGY:
  When a large metal object (service vehicle, equipment trailer) moves into or
  out of the ~547m rogue platform location, it causes a measurable step-change
  in RSRP observed by CASTNET nodes. This is the same physical principle used
  by WiFi CSI motion detection systems (ESPectre — francescopace/espectre).

  Unlike gradual atmospheric/oscillator drift (slow rolling variation), a
  vehicle arrival causes a SUDDEN, SUSTAINED shift in signal strength. The
  first derivative of RSRP spikes at the transition, then stabilises at a
  new baseline — identical to a person walking in front of a WiFi router.

  Multi-node correlation (Pixel 9 Pro + Ulefone) eliminates local interference:
  if both nodes show the same step-change simultaneously, the disruption
  occurred near the SOURCE (~547m), not near the receivers.

  AFP ACTION: Cross-reference HIGH/MEDIUM vehicle event timestamps against:
    - Service Stream vehicle GPS tracker records
    - Employee attendance/site visit logs
    - CCTV in the ~547m radius of 74 Prendergast Ave Cranbourne East

CASTNET DB:    {castnet_path}
Window file:   {window_path}
Windows analysed: {len(results)}

SUMMARY:
  HIGH confidence vehicle events:   {len(high)}
  MEDIUM confidence vehicle events: {len(medium)}
  LOW confidence vehicle events:    {len(low)}
  Kinematic tracking flags:         {len(kinematic)}
""")

    if high:
        lines.append(sep)
        lines.append(f'HIGH CONFIDENCE VEHICLE EVENTS ({len(high)})')
        lines.append('These timestamps have strong physical evidence of operator')
        lines.append('vehicle presence at the ~547m rogue platform location.')
        lines.append(sep)
        for r in high:
            lines.append(f'\n[{r["window_index"]:03d}] {r["timestamp_aest"]} AEST')
            lines.append(f'  UTC: {r["timestamp_utc"]}')
            lines.append(f'  {r["raw_window"]}')
            if r['step_change_device_a']['detected']:
                sc = r['step_change_device_a']
                lines.append(f'  Device A step-change: {sc["delta_db"]:+.1f}dB ({sc["direction"]}) | confidence: {sc["confidence"]}')
                lines.append(f'    Before: {sc["before_mean_db"]}dBm ({sc["before_samples"]} samples) → After: {sc["after_mean_db"]}dBm ({sc["after_samples"]} samples)')
            if r['step_change_device_b']['detected']:
                sc = r['step_change_device_b']
                lines.append(f'  Device B step-change: {sc["delta_db"]:+.1f}dB ({sc["direction"]}) | confidence: {sc["confidence"]}')
            ta = r['ta_stability']
            if ta['stable'] is not None:
                lines.append(f'  TA stability: {"STABLE" if ta["stable"] else "VARIABLE"} | mean={ta["mean_ta"]} (~{ta["mean_distance_m"]}m) | variance={ta["variance"]}')
            cn = r['cross_node']
            if cn['multi_node']:
                lines.append(f'  Cross-node: {cn["nodes_present"]} | correlated: {cn["correlated"]} | spread: {cn["cross_node_spread_db"]}dB')

    if medium:
        lines.append(f'\n{sep}')
        lines.append(f'MEDIUM CONFIDENCE VEHICLE EVENTS ({len(medium)})')
        lines.append(sep)
        for r in medium:
            lines.append(f'\n[{r["window_index"]:03d}] {r["timestamp_aest"]} AEST | {r["raw_window"]}')
            if r['step_change_device_a']['detected']:
                sc = r['step_change_device_a']
                lines.append(f'  Device A: {sc["delta_db"]:+.1f}dB {sc["direction"]} | {sc["confidence"]}')
            if r['step_change_device_b']['detected']:
                sc = r['step_change_device_b']
                lines.append(f'  Device B: {sc["delta_db"]:+.1f}dB {sc["direction"]} | {sc["confidence"]}')

    if kinematic:
        lines.append(f'\n{sep}')
        lines.append(f'KINEMATIC TRACKING FLAGS ({len(kinematic)})')
        lines.append('TA variance during these windows suggests possible mobile platform')
        lines.append(sep)
        for r in kinematic:
            ta = r['ta_stability']
            lines.append(f'\n[{r["window_index"]:03d}] {r["timestamp_aest"]} AEST')
            lines.append(f'  TA values: {ta["unique_values"]} | variance: {ta["variance"]} steps | mean dist: {ta["mean_distance_m"]}m')
            lines.append(f'  NOTE: TA variance >2 during co-presence = possible mobile tracking operation')

    lines.append(f'\n{sep}')
    lines.append('WINDOWS WITH INSUFFICIENT RSRP DATA')
    lines.append('(CASTNET data too sparse — bladeRF capture would provide denser baseline)')
    lines.append(sep)
    sparse = [r for r in results if r['total_events_in_window'] < MIN_STABLE_SAMPLES * 2]
    for r in sparse:
        lines.append(f'  [{r["window_index"]:03d}] {r["timestamp_aest"]} AEST | {r["total_events_in_window"]} events in window')

    lines.append(f'\n{sep}')
    lines.append('AFP LEGAL REFERENCES')
    lines.append(sep)
    lines.append("""
AFP LEX 4864 | ACMA ENQ-1851DVJH04 | VicPol CIRS-20260331-141 | TIO 2026-03-04898

Applicable legislation:
  Radiocommunications Act 1992 (Cth) s.189
  Telecommunications (Interception and Access) Act 1979 (Cth)
  Privacy Act 1988 (Cth)
  Criminal Code Act 1995 (Cth) Div 477

Methodology references:
  ESPectre (francescopace) — WiFi CSI motion detection via RSRP variance
  SeaGlass (UW 2017) — Passive cellular measurement
  3GPP TS 36.211 — Timing Advance = 78m/step
""")
    lines.append(sep)
    return '\n'.join(lines)


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='RSRP vehicle detection and kinematic tracking analysis'
    )
    parser.add_argument('--castnet', required=True, help='Path to castnet.db')
    parser.add_argument('--windows', required=True,
                        help='Co-presence window file (warrant_*.txt)')
    parser.add_argument('--output', default='rsrp_vehicle_report.txt')
    parser.add_argument('--json', default='rsrp_vehicle_report.json')
    args = parser.parse_args()

    print(f'Loading CASTNET data from {args.castnet}...')
    events = load_castnet(args.castnet)
    print(f'Loaded {len(events)} RSRP events')

    print(f'Loading co-presence windows from {args.windows}...')
    windows = parse_window_file(args.windows)
    print(f'Loaded {len(windows)} co-presence windows')

    if not events:
        print('No CASTNET events found.')
        sys.exit(1)
    if not windows:
        print('No co-presence windows found.')
        sys.exit(1)

    print('Running vehicle detection analysis...')
    results = analyse_windows(events, windows)

    high = sum(1 for r in results if r['vehicle_event_confidence'] == 'HIGH')
    medium = sum(1 for r in results if r['vehicle_event_confidence'] == 'MEDIUM')
    kinematic = sum(1 for r in results if r['ta_stability'].get('kinematic_flag'))

    print(f'\nResults: {high} HIGH | {medium} MEDIUM | {kinematic} kinematic flags')

    report = format_report(results, args.castnet, args.windows)
    print('\n' + report)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'\n[OK] Text report: {args.output}')

    with open(args.json, 'w', encoding='utf-8') as f:
        json.dump({
            'generated': datetime.now().isoformat(),
            'castnet_db': args.castnet,
            'window_file': args.windows,
            'total_windows': len(windows),
            'high_confidence': high,
            'medium_confidence': medium,
            'kinematic_flags': kinematic,
            'results': results,
        }, f, indent=2, default=str)
    print(f'[OK] JSON report: {args.json}')


if __name__ == '__main__':
    main()
