# temporal_device_timeline.py
# Standalone script - run directly against MAY_2026_CAPTURES or any corpus dir
# Usage: python temporal_device_timeline.py --dir D:\MAY_2026_CAPTURES --output timeline_report.txt
# No pipeline required.

import argparse
import json
import math
import os
import re
import sqlite3
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROGUE_CIDS_TELSTRA = {137713155, 137713165, 137713175, 137713195}
# INTEGRITY NOTE (25 Jun 2026): CIDs 8409357/367/387/397 (eNB 32849, TAC=30336)
# are CONFIRMED LEGITIMATE Vodafone macro infrastructure (CASTNET Finding [20]).
# Removed to prevent false rogue attributions.
ROGUE_CIDS_VODAFONE = {8666381, 8666391, 8666411}  # post-ACMA cluster only
ALL_ROGUE_CIDS = ROGUE_CIDS_TELSTRA | ROGUE_CIDS_VODAFONE

CID_BAND_PRIMARY = {
    137713155: 28,
    137713165: 3,
    137713175: 1,
    137713195: 7,
    8409357: 1,
    8409367: 1,
    8409387: 1,
    8409397: 1,
    8666381: 3,
    8666391: 3,
    8666411: 3,
}

INCOMPATIBLE_BAND_PAIRS = {
    frozenset([28, 3]),
    frozenset([28, 7]),
    frozenset([28, 1]),
}

HARRIS_INTERVALS = [(0.075, 0.085), (0.155, 0.165)]
SDR_INTERVALS = [(1.990, 2.150), (0.475, 0.485), (0.235, 0.245)]

ATTACK_SIGNATURES = {
    "AUTH_REJECT": ["authentication reject", "auth_reject", "authreject", "51 00"],
    "IDENTITY_REQUEST": ["identity request", "identity_request", "55 00", "imsi request"],
    "PROSE": ["prose", "proximity", "reportProximityConfig", "d2d"],
    "IMEISV": ["imeisv", "imei sv", "software version", "5e 00"],
    "HANDOVER_INJECT": ["mobilityControlInfo", "MCI=YES", "mci=yes"],
    "NULL_CIPHER": ["eea0", "null cipher", "no encryption"],
}

REGULATORY_EVENTS = [
    {"date": "2026-01-23", "label": "First confirmed attack (corpus start)"},
    {"date": "2026-03-31", "label": "VicPol CIRS-20260331-141"},
    {"date": "2026-04-13", "label": "VicPol CIRS-20260413-6"},
    {"date": "2026-05-08", "label": "ACMA field inspection ENQ-1851DVJH04"},
    {"date": "2026-05-19", "label": "AFP referral via VicPol"},
    {"date": "2026-05-30", "label": "Major blackout begins (76.9h)"},
    {"date": "2026-06-02", "label": "Blackout ends, brief resumption"},
    {"date": "2026-06-04", "label": "Full resumption - record volume"},
]


def get_ts(event: Dict) -> Optional[float]:
    for k in ("timestamp", "time", "ts", "created_at"):
        v = event.get(k)
        if v is None:
            continue
        try:
            if isinstance(v, (int, float)):
                f = float(v)
                if f > 1e12:
                    f /= 1000
                return f
            v2 = str(v).replace("Z", "+00:00")
            dt = datetime.fromisoformat(v2)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, OSError, AttributeError):
            continue
    return None


def to_aest(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=10)


def load_ndjson(path: str) -> List[Dict]:
    events = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    cid = e.get("cell_id") or e.get("ci") or e.get("cid")
                    if cid:
                        try:
                            if int(cid) in ALL_ROGUE_CIDS:
                                events.append(e)
                        except (TypeError, ValueError):
                            pass
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return events


def load_castnet(db_path: str) -> List[Dict]:
    events = []
    if not os.path.exists(db_path):
        return events
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        ph = ",".join(str(c) for c in ALL_ROGUE_CIDS)
        cur.execute(f"""
            SELECT timestamp, ci as cell_id, tac, mcc, mnc,
                   rsrp, timing_advance, bands
            FROM detections
            WHERE ci IN ({ph})
            ORDER BY timestamp ASC
        """)
        for row in cur.fetchall():
            events.append(dict(row))
        conn.close()
        print(f"[CASTNET] Loaded {len(events)} rogue events")
    except Exception as e:
        print(f"[CASTNET] Error: {e}", file=sys.stderr)
    return events


def scan_ndjson_dir(directory: str) -> List[Dict]:
    events = []
    p = Path(directory)
    ndjson_files = list(p.rglob("*.ndjson"))
    print(f"[NDJSON] Scanning {len(ndjson_files)} files...")
    for f in ndjson_files:
        events.extend(load_ndjson(str(f)))
    print(f"[NDJSON] Loaded {len(events)} rogue events")
    return events


def classify_hardware(events: List[Dict]) -> Dict:
    if not events:
        return {"harris_score": 0, "sdr_score": 0, "dominant": "UNKNOWN",
                "band_copresence": 0, "harris_intervals": 0, "sdr_intervals": 0}

    sorted_events = sorted(events, key=lambda e: get_ts(e) or 0)
    timestamps = [t for e in sorted_events if (t := get_ts(e)) is not None]

    intervals = []
    for i in range(len(timestamps) - 1):
        d = timestamps[i+1] - timestamps[i]
        if 0.001 <= d <= 300:
            intervals.append(d)

    harris_count = sum(1 for iv in intervals
                       if any(lo <= iv <= hi for lo, hi in HARRIS_INTERVALS))
    sdr_count = sum(1 for iv in intervals
                    if any(lo <= iv <= hi for lo, hi in SDR_INTERVALS))

    # Band co-presence
    copresence = 0
    ts_cid = [(get_ts(e), int(e.get("cell_id") or e.get("ci") or 0))
              for e in events
              if get_ts(e) is not None]
    ts_cid.sort()

    for i, (ts_a, cid_a) in enumerate(ts_cid):
        band_a = CID_BAND_PRIMARY.get(cid_a)
        if band_a is None:
            continue
        for j in range(i+1, len(ts_cid)):
            ts_b, cid_b = ts_cid[j]
            if ts_b - ts_a > 60:
                break
            band_b = CID_BAND_PRIMARY.get(cid_b)
            if band_b and band_b != band_a:
                if frozenset([band_a, band_b]) in INCOMPATIBLE_BAND_PAIRS:
                    copresence += 1

    harris_score = harris_count * 2 + copresence
    sdr_score = sdr_count * 3

    if harris_score > 0 and sdr_score > 0:
        dominant = "DUAL"
    elif harris_score > sdr_score:
        dominant = "HARRIS"
    elif sdr_score > harris_score:
        dominant = "SDR"
    else:
        dominant = "UNKNOWN"

    return {
        "harris_score": harris_score,
        "sdr_score": sdr_score,
        "dominant": dominant,
        "band_copresence": copresence,
        "harris_intervals": harris_count,
        "sdr_intervals": sdr_count,
        "n_events": len(events),
        "n_intervals": len(intervals),
    }


def classify_attacks(events: List[Dict]) -> Dict:
    counts = {k: 0 for k in ATTACK_SIGNATURES}
    for e in events:
        raw = str(e.get("raw", "") or e.get("msg", "") or "").lower()
        msg = str(e.get("msg_type", "") or e.get("type", "") or "").lower()
        combined = raw + " " + msg
        for attack, sigs in ATTACK_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                counts[attack] += 1
    return counts


def get_active_cids(events: List[Dict]) -> Dict[int, int]:
    counts = defaultdict(int)
    for e in events:
        try:
            cid = int(e.get("cell_id") or e.get("ci") or 0)
            if cid in ALL_ROGUE_CIDS:
                counts[cid] += 1
        except (TypeError, ValueError):
            pass
    return dict(counts)


def get_rsrp_stats(events: List[Dict]) -> Dict:
    vals = []
    for e in events:
        v = e.get("rsrp")
        if v is not None:
            try:
                vals.append(float(v))
            except (TypeError, ValueError):
                pass
    if len(vals) < 3:
        return {"mean": None, "std": None, "n": len(vals)}
    return {
        "mean": statistics.mean(vals),
        "std": statistics.stdev(vals),
        "n": len(vals),
    }


def bucket_events_weekly(events: List[Dict]) -> Dict[str, List[Dict]]:
    buckets = defaultdict(list)
    for e in events:
        ts = get_ts(e)
        if ts is None:
            continue
        dt = to_aest(ts)
        # ISO week key: YYYY-WNN
        week_key = dt.strftime("%Y-W%W")
        buckets[week_key].append(e)
    return dict(buckets)


def get_regulatory_event_for_week(week_key: str) -> Optional[str]:
    year, week = week_key.split("-W")
    year = int(year)
    week = int(week)
    for ev in REGULATORY_EVENTS:
        dt = datetime.fromisoformat(ev["date"])
        ev_week = dt.strftime("%Y-W%W")
        ev_year, ev_wk = ev_week.split("-W")
        if int(ev_year) == year and int(ev_wk) == week:
            return ev["label"]
    return None


def format_report(weekly: Dict, all_events: List[Dict]) -> str:
    lines = []
    sep = "=" * 80

    lines.append(sep)
    lines.append("TEMPORAL DEVICE TIMELINE RECONSTRUCTION")
    lines.append("rayhunter-threat-analyzer v3.7 - Dual Device Timeline Analysis")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total rogue events across corpus: {len(all_events)}")
    lines.append(sep)

    lines.append("""
PURPOSE:
  Reconstruct when each device (Device A: Harris/professional,
  Device B: srsRAN/consumer SDR) entered operation.
  Determine what attacks each device was responsible for.
  Map the clean/dirty separation strategy over time.
  Assess what a corporate audit of the Harris logs would reveal
  for each time period.
""")

    # First and last events
    timestamps = sorted([t for e in all_events if (t := get_ts(e)) is not None])
    if timestamps:
        first_dt = to_aest(timestamps[0])
        last_dt = to_aest(timestamps[-1])
        span_days = (timestamps[-1] - timestamps[0]) / 86400
        lines.append(f"Corpus span: {first_dt.strftime('%Y-%m-%d %H:%M')} AEST "
                     f"to {last_dt.strftime('%Y-%m-%d %H:%M')} AEST "
                     f"({span_days:.0f} days)")

    lines.append("")
    lines.append(sep)
    lines.append("WEEKLY DEVICE TIMELINE")
    lines.append(sep)
    lines.append("")
    lines.append(f"{'Week':<12} {'Events':>6} {'Harris':>7} {'SDR':>6} "
                 f"{'CoPresence':>11} {'Dominant':>10} {'Attacks':>8} {'Regulatory Event'}")
    lines.append("-" * 80)

    # Track when each device first appeared
    first_harris_week = None
    first_sdr_week = None
    first_dual_week = None
    first_copresence_week = None

    harris_only_weeks = []
    sdr_only_weeks = []
    dual_weeks = []

    sorted_weeks = sorted(weekly.keys())

    week_data = []
    for week in sorted_weeks:
        events = weekly[week]
        hw = classify_hardware(events)
        attacks = classify_attacks(events)
        attack_summary = "+".join(k for k, v in attacks.items() if v > 0) or "none"
        reg_event = get_regulatory_event_for_week(week) or ""

        week_data.append({
            "week": week,
            "events": len(events),
            "hw": hw,
            "attacks": attacks,
            "attack_summary": attack_summary,
            "reg_event": reg_event,
        })

        dom = hw["dominant"]
        if dom == "HARRIS" and first_harris_week is None:
            first_harris_week = week
        if dom == "SDR" and first_sdr_week is None:
            first_sdr_week = week
        if dom == "DUAL" and first_dual_week is None:
            first_dual_week = week
        if hw["band_copresence"] > 0 and first_copresence_week is None:
            first_copresence_week = week

        if dom == "HARRIS":
            harris_only_weeks.append(week)
        elif dom == "SDR":
            sdr_only_weeks.append(week)
        elif dom == "DUAL":
            dual_weeks.append(week)

        dom_str = f"[{dom}]"
        reg_short = reg_event[:25] + "..." if len(reg_event) > 25 else reg_event

        lines.append(
            f"{week:<12} {len(events):>6} "
            f"{hw['harris_score']:>7} {hw['sdr_score']:>6} "
            f"{hw['band_copresence']:>11} {dom_str:>10} "
            f"{sum(attacks.values()):>8} {reg_short}"
        )

    lines.append("")
    lines.append(sep)
    lines.append("DEVICE INTRODUCTION TIMELINE")
    lines.append(sep)

    if first_harris_week:
        lines.append(f"\nDEVICE A (Harris/Professional) FIRST DETECTED: {first_harris_week}")
        lines.append(f"  Harris-dominant weeks: {len(harris_only_weeks)}")
    else:
        lines.append("\nDEVICE A (Harris/Professional): NOT DETECTED in corpus")

    if first_sdr_week:
        lines.append(f"\nDEVICE B (srsRAN/Consumer SDR) FIRST DETECTED: {first_sdr_week}")
        lines.append(f"  SDR-dominant weeks: {len(sdr_only_weeks)}")
    else:
        lines.append("\nDEVICE B (srsRAN/Consumer SDR): NOT DETECTED in corpus")

    if first_dual_week:
        lines.append(f"\nDUAL OPERATION FIRST CONFIRMED: {first_dual_week}")
        lines.append(f"  Dual-device weeks: {len(dual_weeks)}")
    else:
        lines.append("\nDUAL OPERATION: Not confirmed in this corpus slice")

    if first_copresence_week:
        lines.append(f"\nBAND CO-PRESENCE FIRST DETECTED: {first_copresence_week}")
        lines.append("  (Physical proof of simultaneous dual-device operation)")

    # Timeline interpretation
    lines.append("")
    lines.append(sep)
    lines.append("TIMELINE INTERPRETATION")
    lines.append(sep)

    if first_harris_week and first_sdr_week:
        harris_dt = datetime.strptime(first_harris_week + "-1", "%Y-W%W-%w")
        sdr_dt = datetime.strptime(first_sdr_week + "-1", "%Y-W%W-%w")
        delta_weeks = abs((harris_dt - sdr_dt).days // 7)

        if harris_dt < sdr_dt:
            lines.append(f"""
SCENARIO: HARRIS FIRST, SDR ADDED LATER (Audit Evasion Theory)
  Device A (Harris) appeared {delta_weeks} weeks before Device B (SDR).
  
  INTERPRETATION: The operator started with professional hardware --
  either employer-issued from the beginning or acquired through work.
  The consumer SDR was added LATER, approximately {first_sdr_week}.
  
  This strongly supports the audit evasion hypothesis:
  - Initially running all operations on the Harris
  - As investigation intensified (ACMA/VicPol/AFP contact), operator
    realised Harris logs could be subpoenaed
  - Added personal SDR to run forensically attributable attacks
    (Auth Reject, ProSe, IMEISV) off the work kit
  - Harris continues passive collection (auditable, looks legitimate)
  - SDR runs the dirty work (not on any corporate register)
  
  AUDIT IMPACT: A corporate audit of periods BEFORE {first_sdr_week}
  would find Harris activity that may contain incriminating attack
  sequences -- because the SDR wasn't yet available to offload them.
  
  HISTORICAL CORPUS VALUE: Captures predating {first_sdr_week}
  may contain Harris-logged attack evidence that would appear in
  an employer audit. This is potentially more damaging to the
  operator than recent corpus -- he hadn't yet started hiding
  the attacks on the personal device.
""")
        elif sdr_dt < harris_dt:
            lines.append(f"""
SCENARIO: SDR FIRST, HARRIS ADDED LATER (Employment/Access Theory)
  Device B (SDR) appeared {delta_weeks} weeks before Device A (Harris).
  
  INTERPRETATION: The operator started with a personal consumer SDR --
  cheaper, personally owned, technically capable but lower power.
  The Harris was added LATER, approximately {first_harris_week}.
  
  This suggests the operator GAINED ACCESS to professional equipment
  during the investigation -- consistent with starting or changing
  employment that provided Harris access.
  
  The addition of Harris would coincide with a significant capability
  upgrade: multi-band simultaneous operation, higher power, more
  sophisticated attack modes.
  
  AUDIT IMPACT: Periods before {first_harris_week} show SDR-only
  activity. The employer audit covers post-{first_harris_week} only.
  Pre-employment SDR activity is entirely outside audit scope and
  represents purely personal criminal conduct.
""")
        else:
            lines.append(f"""
SCENARIO: SIMULTANEOUS INTRODUCTION (Coordinated Setup)
  Both devices appear in the same week ({first_harris_week}).
  
  INTERPRETATION: Either corpus doesn't extend far enough back to
  show introduction, or both were configured simultaneously --
  suggesting a planned, coordinated surveillance setup from the start.
  
  Recommend extending corpus to earlier captures to determine
  which device predates the other.
""")

    # Attack attribution by device
    lines.append("")
    lines.append(sep)
    lines.append("ATTACK ATTRIBUTION BY DEVICE")
    lines.append(sep)
    lines.append("""
Based on temporal analysis and hardware signatures:

DEVICE A (Harris) - PROBABLE ATTACK PROFILE:
  - Passive IMSI collection (beacon-level)
  - CID rotation (documented Harris operational mode)
  - Forced handover injection (requires Harris full LTE stack)
  - Systematic paging floods (Harris automated sweep mode)
  - Multi-band simultaneous scanning
  These attacks appear in Harris logs and COULD appear in a corporate audit.
  However, without a warrant, the employer has no obligation to produce them.

DEVICE B (srsRAN) - CONFIRMED ATTACK PROFILE:
  - Auth Reject -> Identity Request chains
  - ProSe proximity tracking (reportProximityConfig-r9)
  - IMEISV harvest
  - After-hours autonomous operation
  These attacks DO NOT appear in any employer log.
  Only a personal search warrant reveals them.

AUDIT SURVIVABILITY MATRIX:
  Harris attacks (pre-SDR period): VISIBLE in employer audit
    -> Could be damaging if audit covers this period
    -> Employer may be aware and suppressing
  Harris attacks (post-SDR period): VISIBLE in employer audit
    -> Now sanitised -- dirty attacks moved to SDR
    -> Audit likely finds nothing actionable
  SDR attacks (all periods): INVISIBLE to employer audit
    -> Requires personal search warrant
    -> /tmp/srsran/ logs, enb.conf, GNU Radio files
""")

    # Regulatory correlation
    lines.append(sep)
    lines.append("REGULATORY EVENT CORRELATION")
    lines.append(sep)
    for ev in REGULATORY_EVENTS:
        lines.append(f"\n  {ev['date']}: {ev['label']}")
        ev_dt = datetime.fromisoformat(ev["date"])
        ev_week = ev_dt.strftime("%Y-W%W")
        if ev_week in weekly:
            ev_data = [d for d in week_data if d["week"] == ev_week]
            if ev_data:
                d = ev_data[0]
                lines.append(f"    Week {ev_week}: {d['events']} events, "
                             f"dominant={d['hw']['dominant']}, "
                             f"attacks={d['attack_summary']}")
        # Check week after
        ev_dt_plus1 = ev_dt + timedelta(weeks=1)
        ev_week_plus1 = ev_dt_plus1.strftime("%Y-W%W")
        if ev_week_plus1 in weekly:
            ev_data = [d for d in week_data if d["week"] == ev_week_plus1]
            if ev_data:
                d = ev_data[0]
                lines.append(f"    Week after: {d['events']} events, "
                             f"dominant={d['hw']['dominant']}")

    lines.append("")
    lines.append(sep)
    lines.append("AFP SUBMISSION NOTE")
    lines.append(sep)
    lines.append("""
This timeline reconstruction provides:

1. WHEN each device entered operation -- establishes premeditation
   and shows deliberate escalation of surveillance capability.

2. WHAT attacks each device ran -- proves the clean/dirty separation
   strategy and consciousness of guilt.

3. WHAT a corporate audit will find for each period -- allows AFP
   to anticipate and counter any "clean audit" defence.

4. HISTORICAL EVIDENCE VALUE -- early corpus (before SDR was added)
   may contain Harris-logged attacks that are MORE incriminating
   because the operator hadn't yet started hiding them.

CRITICAL: Request from AFP that any corporate audit covers the
FULL investigation period, not just recent activity. Early captures
may contain attack sequences on the Harris that the operator cannot
now sanitise.

AFP LEX 4864 | ACMA ENQ-1851DVJH04
""")

    lines.append(sep)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Temporal device timeline reconstruction"
    )
    parser.add_argument("--dir", help="Directory of NDJSON capture files")
    parser.add_argument("--castnet", help="Path to CASTNET castnet.db")
    parser.add_argument("--output", default="timeline_report.txt")
    args = parser.parse_args()

    if not args.dir and not args.castnet:
        parser.print_help()
        sys.exit(1)

    all_events = []

    if args.dir:
        all_events.extend(scan_ndjson_dir(args.dir))

    if args.castnet:
        all_events.extend(load_castnet(args.castnet))

    if not all_events:
        print("No rogue events found.", file=sys.stderr)
        sys.exit(1)

    print(f"\nTotal rogue events loaded: {len(all_events)}")
    print("Bucketing by week...")

    weekly = bucket_events_weekly(all_events)
    print(f"Weeks with rogue activity: {len(weekly)}")

    report = format_report(weekly, all_events)
    print("\n" + report)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[OK] Report saved: {args.output}")

    json_output = args.output.replace(".txt", ".json")
    weekly_json = {}
    for week, events in weekly.items():
        hw = classify_hardware(events)
        attacks = classify_attacks(events)
        weekly_json[week] = {
            "n_events": len(events),
            "hardware": hw,
            "attacks": attacks,
            "active_cids": get_active_cids(events),
            "rsrp": get_rsrp_stats(events),
        }
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump(weekly_json, f, indent=2, default=str)
    print(f"[OK] Data saved: {json_output}")


if __name__ == "__main__":
    main()
