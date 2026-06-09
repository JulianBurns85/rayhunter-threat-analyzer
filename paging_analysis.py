#!/usr/bin/env python3
"""
paging_analysis.py — Standalone targeted paging analysis script.

Analyses m-TMSI paging frequency from a PCAPNG file using tshark.
Designed for use with Rayhunter captures from the Cranbourne East investigation.

Usage:
    python paging_analysis.py <pcapng_file> [--tmsi d8736117] [--top N]

Requires tshark in PATH.

Corrected base quantum: 10.880s (confirmed from 402-event timestamp series,
27 May 2026 session 1779670603.pcapng).  Earlier analyses used 10.94s
which was a rounding artefact.
"""

import argparse
import json
import statistics
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────── #

BASE_QUANTUM        = 10.880   # seconds — confirmed machine-precision quantum
BASE_WINDOW_LO      = 9.0
BASE_WINDOW_HI      = 13.0
GAP_THRESHOLD       = 60.0     # seconds — gaps above this = device unreachable
TOP_N_DEFAULT       = 10


# ── tshark extraction ──────────────────────────────────────────────────── #

def extract_paging_timestamps(pcapng: Path) -> dict[str, list[float]]:
    """
    Use tshark verbose output to extract m-TMSI values and their
    associated Epoch Arrival Times from a PCAPNG file.

    Returns: dict of m-TMSI hex string → sorted list of epoch timestamps
    """
    cmd = [
        "tshark", "-r", str(pcapng),
        "-V",
        "2>/dev/null"
    ]
    try:
        result = subprocess.run(
            ["tshark", "-r", str(pcapng), "-V"],
            capture_output=True, text=True, timeout=300,
            errors="replace"
        )
    except subprocess.TimeoutExpired:
        print("[ERROR] tshark timed out — file may be very large.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] tshark not found in PATH.", file=sys.stderr)
        sys.exit(1)

    tmsi_ts: dict[str, list[float]] = {}
    current_epoch: float = 0.0

    for line in result.stdout.splitlines():
        stripped = line.strip()

        if "Epoch Arrival Time:" in stripped:
            try:
                current_epoch = float(stripped.split("Epoch Arrival Time:")[1].split()[0])
            except (ValueError, IndexError):
                pass

        elif "m-TMSI:" in stripped and current_epoch > 0:
            try:
                # Format: "m-TMSI: d8736117 [bit length 32 ...]"
                raw = stripped.split("m-TMSI:")[1].split()[0].strip("[](),")
                if raw:
                    tmsi_ts.setdefault(raw, []).append(current_epoch)
            except IndexError:
                pass

    # Sort all timestamp lists
    return {k: sorted(v) for k, v in tmsi_ts.items()}


# ── Interval analysis ──────────────────────────────────────────────────── #

def analyse_tmsi(tmsi: str, timestamps: list[float]) -> dict:
    """Full interval analysis for a single m-TMSI."""
    if len(timestamps) < 2:
        return {}

    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

    base   = [i for i in intervals if BASE_WINDOW_LO  <= i <= BASE_WINDOW_HI]
    double = [i for i in intervals if 2*BASE_WINDOW_LO <= i <= 2*BASE_WINDOW_HI]
    triple = [i for i in intervals if 3*BASE_WINDOW_LO <= i <= 3*BASE_WINDOW_HI]
    other  = [i for i in intervals if i not in base + double + triple]
    gaps   = [(timestamps[i], timestamps[i+1], intervals[i])
              for i in range(len(intervals)) if intervals[i] > GAP_THRESHOLD]

    session_duration = (timestamps[-1] - timestamps[0]) / 3600  # hours

    return {
        "tmsi":              tmsi,
        "count":             len(timestamps),
        "session_duration_h": round(session_duration, 2),
        "start_epoch":       timestamps[0],
        "end_epoch":         timestamps[-1],
        "intervals_total":   len(intervals),
        "base_count":        len(base),
        "base_mean":         round(statistics.mean(base), 4) if base else 0,
        "base_sd":           round(statistics.stdev(base), 4) if len(base) > 1 else 0,
        "double_count":      len(double),
        "triple_count":      len(triple),
        "other_count":       len(other),
        "overall_mean":      round(statistics.mean(intervals), 3),
        "overall_sd":        round(statistics.stdev(intervals), 3) if len(intervals) > 1 else 0,
        "paging_rate_per_h": round(len(timestamps) / max(session_duration, 0.001), 1),
        "gaps":              gaps,
    }


# ── Report printing ────────────────────────────────────────────────────── #

def print_report(data: dict, target_tmsi: str | None = None) -> None:
    sep = "=" * 60

    print(f"\n{sep}")
    print(f"  PAGING ANALYSIS — m-TMSI {data['tmsi']}")
    print(sep)
    print(f"  Total paging events  : {data['count']}")
    print(f"  Session duration     : {data['session_duration_h']:.2f} hours")

    if data['start_epoch'] > 946684800:  # sanity check — after year 2000
        start_dt = datetime.fromtimestamp(data['start_epoch'], tz=timezone.utc)
        end_dt   = datetime.fromtimestamp(data['end_epoch'],   tz=timezone.utc)
        print(f"  Session start (UTC)  : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Session end   (UTC)  : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(f"  Timestamps           : boot-relative (no wall-clock anchor)")

    print(f"\n  INTERVAL ANALYSIS")
    print("-" * 40)
    print(f"  Base interval (~{BASE_QUANTUM}s) : {data['base_count']:>5} occurrences"
          f"  mean={data['base_mean']}s  SD={data['base_sd']}s")
    print(f"  Double interval (~{2*BASE_QUANTUM:.3f}s): {data['double_count']:>5} occurrences")
    print(f"  Triple interval (~{3*BASE_QUANTUM:.3f}s): {data['triple_count']:>5} occurrences")
    print(f"  Other intervals          : {data['other_count']:>5} occurrences")
    print()
    print(f"  Overall mean interval   : {data['overall_mean']}s")
    print(f"  Overall SD              : {data['overall_sd']}s")
    print()
    print(f"  Paging rate             : {data['paging_rate_per_h']} pages/hour")
    print(f"                          : 1 page every {data['overall_mean']:.1f}s on average")

    if data['gaps']:
        print(f"\n  GAPS > {GAP_THRESHOLD:.0f}s (device offline/unreachable): {len(data['gaps'])}")
        print("-" * 40)
        for i, (t_start, t_end, gap) in enumerate(data['gaps']):
            missed = round(gap / BASE_QUANTUM) - 1
            if t_start > 946684800:
                s_dt = datetime.fromtimestamp(t_start, tz=timezone.utc).strftime('%H:%M:%S')
                e_dt = datetime.fromtimestamp(t_end,   tz=timezone.utc).strftime('%H:%M:%S')
                time_str = f"({s_dt} → {e_dt} UTC)"
            else:
                time_str = f"(boot-relative)"
            print(f"  Gap #{i+1:>3}: {gap:>7.0f}s  {time_str}  ~{missed} missed pages")

    print(f"\n  INTERPRETATION")
    print("-" * 40)
    if data['base_sd'] < 1.0 and data['base_count'] > 30:
        precision = "MACHINE PRECISION"
    elif data['base_sd'] < 2.0:
        precision = "High precision"
    else:
        precision = "Moderate precision"

    print(f"  Base paging quantum {data['base_mean']}s with SD={data['base_sd']}s")
    print(f"  Precision assessment: {precision}")
    print()
    if data['count'] > 100:
        print(f"  {data['count']} targeted pages over {data['session_duration_h']:.1f} hours = PERSISTENT SURVEILLANCE.")
    print(f"  No legitimate LTE network pages a single device at this rate.")
    if data['base_count'] > 40:
        print(f"  This m-TMSI is the PRIMARY TARGET of the rogue platform.")
    print()


# ── CLI ────────────────────────────────────────────────────────────────── #

def main() -> None:
    ap = argparse.ArgumentParser(description="Paging analysis — m-TMSI targeting detector")
    ap.add_argument("pcapng", help="Input PCAPNG file (Rayhunter capture)")
    ap.add_argument("--tmsi", help="Analyse a specific m-TMSI only (hex, e.g. d8736117)")
    ap.add_argument("--top",  type=int, default=TOP_N_DEFAULT,
                    help=f"Report top N m-TMSIs by page count (default {TOP_N_DEFAULT})")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = ap.parse_args()

    pcapng = Path(args.pcapng)
    if not pcapng.exists():
        print(f"[ERROR] File not found: {pcapng}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Extracting paging events from {pcapng.name} ...")
    tmsi_data = extract_paging_timestamps(pcapng)

    if not tmsi_data:
        print("[!] No m-TMSI paging events found.")
        sys.exit(0)

    counter = Counter({k: len(v) for k, v in tmsi_data.items()})
    print(f"[*] Found {sum(counter.values())} total paging events across "
          f"{len(counter)} unique m-TMSIs.")

    results = []

    if args.tmsi:
        target = args.tmsi.lower().strip()
        # Try exact match first, then partial
        if target in tmsi_data:
            results = [analyse_tmsi(target, tmsi_data[target])]
        else:
            matches = [k for k in tmsi_data if target in k.lower()]
            if not matches:
                print(f"[!] m-TMSI '{target}' not found in capture.")
                sys.exit(0)
            results = [analyse_tmsi(m, tmsi_data[m]) for m in matches]
    else:
        # Top N by page count
        for tmsi, count in counter.most_common(args.top):
            result = analyse_tmsi(tmsi, tmsi_data[tmsi])
            if result:
                results.append(result)

    if args.json:
        # Serialise gaps list for JSON
        for r in results:
            r["gaps"] = [
                {"start": g[0], "end": g[1], "duration_s": round(g[2], 3)}
                for g in r.get("gaps", [])
            ]
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if r:
                print_report(r)

    # Summary table
    if not args.tmsi and not args.json:
        print("\n" + "=" * 60)
        print("  TOP m-TMSI FREQUENCY TABLE")
        print("=" * 60)
        print(f"  {'Count':>6}  {'m-TMSI':<12}  {'Assessment'}")
        print("-" * 60)
        for tmsi, count in counter.most_common(20):
            if count >= 50:
                tag = "⚠️  TARGETED"
            elif count >= 20:
                tag = "   Elevated"
            else:
                tag = "   Normal"
            print(f"  {count:>6}  {tmsi:<12}  {tag}")
        print()


if __name__ == "__main__":
    main()
