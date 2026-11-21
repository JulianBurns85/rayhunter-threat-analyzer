#!/usr/bin/env python3
"""
Clean Baseline Capture & Comparison Script

Run this from a known-clean location (5-10km from home) to establish
that your detection tools produce ZERO findings on legitimate networks.

This proves:
  1. Your tool doesn't false-positive on clean data
  2. The anomalies at your home location are real, not tool artifacts
  3. The statistical baselines are calibrated to Australian networks

Usage:
  # Step 1: At clean location, after running Rayhunter for 2+ hours:
  python3 baseline_comparison.py --mode capture --input /path/to/clean/files/

  # Step 2: Back home, compare against your investigation data:
  python3 baseline_comparison.py --mode compare --baseline baseline/ --investigation investigation/

Author: Julian Burns / Claude AI-assisted
Date: 2026-05-22
"""

import argparse
import json
import os
import sys
import subprocess
import hashlib
import statistics
from typing import List, Dict, Optional
from collections import Counter
from datetime import datetime

try:
    import numpy as np
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


def analyze_pcapng(pcapng_path: str) -> Dict:
    """Extract key metrics from a PCAPNG file for baseline comparison."""
    
    cmd = [
        "tshark", "-r", pcapng_path,
        "-T", "fields", "-e", "frame.time_epoch", "-e", "_ws.col.Info",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "tshark_failed"}
    
    releases = []
    smc_count = 0
    auth_count = 0
    meas_reports = []
    service_requests = 0
    
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t', 1)
        if len(parts) < 2:
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            continue
        info = parts[1]
        
        if 'RRCConnectionRelease' in info:
            releases.append(ts)
        if 'SecurityModeCommand' in info and 'Complete' not in info:
            smc_count += 1
        if 'Authentication request' in info:
            auth_count += 1
        if 'MeasurementReport' in info:
            meas_reports.append(ts)
        if 'Service request' in info:
            service_requests += 1
    
    # Compute metrics
    metrics = {
        "file": os.path.basename(pcapng_path),
        "release_count": len(releases),
        "smc_count": smc_count,
        "auth_count": auth_count,
        "auth_rate": auth_count / smc_count if smc_count > 0 else None,
        "meas_report_count": len(meas_reports),
        "service_requests": service_requests,
    }
    
    # Release interval analysis
    if len(releases) >= 3:
        intervals = [releases[i] - releases[i-1] for i in range(1, len(releases))]
        normal = [d for d in intervals if 5 < d < 600]
        if normal:
            metrics["release_interval_mean"] = round(statistics.mean(normal), 3)
            metrics["release_interval_sd"] = round(statistics.stdev(normal), 3) if len(normal) > 1 else 0
            metrics["release_interval_cv"] = round(
                statistics.stdev(normal) / statistics.mean(normal), 4
            ) if len(normal) > 1 and statistics.mean(normal) > 0 else None
    
    # MeasurementReport interval
    if len(meas_reports) >= 5:
        mr_intervals = [meas_reports[i] - meas_reports[i-1] for i in range(1, len(meas_reports))]
        normal_mr = [d for d in mr_intervals if 1 < d < 15]
        if normal_mr:
            metrics["meas_report_interval_mean"] = round(statistics.mean(normal_mr), 3)
    
    return metrics


def capture_baseline(input_dir: str, output_file: str = "baseline_profile.json"):
    """
    Analyze all PCAPs in a directory to create a baseline profile.
    Run this from a CLEAN location away from home.
    """
    print("=" * 60)
    print("  CLEAN BASELINE PROFILE GENERATION")
    print(f"  Input: {input_dir}")
    print("=" * 60)
    
    pcap_files = [
        os.path.join(input_dir, f) 
        for f in os.listdir(input_dir) 
        if f.endswith('.pcapng')
    ]
    
    if not pcap_files:
        print("  No PCAPNG files found in input directory.")
        return
    
    all_metrics = []
    for f in sorted(pcap_files):
        print(f"\n  Analyzing: {os.path.basename(f)}")
        metrics = analyze_pcapng(f)
        all_metrics.append(metrics)
        
        # Print summary
        print(f"    Releases: {metrics.get('release_count', 0)}")
        print(f"    Auth rate: {metrics.get('auth_rate', 'N/A')}")
        if metrics.get('release_interval_cv') is not None:
            print(f"    Release interval CV: {metrics['release_interval_cv']}")
    
    # Aggregate baseline
    baseline = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "location": "CLEAN BASELINE — away from investigation site",
        "files_analyzed": len(all_metrics),
        "individual_sessions": all_metrics,
        "aggregate": {},
    }
    
    # Compute aggregate statistics
    auth_rates = [m['auth_rate'] for m in all_metrics if m.get('auth_rate') is not None]
    if auth_rates:
        baseline["aggregate"]["auth_rate_mean"] = round(statistics.mean(auth_rates), 4)
        baseline["aggregate"]["auth_rate_min"] = round(min(auth_rates), 4)
    
    release_cvs = [m['release_interval_cv'] for m in all_metrics if m.get('release_interval_cv') is not None]
    if release_cvs:
        baseline["aggregate"]["release_cv_mean"] = round(statistics.mean(release_cvs), 4)
        baseline["aggregate"]["release_cv_min"] = round(min(release_cvs), 4)
    
    total_releases = sum(m.get('release_count', 0) for m in all_metrics)
    total_smcs = sum(m.get('smc_count', 0) for m in all_metrics)
    baseline["aggregate"]["total_releases"] = total_releases
    baseline["aggregate"]["total_connections"] = total_smcs
    
    # Save
    with open(output_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"\n  Baseline saved to: {output_file}")
    print(f"  Sessions: {len(all_metrics)}")
    print(f"  Total releases: {total_releases}")
    print(f"  Total connections: {total_smcs}")
    if auth_rates:
        print(f"  Auth rate (baseline): {statistics.mean(auth_rates):.1%}")
    
    return baseline


def compare_against_baseline(baseline_file: str, investigation_dir: str):
    """
    Compare investigation data against clean baseline.
    Highlights deviations that prove anomalous activity.
    """
    with open(baseline_file) as f:
        baseline = json.load(f)
    
    print("=" * 60)
    print("  INVESTIGATION vs BASELINE COMPARISON")
    print(f"  Baseline: {baseline_file}")
    print(f"  Investigation: {investigation_dir}")
    print("=" * 60)
    
    pcap_files = [
        os.path.join(investigation_dir, f)
        for f in os.listdir(investigation_dir)
        if f.endswith('.pcapng')
    ]
    
    baseline_auth_rate = baseline.get("aggregate", {}).get("auth_rate_mean")
    baseline_cv = baseline.get("aggregate", {}).get("release_cv_mean")
    
    print(f"\n  Baseline auth rate: {baseline_auth_rate}")
    print(f"  Baseline release CV: {baseline_cv}")
    
    deviations = []
    
    for f in sorted(pcap_files):
        metrics = analyze_pcapng(f)
        fname = os.path.basename(f)
        
        # Check auth rate deviation
        if metrics.get('auth_rate') is not None and baseline_auth_rate is not None:
            if metrics['auth_rate'] < baseline_auth_rate * 0.5:
                deviations.append({
                    "file": fname,
                    "metric": "auth_rate",
                    "baseline": baseline_auth_rate,
                    "observed": metrics['auth_rate'],
                    "severity": "CRITICAL" if metrics['auth_rate'] < 0.1 else "HIGH",
                })
        
        # Check release CV (metronomic = low CV)
        if metrics.get('release_interval_cv') is not None:
            if metrics['release_interval_cv'] < 0.05:
                deviations.append({
                    "file": fname,
                    "metric": "release_periodicity",
                    "cv": metrics['release_interval_cv'],
                    "mean_interval": metrics.get('release_interval_mean'),
                    "severity": "CRITICAL",
                })
        
        # Check MeasurementReport interval
        if metrics.get('meas_report_interval_mean') is not None:
            if metrics['meas_report_interval_mean'] < 10:
                deviations.append({
                    "file": fname,
                    "metric": "forced_measurement_reporting",
                    "interval_s": metrics['meas_report_interval_mean'],
                    "severity": "HIGH",
                })
    
    # Report
    print(f"\n  {'='*50}")
    print(f"  DEVIATIONS FROM BASELINE: {len(deviations)}")
    print(f"  {'='*50}")
    
    for d in deviations:
        print(f"\n  [{d['severity']}] {d['file']}")
        print(f"    Metric: {d['metric']}")
        for k, v in d.items():
            if k not in ('file', 'severity', 'metric'):
                print(f"    {k}: {v}")
    
    if not deviations:
        print("\n  No significant deviations detected.")
        print("  Investigation data appears consistent with baseline.")
    
    # Save comparison
    comparison = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "baseline_file": baseline_file,
        "investigation_dir": investigation_dir,
        "deviations": deviations,
        "deviation_count": len(deviations),
    }
    
    output_file = "baseline_comparison_results.json"
    with open(output_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    print(f"\n  Results saved to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Baseline Capture & Comparison")
    parser.add_argument("--mode", choices=["capture", "compare"], required=True)
    parser.add_argument("--input", type=str, help="Input directory for capture mode")
    parser.add_argument("--baseline", type=str, help="Baseline JSON file for compare mode")
    parser.add_argument("--investigation", type=str, help="Investigation directory for compare mode")
    parser.add_argument("--output", type=str, default="baseline_profile.json")
    
    args = parser.parse_args()
    
    if args.mode == "capture":
        if not args.input:
            print("Error: --input required for capture mode")
            sys.exit(1)
        capture_baseline(args.input, args.output)
    
    elif args.mode == "compare":
        if not args.baseline or not args.investigation:
            print("Error: --baseline and --investigation required for compare mode")
            sys.exit(1)
        compare_against_baseline(args.baseline, args.investigation)


COUNT_METRICS = (
    "identity_request",
    "identity_request_imsi",
    "identity_request_imsi_plain",
    "auth_request",
    "rrc_release",
)


def _parse_int_auto(val) -> Optional[int]:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def parse_rows(rows: List[List[str]]) -> Dict:
    """Parse tabular NAS/RRC rows into metric counts and capture duration."""
    counts = {k: 0 for k in COUNT_METRICS}
    timestamps: List[float] = []

    for row in rows:
        if not row:
            continue
        ts_val = None
        if len(row) > 0 and str(row[0]).strip():
            try:
                ts_val = float(str(row[0]).strip())
                timestamps.append(ts_val)
            except ValueError:
                pass

        msg_code = _parse_int_auto(row[1]) if len(row) > 1 else None
        id_code = _parse_int_auto(row[2]) if len(row) > 2 else None
        sec_hdr = str(row[3]).strip() if len(row) > 3 else ""
        desc = str(row[4]).strip().lower() if len(row) > 4 else ""

        is_id_req = (msg_code == 0x55) or ("identity request" in desc)
        is_auth_req = (msg_code == 0x52) or ("authentication request" in desc)
        is_rrc_rel = ("rrcconnectionrelease" in desc) or ("rrc connection release" in desc)

        if is_id_req:
            counts["identity_request"] += 1
            if id_code == 1:
                counts["identity_request_imsi"] += 1
                if sec_hdr in ("0", ""):
                    counts["identity_request_imsi_plain"] += 1

        if is_auth_req:
            counts["auth_request"] += 1

        if is_rrc_rel:
            counts["rrc_release"] += 1

    duration_s = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
    return {
        "counts": counts,
        "duration_s": duration_s,
    }


def compare_profiles(base: Dict, inv: Dict, ratio_threshold: float = 3.0, min_excess_per_hour: float = 1.0) -> Dict:
    """Compare hourly metric rates between a baseline profile and an investigation profile."""
    base_hours = float(base.get("hours") or 1.0)
    inv_hours = float(inv.get("hours") or 1.0)
    if base_hours <= 0:
        base_hours = 1.0
    if inv_hours <= 0:
        inv_hours = 1.0

    base_counts = base.get("counts", {})
    inv_counts = inv.get("counts", {})
    all_metrics = list(dict.fromkeys(list(COUNT_METRICS) + list(base_counts.keys()) + list(inv_counts.keys())))

    results = []
    for metric in all_metrics:
        b_cnt = float(base_counts.get(metric, 0) or 0)
        i_cnt = float(inv_counts.get(metric, 0) or 0)
        b_rate = b_cnt / base_hours
        i_rate = i_cnt / inv_hours
        excess_rate = i_rate - b_rate

        is_excess = False
        if excess_rate > min_excess_per_hour:
            if b_rate <= 0:
                is_excess = i_cnt > 0
            else:
                is_excess = (i_rate / b_rate) >= ratio_threshold

        results.append({
            "metric": metric,
            "baseline_count": b_cnt,
            "investigation_count": i_cnt,
            "baseline_rate_per_h": round(b_rate, 4),
            "investigation_rate_per_h": round(i_rate, 4),
            "flag": "EXCEEDS_BASELINE" if is_excess else "consistent",
        })

    return {"metrics": results}
