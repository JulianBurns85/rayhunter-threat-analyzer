"""
Advanced Forensic Analysis Module for rayhunter-threat-analyzer v2.5+

Techniques:
  1. Autocorrelation — statistically rigorous periodicity detection
  2. FFT Spectral Analysis — frequency-domain timer signature extraction
  3. Binomial p-value — statistical significance of periodic clustering
  4. SIB4/SIB5 Neighbor Cell List Analysis — empty/minimal neighbor detection
  5. GUTI Reallocation Tracking — missing identity refresh detection
  6. Paging Volume Analysis — mass surveillance indicator
  7. Composite Cross-Session Scoring — temporal persistence weighting

Author: Julian Burns / Claude AI-assisted
Date: 2026-05-22
Device: TP-Link M7350 (Qualcomm MDM9225) running EFF Rayhunter
"""

import subprocess
import sys
import os
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
from scipy import stats as scipy_stats


# ============================================================
# 1. Autocorrelation Periodicity Detector
# ============================================================

def compute_autocorrelation(intervals: np.ndarray, max_lag: int = 5) -> Dict[str, Any]:
    """
    Compute autocorrelation of inter-event intervals at multiple lags.
    
    Metronomic timing → autocorrelation at lag 1 ≈ 1.0
    Random timing → autocorrelation at lag 1 ≈ 0.0
    
    Returns dict with lag-1 autocorrelation, all lags, and interpretation.
    """
    if len(intervals) < 10:
        return {"error": "insufficient_data", "n": len(intervals)}
    
    n = len(intervals)
    mean = np.mean(intervals)
    var = np.var(intervals)
    
    if var < 1e-10:
        return {"lag1": 1.0, "interpretation": "constant_intervals", "n": n}
    
    autocorrs = {}
    for lag in range(1, min(max_lag + 1, n)):
        c = np.sum((intervals[:-lag] - mean) * (intervals[lag:] - mean)) / (n * var)
        autocorrs[f"lag_{lag}"] = round(float(c), 6)
    
    lag1 = autocorrs.get("lag_1", 0.0)
    
    if lag1 > 0.8:
        interpretation = "METRONOMIC — near-perfect periodicity (autocorr > 0.8)"
    elif lag1 > 0.5:
        interpretation = "STRONG periodicity (autocorr 0.5-0.8)"
    elif lag1 > 0.2:
        interpretation = "MODERATE periodicity (autocorr 0.2-0.5)"
    else:
        interpretation = "NO significant periodicity (autocorr < 0.2)"
    
    return {
        "lag1_autocorrelation": lag1,
        "all_lags": autocorrs,
        "interpretation": interpretation,
        "n_intervals": n,
        "mean_interval": round(float(mean), 4),
        "sd_interval": round(float(np.std(intervals)), 4),
    }


# ============================================================
# 2. FFT Spectral Analysis
# ============================================================

def fft_dominant_period(timestamps: np.ndarray, 
                         sample_rate: float = 1.0,
                         min_period: float = 30.0,
                         max_period: float = 600.0) -> Dict[str, Any]:
    """
    Find dominant period in event timing via Fast Fourier Transform.
    
    Creates a binary signal (1 at event times, 0 elsewhere), computes FFT,
    and identifies the dominant frequency peak within the specified range.
    
    Returns the dominant period, its power, and the top-5 peaks.
    """
    if len(timestamps) < 10:
        return {"error": "insufficient_data"}
    
    timestamps = np.sort(timestamps)
    duration = timestamps[-1] - timestamps[0]
    
    if duration < min_period * 3:
        return {"error": "duration_too_short", "duration": float(duration)}
    
    # Create binary event signal
    n_samples = int(duration * sample_rate)
    if n_samples < 64:
        return {"error": "too_few_samples"}
    
    signal = np.zeros(n_samples)
    for t in timestamps:
        idx = int((t - timestamps[0]) * sample_rate)
        if 0 <= idx < n_samples:
            signal[idx] = 1.0
    
    # Subtract mean to remove DC component
    signal -= np.mean(signal)
    
    # FFT
    fft_vals = np.abs(np.fft.rfft(signal))
    freqs = np.fft.rfftfreq(n_samples, d=1.0 / sample_rate)
    
    # Filter to target period range (avoid divide by zero)
    valid_mask = (freqs > 1e-10)
    periods = np.where(valid_mask, 1.0 / freqs, 0)
    valid_mask = valid_mask & (periods >= min_period) & (periods <= max_period)
    
    if not np.any(valid_mask):
        return {"error": "no_valid_frequencies"}
    
    valid_freqs = freqs[valid_mask]
    valid_power = fft_vals[valid_mask]
    
    # Find top peaks
    top_indices = np.argsort(valid_power)[-5:][::-1]
    peaks = []
    for idx in top_indices:
        freq = valid_freqs[idx]
        period = 1.0 / freq if freq > 0 else float('inf')
        power = valid_power[idx]
        peaks.append({
            "period_s": round(float(period), 3),
            "frequency_hz": round(float(freq), 6),
            "power": round(float(power), 2),
        })
    
    dominant = peaks[0] if peaks else None
    
    # Compute signal-to-noise ratio for dominant peak
    if dominant and len(valid_power) > 1:
        noise_floor = np.median(valid_power)
        snr = dominant["power"] / noise_floor if noise_floor > 0 else float('inf')
    else:
        snr = 0.0
    
    return {
        "dominant_period_s": dominant["period_s"] if dominant else None,
        "dominant_power": dominant["power"] if dominant else None,
        "snr": round(float(snr), 2),
        "top_5_peaks": peaks,
        "n_events": len(timestamps),
        "duration_s": round(float(duration), 1),
        "interpretation": (
            f"FFT dominant period: {dominant['period_s']}s "
            f"(SNR={snr:.1f}x above noise floor)"
            if dominant else "No dominant period found"
        ),
    }


# ============================================================
# 3. Binomial P-value for Timer Clustering
# ============================================================

def binomial_timer_test(intervals: np.ndarray,
                         target_period: float,
                         tolerance: float = 5.0,
                         range_min: float = 10.0,
                         range_max: float = 600.0) -> Dict[str, Any]:
    """
    Test whether intervals cluster around a target period more than chance.
    
    H0: Intervals are uniformly distributed in [range_min, range_max]
    H1: Intervals cluster at target_period ± tolerance
    
    Uses binomial test for statistical significance.
    """
    if len(intervals) < 5:
        return {"error": "insufficient_data"}
    
    # Count successes (intervals within tolerance of target)
    hits = int(np.sum(np.abs(intervals - target_period) <= tolerance))
    n = len(intervals)
    
    # Expected probability under H0 (uniform distribution)
    window = 2 * tolerance
    total_range = range_max - range_min
    p_expected = window / total_range
    
    # Binomial test (scipy >= 1.7 uses binomtest)
    try:
        btest = scipy_stats.binomtest(hits, n, p_expected, alternative='greater')
        p_value = float(btest.pvalue)
    except AttributeError:
        # Fallback for older scipy
        p_value = float(scipy_stats.binom_test(hits, n, p_expected, alternative='greater'))
    
    # Also compute exact binomial probability
    expected_hits = n * p_expected
    
    # Log10 of p-value for extreme values
    if p_value > 1e-300:
        log10_p = float(np.log10(max(p_value, 1e-300)))
    else:
        # p is too small for float64 — use log of survival function
        try:
            log10_p = float(scipy_stats.binom.logsf(hits - 1, n, p_expected) / np.log(10))
        except Exception:
            log10_p = -300.0  # Floor
    
    return {
        "target_period_s": target_period,
        "tolerance_s": tolerance,
        "hits": hits,
        "total_intervals": n,
        "hit_rate": round(hits / n, 4),
        "expected_hit_rate": round(p_expected, 6),
        "expected_hits": round(expected_hits, 2),
        "p_value": p_value,
        "log10_p_value": round(log10_p, 2),
        "significant_at_001": p_value < 0.001,
        "significant_at_0001": p_value < 0.0001,
        "interpretation": (
            f"{hits}/{n} intervals ({hits/n*100:.1f}%) fall within "
            f"{target_period}±{tolerance}s. "
            f"Expected by chance: {expected_hits:.1f} ({p_expected*100:.2f}%). "
            f"p-value: {'< 10^' + str(int(log10_p)) if log10_p < -10 else f'{p_value:.2e}'}. "
            f"{'STATISTICALLY SIGNIFICANT — this pattern does not occur by chance.' if p_value < 0.001 else 'Not significant.'}"
        ),
    }


# ============================================================
# 4. SIB4/SIB5 Neighbor Cell List Analysis  
# ============================================================

def parse_neighbor_lists(pcapng_path: str) -> Dict[str, Any]:
    """
    Extract and analyze SIB4 (intra-freq) and SIB5 (inter-freq) neighbor 
    cell lists from a PCAPNG file.
    
    Empty or minimal neighbor lists are a strong IMSI catcher indicator —
    legitimate cells broadcast the frequencies and PCIs of surrounding cells.
    A rogue cell doesn't know its neighborhood.
    """
    # Extract SIB4 content
    cmd_sib4 = [
        "tshark", "-r", pcapng_path, "-V"
    ]
    
    try:
        result = subprocess.run(cmd_sib4, capture_output=True, text=True, timeout=120)
        full_text = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "tshark_failed"}
    
    # Parse SIB4 intra-frequency neighbor cells
    sib4_neighbors = []
    in_sib4 = False
    for line in full_text.split('\n'):
        if 'SystemInformation [ SIB4' in line or 'sib4' in line.lower():
            in_sib4 = True
        elif in_sib4:
            if 'physCellId:' in line:
                import re
                m = re.search(r'physCellId:\s*(\d+)', line)
                if m:
                    sib4_neighbors.append(int(m.group(1)))
            elif 'SystemInformation' in line or 'Frame ' in line:
                in_sib4 = False
    
    # Parse SIB5 inter-frequency neighbor cells
    sib5_entries = []
    in_sib5 = False
    current_earfcn = None
    for line in full_text.split('\n'):
        if 'SystemInformation [ SIB5' in line or 'sib5' in line.lower():
            in_sib5 = True
        elif in_sib5:
            if 'dl-CarrierFreq:' in line:
                import re
                m = re.search(r'dl-CarrierFreq:\s*(\d+)', line)
                if m:
                    current_earfcn = int(m.group(1))
            elif 'physCellId:' in line and current_earfcn is not None:
                import re
                m = re.search(r'physCellId:\s*(\d+)', line)
                if m:
                    sib5_entries.append({
                        "earfcn": current_earfcn,
                        "pci": int(m.group(1))
                    })
            elif 'SystemInformation' in line or 'Frame ' in line:
                in_sib5 = False
                current_earfcn = None
    
    # Count SIB4 and SIB5 message occurrences
    sib4_count = full_text.count('SystemInformation [ SIB4')
    sib5_count = full_text.count('SystemInformation [ SIB5')
    
    # Unique neighbor PCIs
    unique_sib4_pcis = sorted(set(sib4_neighbors))
    unique_sib5_earfcns = sorted(set(e["earfcn"] for e in sib5_entries))
    
    # Assessment
    if sib4_count == 0 and sib5_count == 0:
        assessment = "NO SIB4/SIB5 broadcasts observed — cannot assess neighbor lists"
    elif len(unique_sib4_pcis) == 0 and len(sib5_entries) == 0:
        assessment = "CRITICAL — Empty neighbor cell lists (both SIB4 and SIB5)"
    elif len(unique_sib4_pcis) <= 1:
        assessment = "SUSPICIOUS — Minimal SIB4 neighbor list (≤1 intra-freq neighbor)"
    else:
        assessment = f"NORMAL — {len(unique_sib4_pcis)} intra-freq, {len(unique_sib5_earfcns)} inter-freq neighbors"
    
    return {
        "sib4_broadcasts": sib4_count,
        "sib5_broadcasts": sib5_count,
        "sib4_unique_neighbor_pcis": unique_sib4_pcis,
        "sib4_neighbor_count": len(unique_sib4_pcis),
        "sib5_entries": sib5_entries[:20],  # Cap for readability
        "sib5_unique_earfcns": unique_sib5_earfcns,
        "sib5_inter_freq_count": len(unique_sib5_earfcns),
        "assessment": assessment,
        "source_file": os.path.basename(pcapng_path),
    }


# ============================================================
# 5. GUTI Reallocation Tracking
# ============================================================

def track_guti_reallocation(pcapng_path: str) -> Dict[str, Any]:
    """
    Track GUTI (Globally Unique Temporary Identity) reallocation events.
    
    In legitimate LTE, the MME periodically reallocates GUTIs to prevent
    tracking. An IMSI catcher typically never reallocates GUTIs because
    it doesn't implement a proper MME.
    
    Zero GUTI reallocations across many connections = strong indicator.
    """
    cmd = [
        "tshark", "-r", pcapng_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "_ws.col.Info",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "tshark_failed"}
    
    guti_realloc_count = 0
    attach_accept_count = 0
    tau_accept_count = 0
    total_connections = 0
    
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        info = line.split('\t', 1)[1] if '\t' in line else line
        info_lower = info.lower()
        
        if 'guti reallocation' in info_lower:
            guti_realloc_count += 1
        if 'attach accept' in info_lower:
            attach_accept_count += 1
        if 'tracking area update accept' in info_lower:
            tau_accept_count += 1
        if 'securitymodecommand' in info_lower.replace(' ', '') and 'complete' not in info_lower:
            total_connections += 1
    
    # Assessment
    if total_connections == 0:
        assessment = "No connections observed"
    elif guti_realloc_count == 0 and total_connections >= 10:
        assessment = (
            f"SUSPICIOUS — Zero GUTI reallocations across {total_connections} "
            f"connections. Legitimate networks periodically reallocate GUTIs "
            f"to prevent subscriber tracking."
        )
    elif guti_realloc_count == 0 and total_connections < 10:
        assessment = "Insufficient data to assess (< 10 connections)"
    else:
        ratio = guti_realloc_count / total_connections
        assessment = f"GUTI reallocation rate: {ratio:.1%} ({guti_realloc_count}/{total_connections})"
    
    return {
        "guti_reallocations": guti_realloc_count,
        "attach_accepts": attach_accept_count,
        "tau_accepts": tau_accept_count,
        "total_connections": total_connections,
        "assessment": assessment,
        "source_file": os.path.basename(pcapng_path),
    }


# ============================================================
# 6. Paging Volume Analysis
# ============================================================

def analyze_paging_volume(pcapng_path: str) -> Dict[str, Any]:
    """
    Count unique m-TMSI values in paging messages as a mass surveillance indicator.
    
    High unique m-TMSI counts suggest either a very busy cell or an IMSI catcher
    paging many devices to enumerate the area.
    """
    cmd = ["tshark", "-r", pcapng_path, "-V"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "tshark_failed"}
    
    import re
    
    tmsi_values = set()
    paging_frame_count = 0
    max_records_per_page = 0
    
    current_paging_records = 0
    for line in result.stdout.split('\n'):
        if 'Paging (' in line and 'PagingRecord' in line:
            m = re.search(r'(\d+) PagingRecord', line)
            if m:
                count = int(m.group(1))
                paging_frame_count += 1
                max_records_per_page = max(max_records_per_page, count)
        
        if 'm-TMSI:' in line:
            m = re.search(r'm-TMSI:\s*([0-9a-f]+)', line)
            if m:
                tmsi_values.add(m.group(1))
    
    # Get session duration
    cmd_time = [
        "tshark", "-r", pcapng_path,
        "-T", "fields", "-e", "frame.time_epoch",
    ]
    try:
        time_result = subprocess.run(cmd_time, capture_output=True, text=True, timeout=60)
        times = [float(l.strip()) for l in time_result.stdout.strip().split('\n') if l.strip()]
        duration = times[-1] - times[0] if len(times) > 1 else 0
    except Exception:
        duration = 0
    
    unique_count = len(tmsi_values)
    pages_per_minute = paging_frame_count / (duration / 60) if duration > 60 else 0
    
    return {
        "unique_m_tmsi": unique_count,
        "paging_frames": paging_frame_count,
        "max_records_per_page": max_records_per_page,
        "duration_s": round(duration, 1),
        "pages_per_minute": round(pages_per_minute, 1),
        "assessment": (
            f"{unique_count} unique m-TMSI values paged over "
            f"{duration/3600:.1f}h ({pages_per_minute:.0f} pages/min). "
            f"Max {max_records_per_page} records in a single paging frame."
        ),
        "source_file": os.path.basename(pcapng_path),
    }


# ============================================================
# Master Analysis Runner
# ============================================================

def extract_release_timestamps(pcapng_path: str) -> np.ndarray:
    """Extract RRCConnectionRelease timestamps from PCAPNG."""
    cmd = [
        "tshark", "-r", pcapng_path,
        "-T", "fields", "-e", "frame.time_epoch", "-e", "_ws.col.Info",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    
    times = []
    for line in result.stdout.strip().split('\n'):
        if 'RRCConnectionRelease' in line:
            parts = line.split('\t')
            try:
                times.append(float(parts[0]))
            except (ValueError, IndexError):
                continue
    return np.array(sorted(times))


def extract_reconfig_timestamps(pcapng_path: str) -> np.ndarray:
    """Extract RRCConnectionReconfiguration timestamps (excluding Complete)."""
    cmd = [
        "tshark", "-r", pcapng_path,
        "-T", "fields", "-e", "frame.time_epoch", "-e", "_ws.col.Info",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    
    times = []
    for line in result.stdout.strip().split('\n'):
        if 'RRCConnectionReconfiguration' in line and 'Complete' not in line:
            parts = line.split('\t')
            try:
                times.append(float(parts[0]))
            except (ValueError, IndexError):
                continue
    return np.array(sorted(times))


def filter_major_intervals(timestamps: np.ndarray, 
                            min_gap: float = 5.0, 
                            max_gap: float = 600.0) -> np.ndarray:
    """Filter intervals to major ones (exclude paired events and overnight gaps)."""
    if len(timestamps) < 2:
        return np.array([])
    deltas = np.diff(timestamps)
    return deltas[(deltas > min_gap) & (deltas < max_gap)]


def run_full_analysis(pcapng_path: str) -> Dict[str, Any]:
    """
    Run the complete advanced analysis suite against a single PCAPNG file.
    """
    filename = os.path.basename(pcapng_path)
    print(f"\n{'='*70}")
    print(f"  ADVANCED FORENSIC ANALYSIS: {filename}")
    print(f"{'='*70}")
    
    results = {"file": filename, "analyses": {}}
    
    # --- Release timing analysis ---
    rel_timestamps = extract_release_timestamps(pcapng_path)
    if len(rel_timestamps) >= 5:
        rel_intervals = filter_major_intervals(rel_timestamps)
        
        if len(rel_intervals) >= 5:
            print(f"\n  [RELEASE TIMING] {len(rel_timestamps)} releases, "
                  f"{len(rel_intervals)} major intervals")
            
            # Autocorrelation
            ac = compute_autocorrelation(rel_intervals)
            results["analyses"]["release_autocorrelation"] = ac
            print(f"    Autocorrelation (lag-1): {ac.get('lag1_autocorrelation', 'N/A')}")
            print(f"    {ac.get('interpretation', '')}")
            
            # FFT
            fft = fft_dominant_period(rel_timestamps)
            results["analyses"]["release_fft"] = fft
            if fft.get("dominant_period_s"):
                print(f"    FFT dominant period: {fft['dominant_period_s']}s "
                      f"(SNR={fft.get('snr', 0):.1f}x)")
            
            # Binomial test — auto-detect target from FFT or mean
            target = fft.get("dominant_period_s") or float(np.mean(rel_intervals))
            binom = binomial_timer_test(rel_intervals, target_period=target)
            results["analyses"]["release_binomial"] = binom
            print(f"    Binomial test: {binom.get('hits', 0)}/{binom.get('total_intervals', 0)} "
                  f"at {target:.1f}±5s")
            print(f"    p-value: 10^{binom.get('log10_p_value', 0):.0f}")
            print(f"    {binom.get('interpretation', '')}")
    else:
        print(f"\n  [RELEASE TIMING] Only {len(rel_timestamps)} releases — skipping")
    
    # --- Reconfiguration timing analysis ---
    reconfig_timestamps = extract_reconfig_timestamps(pcapng_path)
    reconfig_intervals = filter_major_intervals(reconfig_timestamps)
    
    if len(reconfig_intervals) >= 5:
        print(f"\n  [RECONFIG TIMING] {len(reconfig_timestamps)} reconfigs, "
              f"{len(reconfig_intervals)} major intervals")
        
        ac_r = compute_autocorrelation(reconfig_intervals)
        results["analyses"]["reconfig_autocorrelation"] = ac_r
        print(f"    Autocorrelation (lag-1): {ac_r.get('lag1_autocorrelation', 'N/A')}")
        
        fft_r = fft_dominant_period(reconfig_timestamps)
        results["analyses"]["reconfig_fft"] = fft_r
        if fft_r.get("dominant_period_s"):
            print(f"    FFT dominant period: {fft_r['dominant_period_s']}s "
                  f"(SNR={fft_r.get('snr', 0):.1f}x)")
    
    # --- SIB Neighbor lists ---
    print(f"\n  [SIB NEIGHBOR LISTS]")
    neighbors = parse_neighbor_lists(pcapng_path)
    results["analyses"]["neighbor_lists"] = neighbors
    print(f"    SIB4 broadcasts: {neighbors.get('sib4_broadcasts', 0)}, "
          f"unique neighbor PCIs: {neighbors.get('sib4_neighbor_count', 0)}")
    print(f"    SIB5 broadcasts: {neighbors.get('sib5_broadcasts', 0)}, "
          f"inter-freq EARFCNs: {len(neighbors.get('sib5_unique_earfcns', []))}")
    print(f"    {neighbors.get('assessment', '')}")
    
    # --- GUTI reallocation ---
    print(f"\n  [GUTI REALLOCATION]")
    guti = track_guti_reallocation(pcapng_path)
    results["analyses"]["guti_reallocation"] = guti
    print(f"    {guti.get('assessment', '')}")
    
    # --- Paging volume (only for larger captures) ---
    if os.path.getsize(pcapng_path) > 100000:  # Skip tiny files
        print(f"\n  [PAGING VOLUME]")
        paging = analyze_paging_volume(pcapng_path)
        results["analyses"]["paging_volume"] = paging
        print(f"    {paging.get('assessment', '')}")
    
    return results


# ============================================================
# Cross-Session Composite Scoring
# ============================================================

def compute_composite_score(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute a composite score across multiple sessions that weights
    temporal persistence and cross-carrier correlation.
    """
    total_releases = 0
    total_connections = 0
    total_auth = 0
    timer_signatures = defaultdict(list)
    carriers_affected = set()
    
    for r in all_results:
        analyses = r.get("analyses", {})
        
        # Count releases from binomial test data
        binom = analyses.get("release_binomial", {})
        if binom.get("total_intervals"):
            total_releases += binom["total_intervals"]
        
        # Track timer signatures
        fft = analyses.get("release_fft", {})
        if fft.get("dominant_period_s") and fft.get("snr", 0) > 3:
            timer_signatures[round(fft["dominant_period_s"])].append(r["file"])
        
        # Auth tracking
        guti = analyses.get("guti_reallocation", {})
        if guti.get("total_connections"):
            total_connections += guti["total_connections"]
    
    # Score components
    score = 0.0
    components = []
    
    # Timer persistence (same timer across multiple sessions)
    for period, files in timer_signatures.items():
        if len(files) > 1:
            score += 2.0
            components.append(
                f"+2.0: Timer ~{period}s persists across {len(files)} sessions"
            )
    
    # Timer count (more distinct timers = more sophisticated)
    if len(timer_signatures) >= 2:
        score += 1.5
        components.append(
            f"+1.5: {len(timer_signatures)} distinct timer signatures detected"
        )
    
    # Low auth rate
    if total_connections > 0:
        auth_rate = total_auth / total_connections
        if auth_rate < 0.1:
            score += 2.0
            components.append(f"+2.0: Auth rate {auth_rate:.1%} (< 10%)")
    
    # Total volume
    if total_releases > 100:
        score += 1.0
        components.append(f"+1.0: {total_releases}+ catch-and-release cycles")
    
    return {
        "composite_score": round(score, 1),
        "components": components,
        "timer_signatures": {k: v for k, v in timer_signatures.items()},
        "total_releases_analyzed": total_releases,
        "sessions_analyzed": len(all_results),
    }


# ============================================================
# CLI Entry Point
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python advanced_forensics.py <pcapng_file> [pcapng_file2 ...]")
        print("Requires: tshark, numpy, scipy")
        sys.exit(1)
    
    all_results = []
    
    for pcapng_path in sys.argv[1:]:
        if not os.path.exists(pcapng_path):
            print(f"File not found: {pcapng_path}")
            continue
        
        try:
            result = run_full_analysis(pcapng_path)
            all_results.append(result)
        except Exception as e:
            print(f"Error analyzing {pcapng_path}: {e}")
            import traceback
            traceback.print_exc()
    
    # Cross-session composite
    if len(all_results) > 1:
        print(f"\n{'='*70}")
        print(f"  CROSS-SESSION COMPOSITE ANALYSIS ({len(all_results)} sessions)")
        print(f"{'='*70}")
        composite = compute_composite_score(all_results)
        print(f"  Composite score: {composite['composite_score']}")
        for c in composite["components"]:
            print(f"    {c}")
        print(f"  Timer signatures: {composite['timer_signatures']}")
    
    # Save JSON report
    output_path = "advanced_forensic_report.json"
    report = {
        "sessions": all_results,
        "composite": composite if len(all_results) > 1 else None,
    }
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  JSON report saved to: {output_path}")
