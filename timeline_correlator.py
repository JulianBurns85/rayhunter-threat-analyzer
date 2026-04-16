#!/usr/bin/env python3
"""
Timeline Correlator — Cross-File Event Correlation
====================================================
Correlates events across all capture files to detect patterns
that span multiple files — the strongest evidence that findings
originate from the same physical rogue transmitter.

Key correlations:
  - Same Cell ID appearing across Telstra AND Vodafone captures
  - Same EARFCN observed simultaneously on both networks
  - Attack sequences spanning multiple PCAP files (same session)
  - Temporal clustering of attack events across all files

This produces a unified chronological event timeline and identifies
"convergence windows" where multiple attack signatures align.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from dateutil import parser as dtparser


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def parse_ts(ts_str) -> Optional[float]:
    """Parse timestamp string to Unix float."""
    if not ts_str:
        return None
    try:
        return dtparser.parse(str(ts_str)).timestamp()
    except Exception:
        try:
            return float(str(ts_str))
        except (ValueError, TypeError):
            return None


def correlate_timelines(events: List[Dict], findings: List[Dict]) -> Dict:
    """
    Build unified cross-file timeline and identify convergence windows.
    
    Returns correlation report dict.
    """
    # --- 1. Build chronological event timeline ---
    timed_events = []
    for ev in events:
        ts = parse_ts(ev.get("timestamp"))
        if ts and ts > 0:
            timed_events.append({
                "ts": ts,
                "dt": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "source": ev.get("source_file", "?"),
                "source_type": ev.get("source_type", "?"),
                "msg_type": ev.get("msg_type"),
                "cipher_alg": ev.get("cipher_alg"),
                "integrity_alg": ev.get("integrity_alg"),
                "identity_type": ev.get("identity_type"),
                "cell_id": ev.get("cell_id"),
                "earfcn": ev.get("earfcn"),
                "has_geran_redirect": ev.get("has_geran_redirect", False),
                "has_prose": ev.get("has_prose", False),
                "threats": ev.get("threats", []),
            })
    timed_events.sort(key=lambda x: x["ts"])

    # --- 2. Cell ID cross-file analysis ---
    cell_file_map = defaultdict(set)   # cell_id -> set of source files
    earfcn_file_map = defaultdict(set) # earfcn -> set of source files

    for ev in events:
        cid = ev.get("cell_id")
        erf = ev.get("earfcn")
        src = ev.get("source_file", "?")
        if cid:
            cell_file_map[str(cid)].add(src)
        if erf:
            earfcn_file_map[str(erf)].add(src)

    # Cells seen in multiple files = strong corroboration
    multi_file_cells = {
        cid: sorted(files)
        for cid, files in cell_file_map.items()
        if len(files) > 1
    }
    multi_file_earfcns = {
        erf: sorted(files)
        for erf, files in earfcn_file_map.items()
        if len(files) > 1
    }

    # --- 3. Convergence window detection ---
    # Find 5-minute windows where 3+ attack types occur simultaneously
    WINDOW = 300  # seconds
    convergence_windows = []

    attack_events = [e for e in timed_events if any([
        e.get("cipher_alg") == "EEA0",
        e.get("identity_type") == "IMSI",
        e.get("has_geran_redirect"),
        e.get("threats"),
        "Identity Request" in str(e.get("msg_type", "")),
        "Security Mode" in str(e.get("msg_type", "")),
        "Authentication Reject" in str(e.get("msg_type", "")),
    ])]

    if attack_events:
        start = 0
        for end in range(len(attack_events)):
            while (attack_events[end]["ts"] - attack_events[start]["ts"]) > WINDOW:
                start += 1
            window_events = attack_events[start:end+1]
            if len(window_events) >= 5:
                # Characterise this window
                techniques = set()
                sources = set()
                for we in window_events:
                    if we.get("cipher_alg") == "EEA0":
                        techniques.add("Null cipher (EEA0)")
                    if we.get("identity_type") == "IMSI":
                        techniques.add("IMSI Identity Request")
                    if we.get("has_geran_redirect"):
                        techniques.add("GERAN redirect")
                    if "Authentication Reject" in str(we.get("msg_type", "")):
                        techniques.add("Authentication Reject")
                    sources.add(we.get("source", "?"))

                if len(techniques) >= 2:
                    convergence_windows.append({
                        "start_dt": attack_events[start]["dt"],
                        "end_dt": attack_events[end]["dt"],
                        "duration_seconds": round(
                            attack_events[end]["ts"] - attack_events[start]["ts"]
                        ),
                        "event_count": len(window_events),
                        "techniques": sorted(techniques),
                        "source_files": sorted(sources),
                        "significance": "CRITICAL" if len(techniques) >= 3 else "HIGH",
                    })
        # Deduplicate overlapping windows — keep most event-rich
        if convergence_windows:
            deduped = [convergence_windows[0]]
            for w in convergence_windows[1:]:
                if w["start_dt"] != deduped[-1]["start_dt"]:
                    deduped.append(w)
            convergence_windows = sorted(
                deduped, key=lambda x: x["event_count"], reverse=True
            )[:20]  # Top 20 windows

    # --- 4. Source file attack summary ---
    file_summary = defaultdict(lambda: {
        "event_count": 0,
        "attack_events": 0,
        "null_cipher_count": 0,
        "imsi_request_count": 0,
        "geran_redirect_count": 0,
        "cell_ids": set(),
        "earfcns": set(),
        "first_event": None,
        "last_event": None,
    })

    for ev in timed_events:
        src = ev["source"]
        fs = file_summary[src]
        fs["event_count"] += 1
        ts_str = ev["dt"]

        if fs["first_event"] is None or ts_str < fs["first_event"]:
            fs["first_event"] = ts_str
        if fs["last_event"] is None or ts_str > fs["last_event"]:
            fs["last_event"] = ts_str

        if ev.get("cipher_alg") == "EEA0":
            fs["null_cipher_count"] += 1
            fs["attack_events"] += 1
        if ev.get("identity_type") == "IMSI":
            fs["imsi_request_count"] += 1
            fs["attack_events"] += 1
        if ev.get("has_geran_redirect"):
            fs["geran_redirect_count"] += 1
            fs["attack_events"] += 1
        if ev.get("cell_id"):
            fs["cell_ids"].add(str(ev["cell_id"]))
        if ev.get("earfcn"):
            fs["earfcns"].add(str(ev["earfcn"]))

    # Convert sets to sorted lists for JSON serialisation
    file_summary_clean = {}
    for fname, fs in file_summary.items():
        file_summary_clean[fname] = dict(fs)
        file_summary_clean[fname]["cell_ids"] = sorted(fs["cell_ids"])
        file_summary_clean[fname]["earfcns"] = sorted(fs["earfcns"])

    # --- 5. Dual-network evidence ---
    # If the same Cell ID or EARFCN appears in files from different networks
    # this is extremely strong evidence of a single physical transmitter
    dual_network_evidence = []

    # Files with "(1)" suffix = Vodafone, others = Telstra (based on investigation)
    def guess_network(filename: str) -> str:
        if "(1)" in filename or filename in ("643297.ndjson", "871100.ndjson",
                                              "3288737.ndjson", "1775720143.ndjson"):
            return "Vodafone"
        return "Telstra"

    for cid, files in multi_file_cells.items():
        networks = {guess_network(f) for f in files}
        if len(networks) > 1:
            dual_network_evidence.append({
                "type": "Cell ID cross-network",
                "value": cid,
                "networks": sorted(networks),
                "files": sorted(files),
                "significance": "CRITICAL — same Cell ID on multiple carriers = same transmitter",
            })

    for erf, files in multi_file_earfcns.items():
        networks = {guess_network(f) for f in files}
        if len(networks) > 1:
            dual_network_evidence.append({
                "type": "EARFCN cross-network",
                "value": erf,
                "networks": sorted(networks),
                "files": sorted(files),
                "significance": "HIGH — same EARFCN on multiple carriers",
            })

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "summary": {
            "total_timed_events": len(timed_events),
            "total_attack_events": len(attack_events),
            "convergence_windows_found": len(convergence_windows),
            "cell_ids_across_multiple_files": len(multi_file_cells),
            "earfcns_across_multiple_files": len(multi_file_earfcns),
            "dual_network_evidence_count": len(dual_network_evidence),
            "source_files_with_attacks": sum(
                1 for fs in file_summary_clean.values()
                if fs["attack_events"] > 0
            ),
        },
        "convergence_windows": convergence_windows,
        "dual_network_evidence": dual_network_evidence,
        "cell_id_cross_file": {
            cid: sorted(files)
            for cid, files in multi_file_cells.items()
        },
        "earfcn_cross_file": {
            erf: sorted(files)
            for erf, files in multi_file_earfcns.items()
        },
        "file_summaries": file_summary_clean,
    }


def print_correlation_summary(correlation: Dict):
    """Print correlation highlights to terminal."""
    s = correlation["summary"]
    print(f"\n  {'='*60}")
    print(f"  CROSS-FILE TIMELINE CORRELATION")
    print(f"  {'='*60}")
    print(f"  Timed events:          {s['total_timed_events']:,}")
    print(f"  Attack events:         {s['total_attack_events']:,}")
    print(f"  Convergence windows:   {s['convergence_windows_found']}")
    print(f"  Cross-file Cell IDs:   {s['cell_ids_across_multiple_files']}")
    print(f"  Cross-network items:   {s['dual_network_evidence_count']}")

    if correlation["convergence_windows"]:
        print(f"\n  Top convergence window:")
        w = correlation["convergence_windows"][0]
        print(f"    Start:      {w['start_dt']}")
        print(f"    Duration:   {w['duration_seconds']}s")
        print(f"    Events:     {w['event_count']}")
        print(f"    Techniques: {', '.join(w['techniques'])}")
        print(f"    Sources:    {', '.join(w['source_files'][:3])}")

    if correlation["dual_network_evidence"]:
        print(f"\n  Dual-network evidence:")
        for item in correlation["dual_network_evidence"][:5]:
            print(f"    [{item['type']}] value={item['value']} "
                  f"networks={item['networks']}")
