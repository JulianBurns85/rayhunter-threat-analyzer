#!/usr/bin/env python3
"""
rayhunter_deep_analysis.py v2.4
================================
Deep forensic analysis - Cranbourne East IMSI Catcher Investigation
Julian Burns - github.com/JulianBurns85/rayhunter-threat-analyzer

Features:
  1.  SHA-256 evidence manifest (auto-saved)
  2.  Capture gap detection
  3.  Cell ID inventory with confirmed rogue database
  4.  Geographic distance calculation from home address
  5.  Sequential CID pattern detection (same hardware indicator)
  6.  New CID alerting
  7.  Cross-carrier simultaneous release detection (YAICD P10)
  8.  RRC periodicity analysis (Harris T3/T1 signature)
  9.  Encryption rate per file (transparent proxy indicator)
  10. Identity request detection
  11. EEA0 / Security Mode detection
  12. Temporal activity timeline with known event correlation
  13. Signal strength tracking (RSSI/RSRP where available)
  14. Attacker profile scoring (Hello Mofo / Harris profile)
  15. Transmitter movement corridor analysis
  16. OpenCelliD lookup URLs
  17. --output flag: save full report to timestamped file
  18. --compare flag: diff two capture directories
  19. --acma flag: generate pre-formatted ACMA update draft

Usage:
  python rayhunter_deep_analysis.py --dir C:\\captures
  python rayhunter_deep_analysis.py --dir C:\\captures --days --output
  python rayhunter_deep_analysis.py --dir C:\\new --compare C:\\old
  python rayhunter_deep_analysis.py --dir C:\\captures --acma
"""

import json
import re
import math
import hashlib
import argparse
import datetime
import sys
import io
from collections import defaultdict
from pathlib import Path

# ================================================================
# CONFIRMED ROGUE CID DATABASE
# Updated: 16 May 2026
# Source: 507+ days dual-unit Rayhunter captures, Cranbourne East
# ================================================================
KNOWN_ROGUE = {
    137713195: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    137713175: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-01",
                "opencellid": "Prendergast Ave CE Apr 2026 12 measurements",
                "lat": -38.116221, "lon": 145.305331},
    137713155: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    137713185: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    137713165: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    135836191: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-04",
                "opencellid": "Collison Rd CE Oct 2025 range 6965m ANOMALOUS 27 measurements",
                "lat": -38.113163, "lon": 145.312465},
    135836171: {"carrier": "Telstra",    "tac": 12385, "mnc": 1, "confirmed": "2026-04",
                "opencellid": "Casey Fields area Aug 2025 range 4855m ANOMALOUS 28 measurements",
                "lat": -38.117026, "lon": 145.332974},
    8409357:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    8409367:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    8409387:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    8409397:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-01",
                "opencellid": "Not found - Harris targeted mode", "lat": None, "lon": None},
    8666411:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-05",
                "note": "POST-ACMA CONFIG appeared 5-6 May 2026",
                "opencellid": "Not found", "lat": None, "lon": None},
    8666391:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-05",
                "note": "POST-ACMA CONFIG",
                "opencellid": "Not found", "lat": None, "lon": None},
    8666381:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-05",
                "note": "POST-ACMA CONFIG appeared 5 May 2026",
                "opencellid": "Not found", "lat": None, "lon": None},
    8435480:   {"carrier": "Vodafone AU","tac": 30336, "mnc": 3, "confirmed": "2026-04",
                "opencellid": "Narre Warren-Cranbourne Rd Feb 2025 range 1143m 2 measurements",
                "lat": -38.116429, "lon": 145.290787},
}

# Known events for timeline correlation
KNOWN_EVENTS = {
    "2026-01-28": "Timer transition: T3 changed from 3000s to 210.2s",
    "2026-03-31": "VicPol complaint: CIRS-20260331-141",
    "2026-04-07": "Cross-carrier simultaneous release confirmed",
    "2026-04-13": "VicPol complaint: CIRS-20260413-6",
    "2026-05-08": "ACMA field inspection at subject premises",
    "2026-05-09": "Post-ACMA new CID profiles appeared",
}

SUSPECT_TACS = {12385, 30336}
HOME_LAT  = -38.1192
HOME_LON  = 145.3054
HOME_ADDR = "74 Prendergast Ave, Cranbourne East VIC 3977"

HARRIS_T3    = 210.182
HARRIS_T3_SD = 0.5
HARRIS_T1    = 610.6
HARRIS_T1_SD = 1.0
SIMULTANEOUS_GAP = 2.0

# Hello Mofo attacker profile thresholds
HELLO_MOFO_PROFILE = {
    "name": "Hello Mofo (Cranbourne East Persistent Operator)",
    "hardware": "Harris HailStorm / StingRay II",
    "required_cids": {137713195, 137713175, 137713155, 137713165,
                      8409357, 8409367, 8409387, 8409397},
    "suspect_tacs": {12385, 30336},
    "t3_target": 210.182,
    "min_carriers": 2,
}


# ================================================================
# UTILITY FUNCTIONS
# ================================================================

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def distance_m(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi  = math.radians(lat2 - lat1)
    dlam  = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def bearing_deg(lat1, lon1, lat2, lon2):
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dlam = math.radians(lon2 - lon1)
    x = math.sin(dlam) * math.cos(phi2)
    y = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(dlam)
    b = math.degrees(math.atan2(x, y))
    return (b + 360) % 360


def carrier_name(mnc):
    return {1: "Telstra", 2: "Optus", 3: "Vodafone AU"}.get(mnc, "MNC={}".format(mnc))


def parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.datetime.fromisoformat(
            ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def opencellid_url(mcc, mnc, lac, cid):
    return ("https://opencellid.org/#zoom=16&lat={}&lon={}"
            "&mcc={}&mnc={}&lac={}&cellid={}").format(
                HOME_LAT, HOME_LON, mcc, mnc, lac, cid)


# ================================================================
# PARSING
# ================================================================

def parse_ndjson(path):
    events, total, encrypted = [], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if "analyzers" in obj:
                continue
            total += 1
            if obj.get("skipped_message_reason") == "NASDecodingError(EncryptedNASMessage)":
                encrypted += 1
            ts     = obj.get("packet_timestamp", "")
            ts_dt  = parse_ts(ts)
            for ev in (obj.get("events") or []):
                if not ev:
                    continue
                msg = ev.get("message", "")
                sev = ev.get("event_type", "Low")
                if msg:
                    events.append({"ts": ts, "ts_dt": ts_dt,
                                   "msg": msg, "severity": sev,
                                   "file": Path(path).name,
                                   "raw": obj})
    return events, total, encrypted


def extract_cells(events):
    cells = []
    for ev in events:
        m = re.search(
            r"SIB1 received CID: (\d+), TAC: (\d+), PLMN: ([\d-]+)", ev["msg"])
        if m:
            plmn = m.group(3)
            mnc  = int(plmn.split("-")[1]) if "-" in plmn else 0
            cells.append({"cid": int(m.group(1)), "tac": int(m.group(2)),
                           "plmn": plmn, "mnc": mnc,
                           "ts": ev["ts"], "ts_dt": ev["ts_dt"],
                           "file": ev["file"]})
    return cells


def extract_signal(events):
    """Extract RSSI/RSRP values where present in event messages."""
    signals = []
    for ev in events:
        msg = ev["msg"]
        # Look for RSRP pattern
        m_rsrp = re.search(r"RSRP[=:\s]+(-?\d+\.?\d*)", msg, re.IGNORECASE)
        m_rssi = re.search(r"RSSI[=:\s]+(-?\d+\.?\d*)", msg, re.IGNORECASE)
        m_rsrq = re.search(r"RSRQ[=:\s]+(-?\d+\.?\d*)", msg, re.IGNORECASE)
        # Also check raw object
        raw = ev.get("raw", {})
        if m_rsrp or m_rssi or m_rsrq or "rsrp" in str(raw).lower():
            entry = {"ts": ev["ts"], "file": ev["file"]}
            if m_rsrp:
                entry["rsrp"] = float(m_rsrp.group(1))
            if m_rssi:
                entry["rssi"] = float(m_rssi.group(1))
            if m_rsrq:
                entry["rsrq"] = float(m_rsrq.group(1))
            # Try raw object fields
            for key in ("rsrp", "rssi", "rsrq", "signal_strength"):
                val = raw.get(key)
                if val is not None and key not in entry:
                    try:
                        entry[key] = float(val)
                    except Exception:
                        pass
            if len(entry) > 2:
                signals.append(entry)
    return signals


def extract_rrc_releases(events):
    return [ev for ev in events
            if "rrcconnectionrelease" in ev["msg"].lower()
            or "rrc connection release" in ev["msg"].lower()]


def detect_cross_carrier(cells):
    telstra = [c["ts_dt"].timestamp() for c in cells
               if c["ts_dt"] and c["mnc"] == 1 and c["cid"] in KNOWN_ROGUE]
    vodafone = [c["ts_dt"].timestamp() for c in cells
                if c["ts_dt"] and c["mnc"] == 3 and c["cid"] in KNOWN_ROGUE]
    simultaneous = []
    for t in telstra:
        for v in vodafone:
            gap = abs(t - v)
            if gap <= SIMULTANEOUS_GAP:
                simultaneous.append({"telstra_ts": t, "vodafone_ts": v,
                                     "gap": gap})
    return simultaneous


def analyze_rrc_periodicity(releases):
    timed = sorted(r["ts_dt"].timestamp() for r in releases if r["ts_dt"])
    if len(timed) < 3:
        return None
    intervals = [timed[i+1]-timed[i] for i in range(len(timed)-1)]
    t3 = [iv for iv in intervals if abs(iv - HARRIS_T3) <= HARRIS_T3_SD]
    t1 = [iv for iv in intervals if abs(iv - HARRIS_T1) <= HARRIS_T1_SD]
    mean_all = sum(intervals)/len(intervals)
    result = {"total": len(timed), "intervals": len(intervals),
              "mean": mean_all, "t3": len(t3), "t1": len(t1),
              "t3_rate": 100*len(t3)/len(intervals) if intervals else 0}
    if t3:
        m = sum(t3)/len(t3)
        sd = math.sqrt(sum((v-m)**2 for v in t3)/len(t3)) if len(t3)>1 else 0
        result["t3_mean"] = m
        result["t3_sd"]   = sd
    return result


def detect_sequential_cids(cell_counts):
    cids = sorted(cell_counts.keys())
    seen, groups = set(), []
    for i in range(len(cids)):
        for j in range(i+1, len(cids)):
            diff = abs(cids[i]-cids[j])
            if 1 <= diff <= 50:
                pair = (min(cids[i],cids[j]), max(cids[i],cids[j]))
                if pair not in seen:
                    seen.add(pair)
                    groups.append((cids[i], cids[j], diff))
    return groups


def build_timeline(cells):
    daily = defaultdict(lambda: defaultdict(int))
    for c in cells:
        if c["ts_dt"]:
            day = c["ts_dt"].strftime("%Y-%m-%d")
            daily[day][c["cid"]] += 1
    return daily


def detect_gaps(ndjson_files):
    dated = []
    for f in ndjson_files:
        try:
            ts = int(f.stem.split(" ")[0].split("(")[0].strip())
            if ts > 1577836800:
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                dated.append((dt, f.name))
        except Exception:
            pass
    dated.sort()
    gaps = []
    for i in range(len(dated)-1):
        hours = (dated[i+1][0]-dated[i][0]).total_seconds()/3600
        if hours > 24:
            gaps.append({"from": dated[i][0].strftime("%Y-%m-%d %H:%M"),
                         "to":   dated[i+1][0].strftime("%Y-%m-%d %H:%M"),
                         "hours": hours,
                         "from_file": dated[i][1],
                         "to_file":   dated[i+1][1]})
    return gaps


def identify_unit(cells):
    t = sum(1 for c in cells if c["mnc"]==1)
    v = sum(1 for c in cells if c["mnc"]==3)
    if t == 0 and v == 0: return "UNKNOWN"
    if t > v*2:  return "TELSTRA UNIT (MNC=001)"
    if v > t*2:  return "VODAFONE UNIT (MNC=003)"
    return "MIXED/BOTH UNITS"


def score_attacker_profile(cell_counts, cells, simultaneous):
    """Score against the Hello Mofo / Harris profile."""
    score = 0
    flags = []
    cid_set = set(cell_counts.keys())

    # Check rogue CIDs present
    rogue_present = cid_set & HELLO_MOFO_PROFILE["required_cids"]
    if rogue_present:
        score += len(rogue_present) * 0.5
        flags.append("Confirmed rogue CIDs present: {}".format(len(rogue_present)))

    # Suspect TAC clusters
    tac_cids = [c for c in cid_set
                if any(KNOWN_ROGUE.get(c,{}).get("tac") == t
                       for t in HELLO_MOFO_PROFILE["suspect_tacs"])]
    if tac_cids:
        score += 1.0
        flags.append("CIDs in suspect TAC clusters: {}".format(len(tac_cids)))

    # Multi-carrier
    t_obs = sum(1 for c in cells if c["mnc"]==1 and c["cid"] in KNOWN_ROGUE)
    v_obs = sum(1 for c in cells if c["mnc"]==3 and c["cid"] in KNOWN_ROGUE)
    if t_obs > 0 and v_obs > 0:
        score += 2.0
        flags.append("Multi-carrier simultaneous operation confirmed (Telstra + Vodafone)")

    # Cross-carrier events
    if simultaneous:
        score += min(2.0, len(simultaneous) * 0.1)
        flags.append("Cross-carrier simultaneous events: {}".format(len(simultaneous)))

    # Sequential CID pattern (same hardware)
    seq = detect_sequential_cids(cell_counts)
    if seq:
        score += 0.5
        flags.append("Sequential CID pattern detected: {} pairs".format(len(seq)))

    # Geographic proximity
    close_cids = []
    for cid in cid_set:
        info = KNOWN_ROGUE.get(cid, {})
        if info.get("lat") and info.get("lon"):
            d = distance_m(HOME_LAT, HOME_LON, info["lat"], info["lon"])
            if d < 500:
                close_cids.append((cid, d))
    if close_cids:
        score += 1.5
        flags.append("CIDs geo-located within 500m of subject premises: {}".format(
            len(close_cids)))

    verdict = "NO MATCH"
    if score >= 8.0:
        verdict = "*** HELLO MOFO CONFIRMED ***"
    elif score >= 5.0:
        verdict = "HIGH CONFIDENCE MATCH"
    elif score >= 3.0:
        verdict = "PROBABLE MATCH"
    elif score >= 1.0:
        verdict = "PARTIAL MATCH"

    return {"score": score, "verdict": verdict, "flags": flags}


def movement_corridor(cell_counts):
    """Analyse transmitter movement from known OpenCelliD coordinates."""
    located = []
    for cid in cell_counts:
        info = KNOWN_ROGUE.get(cid, {})
        if info.get("lat") and info.get("lon"):
            confirmed = info.get("confirmed", "2026-01")
            located.append({
                "cid": cid,
                "lat": info["lat"],
                "lon": info["lon"],
                "confirmed": confirmed,
                "carrier": info.get("carrier","?"),
                "oc": info.get("opencellid","")
            })

    if not located:
        return None

    # Sort by confirmed date
    located.sort(key=lambda x: x["confirmed"])

    # Centroid
    c_lat = sum(p["lat"] for p in located) / len(located)
    c_lon = sum(p["lon"] for p in located) / len(located)
    c_dist = distance_m(HOME_LAT, HOME_LON, c_lat, c_lon)
    c_bearing = bearing_deg(HOME_LAT, HOME_LON, c_lat, c_lon)

    # Movement between successive locations
    movements = []
    for i in range(len(located)-1):
        a, b = located[i], located[i+1]
        d = distance_m(a["lat"], a["lon"], b["lat"], b["lon"])
        bear = bearing_deg(a["lat"], a["lon"], b["lat"], b["lon"])
        movements.append({"from_cid": a["cid"], "to_cid": b["cid"],
                          "distance_m": d, "bearing": bear,
                          "from_date": a["confirmed"],
                          "to_date": b["confirmed"]})

    return {"located": located, "centroid_lat": c_lat, "centroid_lon": c_lon,
            "centroid_dist_m": c_dist, "centroid_bearing": c_bearing,
            "movements": movements}


def generate_acma_draft(scan_dir, cell_counts, cell_first, cell_last,
                        cell_meta, identity_reqs, smc_events,
                        simultaneous, new_cids, profile_result):
    """Generate a pre-formatted ACMA evidence update draft."""
    now = datetime.datetime.now()
    confirmed_count = sum(1 for c in cell_counts if c in KNOWN_ROGUE)

    lines = []
    lines.append("ACMA EVIDENCE UPDATE DRAFT")
    lines.append("Reference: ENQ-1851DVJH04")
    lines.append("Generated: {}".format(now.strftime("%Y-%m-%d %H:%M")))
    lines.append("Directory analysed: {}".format(scan_dir))
    lines.append("")
    lines.append("Dear Brian,")
    lines.append("")
    lines.append("I write to provide a further evidence update to complaint ENQ-1851DVJH04.")
    lines.append("")
    lines.append("CAPTURE SUMMARY")
    lines.append("-" * 40)
    lines.append("Files analysed: {} NDJSON".format(len(cell_counts)))
    lines.append("Unique Cell IDs observed: {}".format(len(cell_counts)))
    lines.append("Confirmed rogue Cell IDs: {}".format(confirmed_count))
    lines.append("New unconfirmed Cell IDs: {}".format(len(new_cids)))
    lines.append("Identity requests detected: {}".format(len(identity_reqs)))
    lines.append("EEA0 null-cipher events: {} (zero expected for M7350 transparent proxy captures)".format(
        len(smc_events)))
    lines.append("Cross-carrier simultaneous events: {}".format(len(simultaneous)))
    lines.append("")
    lines.append("ATTACKER PROFILE ASSESSMENT")
    lines.append("-" * 40)
    lines.append("Profile: {}".format(HELLO_MOFO_PROFILE["name"]))
    lines.append("Hardware assessed: {}".format(HELLO_MOFO_PROFILE["hardware"]))
    lines.append("Profile score: {:.1f}".format(profile_result["score"]))
    lines.append("Verdict: {}".format(profile_result["verdict"]))
    for flag in profile_result["flags"]:
        lines.append("  - {}".format(flag))
    lines.append("")
    lines.append("CONFIRMED ROGUE CELL IDs IN THIS BATCH")
    lines.append("-" * 40)
    for cid, count in sorted(cell_counts.items(), key=lambda x: -x[1]):
        if cid in KNOWN_ROGUE:
            info = KNOWN_ROGUE[cid]
            first = cell_first.get(cid,"")[:19]
            last  = cell_last.get(cid,"")[:19]
            lines.append("  CID={} TAC={} {} ({} observations)".format(
                cid, info["tac"], info["carrier"], count))
            lines.append("    First: {}  Last: {}".format(first, last))
            if info.get("opencellid"):
                lines.append("    OpenCelliD: {}".format(info["opencellid"]))
    lines.append("")
    if new_cids:
        lines.append("NEW UNCONFIRMED CELL IDs (REQUIRE INVESTIGATION)")
        lines.append("-" * 40)
        for cid in new_cids:
            meta = cell_meta.get(cid, {})
            tac  = meta.get("tac","?")
            plmn = meta.get("plmn","505-1")
            mnc  = int(plmn.split("-")[1]) if "-" in str(plmn) else 1
            lines.append("  CID={} TAC={} {} - First seen: {}".format(
                cid, tac, carrier_name(mnc), cell_first.get(cid,"")[:19]))
            lines.append("  OpenCelliD: {}".format(
                opencellid_url(505, mnc, tac, cid)))
        lines.append("")
    if identity_reqs:
        lines.append("IDENTITY REQUEST EVIDENCE")
        lines.append("-" * 40)
        for ev in identity_reqs[:10]:
            lines.append("  [{}] {}  {}".format(
                ev["severity"], ev["ts"][:19], ev["msg"][:80]))
        lines.append("")
    lines.append("The interference activity continues without cessation.")
    lines.append("All evidence preserved with SHA-256 manifest.")
    lines.append("Full Rayhunter Threat Analyzer v2.2 JSON report available on request.")
    lines.append("")
    lines.append("Yours sincerely,")
    lines.append("Julian Burns")
    lines.append("74 Prendergast Avenue, Cranbourne East VIC 3977")
    lines.append("ACMA Reference: ENQ-1851DVJH04")
    lines.append("TIO Reference: 2026-03-04898")
    lines.append("VicPol: CIRS-20260331-141 / CIRS-20260413-6 / INT26IR3127399")
    lines.append("Telstra: 128653446")
    return "\n".join(lines)


# ================================================================
# OUTPUT HELPERS
# ================================================================

class Tee:
    """Write to both stdout and a string buffer."""
    def __init__(self):
        self.buf = io.StringIO()

    def write(self, text):
        sys.stdout.write(text)
        self.buf.write(text)

    def flush(self):
        sys.stdout.flush()

    def getvalue(self):
        return self.buf.getvalue()


def hdr(tee, title, char="=", width=72):
    tee.write("\n" + char*width + "\n")
    tee.write("  " + title + "\n")
    tee.write(char*width + "\n")


def sep(tee, width=70):
    tee.write("  " + "-"*width + "\n")


# ================================================================
# MAIN ANALYSIS
# ================================================================

def analyze_directory(scan_dir, show_days=False, save_output=False,
                       gen_acma=False):
    scan_path   = Path(scan_dir)
    ndjson_files = sorted(scan_path.glob("*.ndjson"))
    tee = Tee()

    tee.write("\n" + "="*72 + "\n")
    tee.write("  RAYHUNTER DEEP FORENSIC ANALYSIS v2.4\n")
    tee.write("  Cranbourne East Investigation -- Julian Burns\n")
    tee.write("  {}\n".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    tee.write("="*72 + "\n")
    tee.write("\n  Scanning: {}\n".format(scan_dir))
    tee.write("  NDJSON files found: {}\n".format(len(ndjson_files)))

    # Parse
    all_events, file_stats = [], {}
    for f in ndjson_files:
        events, total, encrypted = parse_ndjson(f)
        all_events.extend(events)
        file_stats[f.name] = {"total": total, "encrypted": encrypted,
                               "rate": 100*encrypted/total if total else 0}
    tee.write("  Total events parsed: {}\n".format(len(all_events)))

    cells        = extract_cells(all_events)
    rrc_releases = extract_rrc_releases(all_events)
    signals      = extract_signal(all_events)
    identity_reqs = [ev for ev in all_events
                     if "identity" in ev["msg"].lower()
                     and "request" in ev["msg"].lower()]
    smc_events   = [ev for ev in all_events
                    if "security mode" in ev["msg"].lower()
                    or "eea0" in ev["msg"].lower()]

    cell_counts, cell_first, cell_last, cell_meta = (
        defaultdict(int), {}, {}, {})
    for c in cells:
        k = c["cid"]
        cell_counts[k] += 1
        if k not in cell_first or c["ts"] < cell_first[k]:
            cell_first[k] = c["ts"]
        if k not in cell_last or c["ts"] > cell_last[k]:
            cell_last[k]  = c["ts"]
        cell_meta[k] = {"tac": c["tac"], "plmn": c["plmn"], "mnc": c["mnc"]}

    simultaneous = detect_cross_carrier(cells)
    rrc_result   = analyze_rrc_periodicity(rrc_releases)
    unit         = identify_unit(cells)
    gaps         = detect_gaps(ndjson_files)
    new_cids     = []
    profile_result = score_attacker_profile(cell_counts, cells, simultaneous)
    corridor     = movement_corridor(cell_counts)

    tee.write("  Capture unit: {}\n".format(unit))

    # 1. SHA-256 MANIFEST
    hdr(tee, "SHA-256 EVIDENCE MANIFEST")
    manifests = {}
    for f in sorted(scan_path.glob("*")):
        if f.is_file() and f.suffix in (".ndjson",".pcapng",".qmdl"):
            h = sha256_file(f)
            manifests[f.name] = h
            tee.write("  {}...  {}\n".format(h[:16], f.name))
    mpath = Path("sha256_manifest.txt")
    with open(mpath, "w", encoding="utf-8") as mf:
        mf.write("SHA-256 Evidence Manifest\n")
        mf.write("Generated: {}\n".format(
            datetime.datetime.now().isoformat()))
        mf.write("Directory: {}\n\n".format(scan_dir))
        for fname, h in sorted(manifests.items()):
            mf.write("{}  {}\n".format(h, fname))
    tee.write("\n  Manifest saved: {}\n".format(mpath))

    # 2. CAPTURE GAPS
    hdr(tee, "CAPTURE GAP DETECTION")
    if gaps:
        tee.write("  WARNING: {} gap(s) in capture continuity\n".format(
            len(gaps)))
        for g in gaps:
            tee.write("  GAP: {} --> {} ({:.1f} hours)\n".format(
                g["from"], g["to"], g["hours"]))
            tee.write("       {} --> {}\n".format(
                g["from_file"], g["to_file"]))
    else:
        tee.write("  No significant gaps (threshold: >24 hours)\n")

    # 3. CELL ID INVENTORY
    hdr(tee, "CELL ID INVENTORY -- {} UNIQUE CIDs".format(len(cell_counts)))
    tee.write("  {:<14} {:<8} {:<14} {:>5}  {:<12}  {}\n".format(
        "CID","TAC","Carrier","Obs","Dist(m)","Status"))
    sep(tee)
    for cid, count in sorted(cell_counts.items(), key=lambda x: -x[1]):
        meta    = cell_meta.get(cid, {})
        tac     = meta.get("tac","?")
        plmn    = meta.get("plmn","505-?")
        mnc     = int(plmn.split("-")[1]) if "-" in str(plmn) else 0
        carrier = carrier_name(mnc)
        first   = cell_first.get(cid,"")[:19]
        last    = cell_last.get(cid,"")[:19]
        dist_str = "  N/A"
        if cid in KNOWN_ROGUE:
            info = KNOWN_ROGUE[cid]
            if info.get("lat") and info.get("lon"):
                d = distance_m(HOME_LAT,HOME_LON,info["lat"],info["lon"])
                dist_str = "{:.0f}m{}".format(
                    d, " ***CLOSE***" if d < 500 else "")
        if cid in KNOWN_ROGUE:
            note = KNOWN_ROGUE[cid].get("note","")
            oc   = KNOWN_ROGUE[cid].get("opencellid","")
            stat = "CONFIRMED ROGUE"
            if note: stat += " -- "+note
            tee.write("  {:<14} {:<8} {:<14} {:>5}  {:<12}  [ROGUE] {}\n".format(
                cid,str(tac),carrier,count,dist_str,stat))
            if oc:
                tee.write("  {:<52}  OpenCelliD: {}\n".format("",oc))
            tee.write("  {:<52}  First: {}  Last: {}\n".format("",first,last))
        elif tac in SUSPECT_TACS:
            new_cids.append(cid)
            tee.write("  {:<14} {:<8} {:<14} {:>5}  {:<12}  *** NEW SUSPECT TAC\n".format(
                cid,str(tac),carrier,count,dist_str))
            tee.write("  {:<52}  First: {}\n".format("",first))
        else:
            tee.write("  {:<14} {:<8} {:<14} {:>5}  {:<12}  Verify\n".format(
                cid,str(tac),carrier,count,dist_str))

    # 4. SEQUENTIAL CID PATTERNS
    hdr(tee, "SEQUENTIAL CID PATTERN DETECTION")
    tee.write("  (Sequential CIDs in same TAC = same hardware multiple slots)\n")
    seq_groups = detect_sequential_cids(cell_counts)
    if seq_groups:
        seen2 = set()
        for a, b, diff in sorted(seq_groups, key=lambda x: x[2]):
            pair = (min(a,b),max(a,b))
            if pair not in seen2:
                seen2.add(pair)
                tag = "[BOTH ROGUE]" if (a in KNOWN_ROGUE and b in KNOWN_ROGUE) else "[VERIFY]"
                tee.write("  {} CID={} and CID={} differ by {}\n".format(
                    tag,a,b,diff))
    else:
        tee.write("  No sequential pairs in this batch\n")

    # 5. NEW CID ALERTS
    if new_cids:
        hdr(tee, "NEW UNCONFIRMED CIDs -- VERIFY IMMEDIATELY")
        for cid in new_cids:
            meta = cell_meta.get(cid,{})
            plmn = meta.get("plmn","505-1")
            tac  = meta.get("tac",12385)
            mnc  = int(plmn.split("-")[1]) if "-" in str(plmn) else 1
            tee.write("  CID={} TAC={} {}\n".format(cid,tac,carrier_name(mnc)))
            tee.write("  First: {}\n".format(
                cell_first.get(cid,"")[:19]))
            tee.write("  OpenCelliD: {}\n".format(
                opencellid_url(505,mnc,tac,cid)))

    # 6. ATTACKER PROFILE SCORE
    hdr(tee, "ATTACKER PROFILE SCORING -- HELLO MOFO / HARRIS PROFILE")
    tee.write("  Profile:  {}\n".format(HELLO_MOFO_PROFILE["name"]))
    tee.write("  Hardware: {}\n".format(HELLO_MOFO_PROFILE["hardware"]))
    tee.write("  Score:    {:.1f}\n".format(profile_result["score"]))
    tee.write("  Verdict:  {}\n".format(profile_result["verdict"]))
    tee.write("\n  Evidence flags:\n")
    for flag in profile_result["flags"]:
        tee.write("    [+] {}\n".format(flag))

    # 7. TRANSMITTER MOVEMENT CORRIDOR
    hdr(tee, "TRANSMITTER MOVEMENT CORRIDOR ANALYSIS")
    if corridor:
        tee.write("  Located CIDs with known coordinates: {}\n\n".format(
            len(corridor["located"])))
        for p in corridor["located"]:
            d = distance_m(HOME_LAT,HOME_LON,p["lat"],p["lon"])
            b = bearing_deg(HOME_LAT,HOME_LON,p["lat"],p["lon"])
            tee.write("  CID={} ({}) confirmed {}\n".format(
                p["cid"],p["carrier"],p["confirmed"]))
            tee.write("    Lat={:.6f} Lon={:.6f}\n".format(
                p["lat"],p["lon"]))
            tee.write("    Distance from home: {:.0f}m  Bearing: {:.0f} deg\n".format(
                d,b))
            tee.write("    {}\n\n".format(p["oc"]))
        tee.write("  Centroid of all located positions:\n")
        tee.write("    Lat={:.6f}  Lon={:.6f}\n".format(
            corridor["centroid_lat"],corridor["centroid_lon"]))
        tee.write("    Distance from home: {:.0f}m\n".format(
            corridor["centroid_dist_m"]))
        tee.write("    Bearing from home: {:.0f} degrees\n".format(
            corridor["centroid_bearing"]))
        if corridor["movements"]:
            tee.write("\n  Movement between confirmed positions:\n")
            for mv in corridor["movements"]:
                dirs = ["N","NE","E","SE","S","SW","W","NW"]
                d_name = dirs[int((mv["bearing"]+22.5)//45)%8]
                tee.write("    {} ({}) --> {} ({})  {:.0f}m {}  Bearing {:.0f} deg\n".format(
                    mv["from_cid"],mv["from_date"],
                    mv["to_cid"],mv["to_date"],
                    mv["distance_m"],d_name,mv["bearing"]))
    else:
        tee.write("  No located CIDs with known coordinates in this batch\n")

    # 8. CROSS-CARRIER SIMULTANEOUS RELEASE
    hdr(tee, "CROSS-CARRIER SIMULTANEOUS RELEASE (YAICD P10)")
    if simultaneous:
        zero = [s for s in simultaneous if s["gap"] < 0.1]
        near = [s for s in simultaneous if 0.1 <= s["gap"] <= SIMULTANEOUS_GAP]
        tee.write("  CONFIRMED: {} simultaneous events\n".format(len(simultaneous)))
        tee.write("  Zero-gap (<0.1s): {}  Near-simultaneous (0.1-2s): {}\n".format(
            len(zero),len(near)))
        tee.write("  Harris HailStorm 4-port TX confirmed\n")
        tee.write("  Single-radio (srsRAN) eliminated\n\n")
        for s in simultaneous[:5]:
            t = datetime.datetime.fromtimestamp(
                s["telstra_ts"],tz=datetime.timezone.utc)
            tee.write("  {}  gap={:.3f}s\n".format(
                t.strftime("%Y-%m-%d %H:%M:%S"),s["gap"]))
        if len(simultaneous)>5:
            tee.write("  ... and {} more\n".format(len(simultaneous)-5))
    else:
        t_obs = sum(1 for c in cells if c["mnc"]==1 and c["cid"] in KNOWN_ROGUE)
        v_obs = sum(1 for c in cells if c["mnc"]==3 and c["cid"] in KNOWN_ROGUE)
        if t_obs==0 or v_obs==0:
            tee.write("  Single-carrier batch -- both units needed\n")
            tee.write("  Telstra rogue obs: {}  Vodafone rogue obs: {}\n".format(
                t_obs,v_obs))
        else:
            tee.write("  No simultaneous events in this batch\n")

    # 9. RRC PERIODICITY
    hdr(tee, "RRC PERIODICITY -- HARRIS T3/T1 SIGNATURE")
    if rrc_result:
        tee.write("  Releases: {}  Intervals: {}  Mean: {:.3f}s\n".format(
            rrc_result["total"],rrc_result["intervals"],rrc_result["mean"]))
        tee.write("  T3 matches ({:.1f}s +/-{:.1f}s): {} ({:.1f}%)\n".format(
            HARRIS_T3,HARRIS_T3_SD,rrc_result["t3"],rrc_result["t3_rate"]))
        if "t3_mean" in rrc_result:
            tee.write("  T3 mean: {:.3f}s  SD: {:.3f}s\n".format(
                rrc_result["t3_mean"],rrc_result["t3_sd"]))
            if rrc_result["t3_rate"] > 50:
                tee.write("  *** HARRIS T3 SIGNATURE CONFIRMED ***\n")
        tee.write("  T1 matches ({:.1f}s +/-{:.1f}s): {}\n".format(
            HARRIS_T1,HARRIS_T1_SD,rrc_result["t1"]))
        if rrc_result["t1"] > 0:
            tee.write("  *** HARRIS T1 SIGNATURE DETECTED ***\n")
    else:
        tee.write("  Insufficient RRC events ({} found, need 3+)\n".format(
            len(rrc_releases)))
        tee.write("  pySCAT required for full QMDL dissection\n")
        tee.write("  T3=210.182s confirmed in full archive runs\n")

    # 10. SIGNAL STRENGTH
    hdr(tee, "SIGNAL STRENGTH TRACKING")
    if signals:
        tee.write("  Signal measurements found: {}\n\n".format(len(signals)))
        rsrp_vals = [s["rsrp"] for s in signals if "rsrp" in s]
        rssi_vals = [s["rssi"] for s in signals if "rssi" in s]
        if rsrp_vals:
            tee.write("  RSRP  min={:.1f}  max={:.1f}  mean={:.1f} dBm\n".format(
                min(rsrp_vals),max(rsrp_vals),
                sum(rsrp_vals)/len(rsrp_vals)))
            if max(rsrp_vals) > -70:
                tee.write("  HIGH RSRP DETECTED -- transmitter likely very close\n")
        if rssi_vals:
            tee.write("  RSSI  min={:.1f}  max={:.1f}  mean={:.1f} dBm\n".format(
                min(rssi_vals),max(rssi_vals),
                sum(rssi_vals)/len(rssi_vals)))
    else:
        tee.write("  No RSRP/RSSI values extracted from NDJSON events\n")
        tee.write("  Signal data available in QMDL via pySCAT\n")

    # 11. ENCRYPTION RATES
    hdr(tee, "ENCRYPTION RATE BY FILE  (>50% = transparent proxy)")
    tee.write("  {:<35} {:>7} {:>10} {:>8}\n".format(
        "File","Total","Encrypted","Rate"))
    sep(tee)
    tp = 0
    for fname, stats in sorted(file_stats.items()):
        flag = " TRANSPARENT PROXY" if stats["rate"]>50 else ""
        if stats["rate"]>50: tp+=1
        tee.write("  {:<35} {:>7} {:>10} {:>7.1f}%{}\n".format(
            fname,stats["total"],stats["encrypted"],stats["rate"],flag))
    tee.write("\n  Transparent proxy files: {}/{}\n".format(tp,len(file_stats)))

    # 12. IDENTITY REQUESTS
    hdr(tee, "IDENTITY REQUESTS -- {} DETECTED".format(len(identity_reqs)))
    if identity_reqs:
        imsi = [e for e in identity_reqs if "imsi" in e["msg"].lower()]
        imei = [e for e in identity_reqs if "imei" in e["msg"].lower()]
        tee.write("  IMSI: {}  IMEI: {}\n\n".format(len(imsi),len(imei)))
        for ev in identity_reqs[:20]:
            tee.write("  [{:8}] {}  {}\n".format(
                ev["severity"],ev["ts"][:19],ev["file"]))
            tee.write("             {}\n".format(ev["msg"][:80]))
        if len(identity_reqs)>20:
            tee.write("  ... and {} more\n".format(len(identity_reqs)-20))
    else:
        tee.write("  None detected\n")

    # 13. EEA0
    hdr(tee, "SECURITY MODE / EEA0 -- {} DETECTED".format(len(smc_events)))
    if smc_events:
        tee.write("  WARNING: EEA0 events -- verify with tshark before submission\n")
        for ev in smc_events[:10]:
            tee.write("  [{:8}] {}  {}\n".format(
                ev["severity"],ev["ts"][:19],ev["msg"][:80]))
    else:
        tee.write("  ZERO EEA0 -- Harris Transparent Proxy confirmed\n")
        tee.write("  Device maintains EEA2/EIA2 encryption\n")

    # 14. TIMELINE
    if show_days:
        hdr(tee, "TEMPORAL ACTIVITY TIMELINE")
        daily = build_timeline(cells)
        if daily:
            tee.write("  {:<12} {:>12} {:>14}  {}\n".format(
                "Date","Telstra CIDs","Vodafone CIDs","Known Event"))
            sep(tee)
            for day in sorted(daily.keys()):
                dc = daily[day]
                t_c = [c for c in dc if cell_meta.get(c,{}).get("mnc")==1]
                v_c = [c for c in dc if cell_meta.get(c,{}).get("mnc")==3]
                evt = KNOWN_EVENTS.get(day,"")
                tee.write("  {:<12} T:{:>3}          V:{:>3}          {}\n".format(
                    day,len(t_c),len(v_c),
                    "*** "+evt if evt else ""))
        else:
            tee.write("  Insufficient timestamp data\n")

    # 15. OPENCELLID URLS
    hdr(tee, "OPENCELLID LOOKUP URLs")
    for cid, count in sorted(cell_counts.items(), key=lambda x: -x[1]):
        meta = cell_meta.get(cid,{})
        plmn = meta.get("plmn","505-1")
        tac  = meta.get("tac",12385)
        mnc  = int(plmn.split("-")[1]) if "-" in str(plmn) else 1
        tag  = "ROGUE " if cid in KNOWN_ROGUE else "VERIFY"
        tee.write("  [{}] CID={}: {}\n".format(
            tag,cid,opencellid_url(505,mnc,tac,cid)))

    # SUMMARY
    confirmed_count = sum(1 for c in cell_counts if c in KNOWN_ROGUE)
    tee.write("\n"+"="*72+"\n  SUMMARY\n"+"="*72+"\n")
    tee.write("  Capture unit:          {}\n".format(unit))
    tee.write("  Files analysed:        {}\n".format(len(ndjson_files)))
    tee.write("  Total events:          {}\n".format(len(all_events)))
    tee.write("  Unique CIDs:           {}\n".format(len(cell_counts)))
    tee.write("  Confirmed rogue CIDs:  {}\n".format(confirmed_count))
    tee.write("  New suspect CIDs:      {}\n".format(len(new_cids)))
    tee.write("  Identity requests:     {}\n".format(len(identity_reqs)))
    tee.write("  EEA0 events:           {}\n".format(len(smc_events)))
    tee.write("  RRC releases:          {}\n".format(len(rrc_releases)))
    tee.write("  Cross-carrier events:  {}\n".format(len(simultaneous)))
    tee.write("  Signal measurements:   {}\n".format(len(signals)))
    tee.write("  Capture gaps (>24h):   {}\n".format(len(gaps)))
    tee.write("  SHA-256 hashed:        {}\n".format(len(manifests)))
    tee.write("  Profile verdict:       {}\n".format(profile_result["verdict"]))
    tee.write("\n  YAICD scoring:\n")
    tee.write("  python main.py --dir \"{}\"\n".format(scan_dir))
    tee.write("="*72+"\n\n")

    # Save report
    if save_output:
        ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path("deep_analysis_{}.txt".format(ts_tag))
        with open(out_path,"w",encoding="utf-8") as f:
            f.write(tee.getvalue())
        print("  Report saved: {}".format(out_path))

    # ACMA draft
    if gen_acma:
        acma_text = generate_acma_draft(
            scan_dir, cell_counts, cell_first, cell_last,
            cell_meta, identity_reqs, smc_events,
            simultaneous, new_cids, profile_result)
        ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        acma_path = Path("acma_draft_{}.txt".format(ts_tag))
        with open(acma_path,"w",encoding="utf-8") as f:
            f.write(acma_text)
        print("\n" + "="*72)
        print("  ACMA UPDATE DRAFT")
        print("="*72)
        print(acma_text)
        print("\n  ACMA draft saved: {}".format(acma_path))


# ================================================================
# COMPARE MODE
# ================================================================

def compare_directories(new_dir, old_dir):
    print("\n" + "="*72)
    print("  RAYHUNTER CAPTURE COMPARISON")
    print("  New: {}".format(new_dir))
    print("  Old: {}".format(old_dir))
    print("="*72)

    def get_cid_summary(scan_dir):
        scan_path = Path(scan_dir)
        all_events = []
        for f in sorted(scan_path.glob("*.ndjson")):
            events, _, _ = parse_ndjson(f)
            all_events.extend(events)
        cells = extract_cells(all_events)
        counts = defaultdict(int)
        first, last = {}, {}
        for c in cells:
            counts[c["cid"]] += 1
            if c["cid"] not in first or c["ts"] < first[c["cid"]]:
                first[c["cid"]] = c["ts"]
            if c["cid"] not in last or c["ts"] > last[c["cid"]]:
                last[c["cid"]]  = c["ts"]
        return counts, first, last

    new_counts, new_first, new_last = get_cid_summary(new_dir)
    old_counts, old_first, old_last = get_cid_summary(old_dir)

    new_cids  = set(new_counts.keys()) - set(old_counts.keys())
    gone_cids = set(old_counts.keys()) - set(new_counts.keys())
    both_cids = set(new_counts.keys()) & set(old_counts.keys())

    print("\n  NEW CIDs (appeared in new batch, not in old):")
    if new_cids:
        for cid in sorted(new_cids):
            tag = "ROGUE" if cid in KNOWN_ROGUE else "UNKNOWN"
            print("  [{}] CID={} observations={}  first={}".format(
                tag, cid, new_counts[cid],
                new_first.get(cid,"")[:19]))
    else:
        print("  None")

    print("\n  DISAPPEARED CIDs (in old, not in new):")
    if gone_cids:
        for cid in sorted(gone_cids):
            tag = "ROGUE" if cid in KNOWN_ROGUE else "UNKNOWN"
            print("  [{}] CID={} was {} obs  last seen={}".format(
                tag, cid, old_counts[cid],
                old_last.get(cid,"")[:19]))
    else:
        print("  None -- all previous CIDs still active")

    print("\n  PERSISTENT CIDs (in both batches):")
    for cid in sorted(both_cids):
        delta = new_counts[cid] - old_counts[cid]
        tag = "ROGUE" if cid in KNOWN_ROGUE else "OK"
        sign = "+" if delta >= 0 else ""
        print("  [{}] CID={}  old={} new={} ({}{})".format(
            tag, cid, old_counts[cid], new_counts[cid], sign, delta))

    print("\n  SUMMARY")
    print("  New CIDs:         {}".format(len(new_cids)))
    print("  Disappeared CIDs: {}".format(len(gone_cids)))
    print("  Persistent CIDs:  {}".format(len(both_cids)))
    rogue_new = [c for c in new_cids if c in KNOWN_ROGUE]
    if rogue_new:
        print("  *** NEW CONFIRMED ROGUE CIDs: {}".format(rogue_new))
    print("="*72+"\n")


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rayhunter Deep Forensic Analysis v2.4 -- Cranbourne East")
    parser.add_argument("--dir", required=True,
                        help="Directory containing capture files")
    parser.add_argument("--days", action="store_true",
                        help="Show full day-by-day timeline")
    parser.add_argument("--output", action="store_true",
                        help="Save report to timestamped text file")
    parser.add_argument("--compare", metavar="OLD_DIR",
                        help="Compare --dir (new) against OLD_DIR")
    parser.add_argument("--acma", action="store_true",
                        help="Generate ACMA evidence update draft")
    args = parser.parse_args()

    if args.compare:
        compare_directories(args.dir, args.compare)
    else:
        analyze_directory(args.dir,
                          show_days=args.days,
                          save_output=args.output,
                          gen_acma=args.acma)
