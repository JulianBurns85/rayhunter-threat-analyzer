"""
time_quality.py (v4.4.3) — tag events whose timestamps cannot be trusted, and say which files.

Why: parsers anchor "boot-relative" times to file mtime and some QMDL/PCAP time fields are garbage.
Downstream span/rhythm/persistence maths then reports impossible things (e.g. 549 active days for a
capture set that starts in October 2026). This does NOT change timestamps; it only sets
event["timestamp_source"] so forensic_time.trusted_timestamp() can exclude them.

Tags (first match wins; an existing parser-set timestamp_source is preserved):
  invalid            no parseable/plausible timestamp
  out_of_window      outside analysis.capture_window [start, end]  (default 2026-01-01 .. 2026-12-31)
  filename_mismatch  file is named by a Unix start epoch (Rayhunter style, e.g. 1792071242.pcapng) but
                     the event is more than analysis.max_file_span_days after/before that start
Config (config.yaml):
  analysis:
    capture_window: ["2026-01-01", "2026-12-31"]
    max_file_span_days: 14
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from forensic_time import normalize_epoch_seconds


def _epoch(ts) -> Optional[float]:
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return normalize_epoch_seconds(float(ts))
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return normalize_epoch_seconds(dt.timestamp())
    except (ValueError, OSError, OverflowError):
        return None


def _name_epoch(source_file: str) -> Optional[float]:
    stem = Path(str(source_file)).stem
    if stem.isdigit() and 9 <= len(stem) <= 10:
        return normalize_epoch_seconds(float(stem))
    return None


def audit_and_tag(events: List[Dict], cfg: dict) -> List[Dict]:
    a = (cfg or {}).get("analysis", {}) or {}
    w0, w1 = a.get("capture_window", ["2026-01-01", "2026-12-31"])
    lo = datetime.fromisoformat(str(w0)).replace(tzinfo=timezone.utc).timestamp()
    hi = datetime.fromisoformat(str(w1)).replace(tzinfo=timezone.utc).timestamp() + 86400
    max_span = float(a.get("max_file_span_days", 14)) * 86400

    files: Dict[str, Dict] = {}
    for e in events:
        f = str(e.get("source_file", "?"))
        row = files.setdefault(f, {"file": f, "events": 0, "tagged": 0, "first": None, "last": None,
                                   "name_epoch": _name_epoch(f), "tags": {}})
        row["events"] += 1
        t = _epoch(e.get("timestamp") or e.get("time") or e.get("ts"))
        tag = None
        if t is None:
            tag = "invalid"
        else:
            row["first"] = t if row["first"] is None else min(row["first"], t)
            row["last"] = t if row["last"] is None else max(row["last"], t)
            if not (lo <= t <= hi):
                tag = "out_of_window"
            elif row["name_epoch"] is not None and not (-3600 <= t - row["name_epoch"] <= max_span):
                tag = "filename_mismatch"
        if tag and not e.get("timestamp_source"):
            e["timestamp_source"] = tag
            row["tagged"] += 1
            row["tags"][tag] = row["tags"].get(tag, 0) + 1
    return list(files.values())


def print_audit(rows: List[Dict]) -> None:
    total = sum(r["events"] for r in rows)
    tagged = sum(r["tagged"] for r in rows)
    bad = [r for r in rows if r["tagged"]]
    print(f"\n  [TIME] {tagged:,} of {total:,} events ({(tagged / total * 100 if total else 0):.1f}%) "
          f"have untrusted timestamps in {len(bad)} of {len(rows)} files "
          f"(excluded from span/rhythm maths; timestamps unchanged).")
    for r in sorted(bad, key=lambda r: -r["tagged"])[:10]:
        fmt = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d") if t else "?"
        print(f"    {Path(r['file']).name}: {r['tagged']:,}/{r['events']:,} {r['tags']} "
              f"range {fmt(r['first'])}..{fmt(r['last'])}")
    if len(bad) > 10:
        print(f"    ... and {len(bad) - 10} more file(s)")
