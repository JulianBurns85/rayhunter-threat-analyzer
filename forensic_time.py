"""
forensic_time.py — timestamp sanity + robust "active day" helpers (v4.4.3)

QMDL/PCAP parsers sometimes emit epoch-zero, ms/us/ns-as-seconds, boot-relative
or file-mtime-anchored timestamps. Span/rhythm maths must only use trusted ones,
and must not treat a handful of stray events on a day as "activity on that day".
"""
from datetime import datetime, timezone, timedelta, date
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

MIN_VALID_EPOCH = 1_577_836_800.0   # 2020-01-01 UTC
MAX_VALID_EPOCH = 2_205_398_400.0   # 2039-12-31 UTC

# timestamp_source values (set by parsers) that must NOT feed time-of-day maths
UNTRUSTED_SOURCES = {"mtime", "file_mtime", "boot_relative", "anchored", "synthetic",
                     "out_of_window", "filename_mismatch", "invalid"}


def normalize_epoch_seconds(ts: Optional[float]) -> Optional[float]:
    """Return UTC epoch seconds if ts is plausible (handles s/ms/us/ns), else None."""
    if ts is None:
        return None
    try:
        v = float(ts)
    except (TypeError, ValueError):
        return None
    if v != v or v <= 0:          # NaN or non-positive
        return None
    if v > 1e17:                  # nanoseconds
        v /= 1e9
    elif v > 1e14:                # microseconds
        v /= 1e6
    elif v > 1e11:                # milliseconds
        v /= 1e3
    return v if MIN_VALID_EPOCH <= v <= MAX_VALID_EPOCH else None


def filter_epochs(epochs: Iterable[Optional[float]]) -> List[float]:
    out = []
    for ts in epochs:
        n = normalize_epoch_seconds(ts)
        if n is not None:
            out.append(n)
    return out


def trusted_timestamp(event: dict) -> bool:
    """False if the parser flagged this event's time as inferred (mtime/boot-relative)."""
    src = str(event.get("timestamp_source") or event.get("ts_source") or "").lower()
    return src not in UNTRUSTED_SOURCES


def local_tz(name: str = "Australia/Melbourne"):
    """DST-aware zone (Melbourne is AEDT/UTC+11 from first Sun Oct to first Sun Apr).
    Falls back to fixed UTC+10 if zoneinfo/tzdata is unavailable (pip install tzdata)."""
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return timezone(timedelta(hours=10))


def calendar_span_days(epochs: Sequence[float]):
    """(distinct UTC days with any event, min_epoch, max_epoch). Kept for compatibility."""
    if not epochs:
        return 0, None, None
    days = {datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%d") for e in epochs}
    return len(days), min(epochs), max(epochs)


def wall_span_days(epochs: Sequence[float]) -> float:
    if len(epochs) < 2:
        return 1.0 if epochs else 0.0
    return max((max(epochs) - min(epochs)) / 86400.0, 1.0)


def active_days(epochs: Sequence[float], min_events: int = 50,
                tz=timezone.utc) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Split local calendar days into (kept, dropped) by event count.
    'dropped' days have < min_events and are treated as stray/mis-anchored."""
    counts: Dict[str, int] = {}
    for e in epochs:
        d = datetime.fromtimestamp(e, tz=tz).strftime("%Y-%m-%d")
        counts[d] = counts.get(d, 0) + 1
    kept = {d: c for d, c in sorted(counts.items()) if c >= min_events}
    dropped = {d: c for d, c in sorted(counts.items()) if c < min_events}
    return kept, dropped


def contiguous_bursts(days: Iterable[str]) -> List[Tuple[str, str, int]]:
    """Group YYYY-MM-DD strings into runs of consecutive days: (first, last, n_days)."""
    ds = sorted(datetime.strptime(d, "%Y-%m-%d").date() for d in days)
    runs: List[List] = []
    for d in ds:
        if runs and (d - runs[-1][1]).days == 1:
            runs[-1][1] = d
            runs[-1][2] += 1
        else:
            runs.append([d, d, 1])
    return [(a.isoformat(), b.isoformat(), n) for a, b, n in runs]
