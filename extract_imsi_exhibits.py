#!/usr/bin/env python3
"""Write pre-security IMSI exhibit CSVs using the same session rule as
CipherNegotiationSequenceAnalyser: Identity Request typed IMSI, occurring
before the first SecurityModeCommand in a 300-second NAS session.
"""
from __future__ import annotations

import csv
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from detectors.cipher_negotiation_sequence_analyser import (  # noqa: E402
    MSG_MAP,
    SESSION_GAP_S,
    _identity_is_imsi,
)
from main import collect_files  # noqa: E402
from parsers.ndjson_parser import NdjsonParser  # noqa: E402
from parsers.pcap_parser import PcapParser  # noqa: E402
from parsers.qmdl_parser import QmdlParser  # noqa: E402

OUT_ROOT = Path(r"C:\RH\reports and maps\exhibits")


def _ts(event: dict):
    ts = event.get("ts_epoch") or event.get("timestamp") or event.get("time") or event.get("ts")
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    except (ValueError, OSError):
        return None
    return None


def _norm(event: dict):
    msg = str(event.get("message_type") or event.get("msg_type") or "").lower()
    kind = None
    for pattern, norm_type in MSG_MAP.items():
        if pattern in msg:
            kind = norm_type
            break
    ts = _ts(event)
    if not ts or not kind:
        return None
    return {
        "ts": ts,
        "type": kind,
        "imsi": kind == "IDENTITY" and _identity_is_imsi(event, msg),
        "event": event,
        "raw": msg,
    }


def load_events(directory: str) -> list:
    files = collect_files([], directory)
    cfg = {}
    parsers = [
        (NdjsonParser(cfg), files["ndjson"]),
        (PcapParser(cfg), files["pcap"]),
        (QmdlParser(cfg), files["qmdl"]),
    ]
    events = []
    for parser, paths in parsers:
        for path in paths:
            try:
                batch = parser.parse(path)
            except Exception as exc:
                print(f"  [WARN] {Path(path).name}: {exc}")
                continue
            print(f"  -> {len(batch):,} events from {Path(path).name}")
            events.extend(batch)
    print(f"  Total events: {len(events):,}")
    return events


def presecurity_imsi_rows(events: list) -> list:
    normed = [n for n in (_norm(e) for e in events) if n]
    normed.sort(key=lambda x: x["ts"])
    if not normed:
        return []
    sessions = []
    current = [normed[0]]
    for ev in normed[1:]:
        if ev["ts"] - current[-1]["ts"] <= SESSION_GAP_S:
            current.append(ev)
        else:
            sessions.append(current)
            current = [ev]
    sessions.append(current)

    rows = []
    for sid, session in enumerate(sessions, start=1):
        seq = [e["type"] for e in session]
        idx_smc = seq.index("SMC") if "SMC" in seq else len(seq)
        smc_ts = next((e["ts"] for e in session if e["type"] == "SMC"), None)
        for i, item in enumerate(session):
            if item["type"] == "IDENTITY" and i < idx_smc:
                ev = item["event"]
                rows.append({
                    "session": sid,
                    "timestamp_utc": datetime.fromtimestamp(item["ts"], tz=timezone.utc).isoformat(),
                    "seconds_before_smc": "" if smc_ts is None else f"{smc_ts - item['ts']:.3f}",
                    "smc_in_session": "yes" if smc_ts is not None else "no",
                    "source_file": ev.get("source_file") or "",
                    "source_type": ev.get("source_type") or "",
                    "msg_type": ev.get("msg_type") or ev.get("message_type") or "",
                    "identity_type": ev.get("identity_type") or ev.get("id_type") or "",
                    "pci": ev.get("pci") if ev.get("pci") is not None else "",
                    "cid": ev.get("cid") or "",
                    "tac": ev.get("tac") or "",
                    "log_code": ev.get("log_code") or "",
                })
    return rows


def write_package(name: str, directory: str, report: str, kml: str, note: str) -> Path:
    dest = OUT_ROOT / name
    dest.mkdir(parents=True, exist_ok=True)
    print(f"\n== {name} ==")
    events = load_events(directory)
    rows = presecurity_imsi_rows(events)
    csv_path = dest / "imsi_presecurity.csv"
    fields = [
        "exhibit_id", "session", "timestamp_utc", "seconds_before_smc", "smc_in_session",
        "source_file", "source_type", "msg_type", "identity_type", "pci", "cid", "tac", "log_code",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for n, row in enumerate(rows, start=1):
            row["exhibit_id"] = f"{name}-{n:02d}"
            writer.writerow(row)
    copied = []
    for src in (report, kml):
        p = Path(src)
        if p.exists():
            target = dest / p.name
            shutil.copy2(p, target)
            copied.append(target.name)
    index = dest / "INDEX.txt"
    index.write_text(
        "\n".join([
            name,
            note,
            f"Capture directory: {directory}",
            f"Pre-security Identity Requests: {len(rows)}",
            f"  IMSI: {sum(1 for r in rows if r.get('identity_type') == 'IMSI')}",
            f"  IMEISV: {sum(1 for r in rows if r.get('identity_type') == 'IMEISV')}",
            f"CSV: {csv_path}",
            "Copied: " + ", ".join(copied),
            "",
            "Each CSV row is an Identity Request before the first SecurityModeCommand",
            "in that 300-second session. identity_type is nas-eps.emm.id_type2",
            "(1=IMSI, 2=IMEI, 3=IMEISV, 4=TMSI). IMEISV is a routine request and",
            "is not an IMSI harvest.",
            "",
            "tshark (Wireshark 4.6 — message type field is nas_msg_emm_type):",
            '  tshark -r "<full path>" -Y "nas-eps.nas_msg_emm_type == 0x55" -T fields -e frame.time_utc -e nas-eps.emm.id_type2',
            "",
        ]),
        encoding="utf-8",
    )
    imsi_n = sum(1 for r in rows if r.get("identity_type") == "IMSI")
    imeisv_n = sum(1 for r in rows if r.get("identity_type") == "IMEISV")
    print(f"  Rows: {len(rows)} (IMSI {imsi_n}, IMEISV {imeisv_n}) -> {csv_path}")
    return dest


def main():
    write_package(
        "A-20.10.26",
        r"C:\Users\Jessum Fellow\Desktop\raymum4\20.10.26",
        r"C:\RH\reports and maps\rayhunter_report_1792552429.json",
        r"C:\RH\reports and maps\rayhunter_forensic_map_1792552413.kml",
        "Exhibit session. capture_only. 4 pre-security IMSI headline from rayhunter_report_1792552429.json.",
    )
    write_package(
        "B-raymum-full",
        r"C:\Users\Jessum Fellow\Desktop\raymum4\raymum",
        r"C:\RH\reports and maps\rayhunter_report_1792552122.json",
        r"C:\RH\reports and maps\rayhunter_forensic_map_1792552034.kml",
        "Full investigation corpus. 28 pre-security IMSI headline from rayhunter_report_1792552122.json.",
    )


if __name__ == "__main__":
    main()
