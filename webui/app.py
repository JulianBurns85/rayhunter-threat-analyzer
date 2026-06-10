"""
rayhunter-threat-analyzer — Web UI
Flask localhost:8080
"""

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────── #
RTA_ROOT    = Path(os.environ.get("RTA_ROOT", r"C:\RH\rayhunter-threat-analyzer"))
OUTPUT_DIR  = Path(os.environ.get("RTA_OUTPUT", r"C:\RH\MASTER\output"))
PYTHON_EXE  = sys.executable

# Active run state
_run_lock   = threading.Lock()
_run_active = False
_run_queue  = Queue()


# ── Helpers ───────────────────────────────────────────────────────────────── #

def list_reports():
    """Return sorted list of JSON report files in OUTPUT_DIR."""
    if not OUTPUT_DIR.exists():
        return []
    reports = sorted(
        OUTPUT_DIR.glob("forensic_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    return reports


def load_report(path: Path) -> dict:
    """Load and return a report JSON, or empty dict on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def severity_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}.get(s.upper(), 4)


def format_ts(ts_str: str) -> str:
    """Format ISO timestamp to human-readable."""
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts_str)


# ── Routes ────────────────────────────────────────────────────────────────── #

@app.route("/")
def index():
    reports = list_reports()
    selected = None
    report_data = {}

    report_name = request.args.get("report")
    if report_name:
        path = OUTPUT_DIR / report_name
        if path.exists():
            report_data = load_report(path)
            selected = report_name
    elif reports:
        report_data = load_report(reports[0])
        selected = reports[0].name

    findings = report_data.get("findings", [])
    findings_sorted = sorted(findings, key=lambda f: severity_order(f.get("severity", "INFO")))

    # Summary stats
    stats = {
        "events":    report_data.get("summary", {}).get("total_events_analyzed", report_data.get("total_events_analyzed", 0)),
        "findings":  len(findings),
        "critical":  sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
        "high":      sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
        "medium":    sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM"),
        "info":      sum(1 for f in findings if f.get("severity", "").upper() == "INFO"),
        "yaicd":     report_data.get("yaicd_score", report_data.get("heuristic_analysis", {}).get("yaicd_formal_score", "—")),
        "verdict":   report_data.get("heuristic_analysis", {}).get("verdict", "—"),
        "generated": format_ts(report_data.get("generated_at", report_data.get("timestamp", ""))),
        "corpus":    report_data.get("corpus_dir", report_data.get("scan_directory", "—")),
        "analysis_time": report_data.get("analysis_duration_seconds", report_data.get("analysis_time_seconds", report_data.get("analysis_time", "—"))),
    }

    # Heuristics
    heuristics = []
    ha = report_data.get("heuristic_analysis", {})
    for h in ha.get("heuristics", []):
        heuristics.append({
            "id":     h.get("heuristic_id", ""),
            "label":  h.get("label", ""),
            "status": h.get("status", ""),
        })

    # Priority actions
    priority = report_data.get("priority_actions", [])

    return render_template(
        "index.html",
        reports=[r.name for r in reports],
        selected=selected,
        stats=stats,
        findings=findings_sorted,
        heuristics=heuristics,
        priority=priority,
        report_data=report_data,
        run_active=_run_active,
    )


@app.route("/finding/<int:idx>")
def finding_detail(idx):
    """Return full finding detail as JSON for modal."""
    report_name = request.args.get("report")
    if not report_name:
        return jsonify({"error": "no report specified"}), 400
    path = OUTPUT_DIR / report_name
    if not path.exists():
        return jsonify({"error": "report not found"}), 404
    data = load_report(path)
    findings = data.get("findings", [])
    findings_sorted = sorted(findings, key=lambda f: severity_order(f.get("severity", "INFO")))
    if idx < 0 or idx >= len(findings_sorted):
        return jsonify({"error": "index out of range"}), 404
    return jsonify(findings_sorted[idx])


@app.route("/run", methods=["POST"])
def run_analysis():
    """Trigger a new analysis run. Returns SSE stream."""
    global _run_active
    with _run_lock:
        if _run_active:
            return jsonify({"error": "A run is already in progress"}), 409
        _run_active = True

    # Clear queue
    while not _run_queue.empty():
        try:
            _run_queue.get_nowait()
        except Empty:
            break

    data = request.get_json(silent=True) or {}
    corpus_dir  = data.get("dir", "")
    output_file = data.get("output", str(OUTPUT_DIR / f"forensic_{int(time.time())}.json"))
    extra_args  = data.get("extra_args", "--no-opencellid")

    def run_thread():
        global _run_active
        try:
            cmd = [
                PYTHON_EXE, str(RTA_ROOT / "main.py"),
                "--dir", corpus_dir,
                "--output", output_file,
                "--manifest",
            ] + extra_args.split()

            _run_queue.put(f"data: [START] Running: {' '.join(cmd)}\n\n")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(RTA_ROOT),
            )

            for line in proc.stdout:
                _run_queue.put(f"data: {line.rstrip()}\n\n")

            proc.wait()
            status = "COMPLETE" if proc.returncode == 0 else f"ERROR (exit {proc.returncode})"
            _run_queue.put(f"data: [DONE] {status}\n\n")
            _run_queue.put(f"data: [OUTPUT] {output_file}\n\n")

        except Exception as e:
            _run_queue.put(f"data: [ERROR] {e}\n\n")
        finally:
            _run_active = False
            _run_queue.put(None)  # sentinel

    threading.Thread(target=run_thread, daemon=True).start()
    return jsonify({"status": "started", "output": output_file})


@app.route("/stream")
def stream():
    """SSE endpoint — streams output from the active run."""
    def event_stream():
        while True:
            try:
                msg = _run_queue.get(timeout=30)
                if msg is None:
                    yield "data: [END]\n\n"
                    break
                yield msg
            except Empty:
                yield "data: [PING]\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/status")
def status():
    return jsonify({"run_active": _run_active})


@app.route("/reports")
def reports_list():
    reports = list_reports()
    return jsonify([{
        "name": r.name,
        "mtime": r.stat().st_mtime,
        "size_kb": round(r.stat().st_size / 1024, 1),
    } for r in reports])


@app.route("/timeline")
def timeline():
    import re
    all_days = {}
    detail = {}
    reg_events = [
        {"date": "2026-01-23", "label": "First complaint",   "color": "#4a9eff"},
        {"date": "2026-03-31", "label": "VicPol CIRS",       "color": "#4a9eff"},
        {"date": "2026-04-15", "label": "AFP Referral",      "color": "#a855f7"},
        {"date": "2026-05-08", "label": "ACMA Inspection",   "color": "#ff8c3a"},
        {"date": "2026-05-30", "label": "Blackout begins",   "color": "#ff4a4a"},
        {"date": "2026-06-02", "label": "Resumption 44.5x", "color": "#ff4a4a"},
        {"date": "2026-06-09", "label": "AFP Submission",    "color": "#00c896"},
    ]
    for path in OUTPUT_DIR.glob("forensic_*.json"):
        data = load_report(path)
        for finding in data.get("findings", []):
            if "Attack Intensity" not in finding.get("title", ""):
                continue
            for ev in finding.get("evidence", []):
                ev = str(ev)
                m1 = re.match(r'\s*(20\d\d-\d\d-\d\d)\s+\[.*?\]\s+(\d+)', ev)
                if m1:
                    d, s = m1.group(1), int(m1.group(2))
                    if d not in all_days or s > all_days[d]:
                        all_days[d] = s
                m2 = re.match(r'\s*(20\d\d-\d\d-\d\d)\s+[^\d]*Score:\s+(\d+)\s+\|\s+Handovers:\s+(\d+)\s+\|\s+IMSI:\s+(\d+)', ev)
                if m2 and m2.group(1) not in detail:
                    detail[m2.group(1)] = {
                        "score": int(m2.group(2)),
                        "handovers": int(m2.group(3)),
                        "imsi": int(m2.group(4))
                    }
    valid = sorted((k, v) for k, v in all_days.items() if k.startswith("20"))
    total_score = sum(v for _, v in valid)
    peak = max(valid, key=lambda x: x[1]) if valid else ("--", 0)
    return render_template(
        "timeline.html",
        days=json.dumps(valid),
        detail=json.dumps(detail),
        reg_events=json.dumps(reg_events),
        total_score=f"{total_score:,}",
        active_days=len(valid),
        peak_date=peak[0],
        peak_score=f"{peak[1]:,}",
    )


@app.route("/ghostnet")
def ghostnet():
    return render_template("ghostnet.html")


@app.route("/schedule")
def schedule():
    return render_template("schedule.html")


@app.route("/killchain")
def killchain():
    return render_template("killchain.html")


if __name__ == "__main__":
    print("rayhunter-threat-analyzer Web UI")
    print(f"  RTA root:   {RTA_ROOT}")
    print(f"  Output dir: {OUTPUT_DIR}")
    print(f"  Listening:  http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
