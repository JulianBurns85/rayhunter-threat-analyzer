import argparse
import csv
import json
import os

INPUT_FILE = "master_analysis_report.json"
OUTPUT_CSV = "master_threats_only.csv"


def load_json_blocks(filepath):
    """Safely parse standard JSON or recover streamed/concatenated JSON blocks."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        return [json.loads(content)]
    except json.JSONDecodeError:
        blocks = []
        decoder = json.JSONDecoder()
        idx = 0
        length = len(content)
        while idx < length:
            while idx < length and content[idx] not in "{[":
                idx += 1
            if idx >= length:
                break
            try:
                obj, end_idx = decoder.raw_decode(content, idx)
                blocks.append(obj)
                idx = end_idx
            except json.JSONDecodeError:
                idx += 1
        return blocks


def extract_events(node, current_file="Unknown_Source", current_analyzer="Unknown_Analyzer", findings=None):
    """Recursively traverse report objects while inheriting parent file paths and analyzer names."""
    if findings is None:
        findings = []

    if isinstance(node, list):
        for item in node:
            extract_events(item, current_file, current_analyzer, findings)
        return findings

    if not isinstance(node, dict):
        return findings

    # Update context if this dictionary defines a file path or analyzer metadata
    for path_key in ("file", "filepath", "filename", "path", "source", "capture_file"):
        if path_key in node and isinstance(node[path_key], str) and node[path_key].strip():
            current_file = node[path_key].strip()
            break

    if "analyzer" in node:
        meta = node["analyzer"]
        if isinstance(meta, dict) and "name" in meta:
            current_analyzer = meta["name"]
        elif isinstance(meta, str):
            current_analyzer = meta
    elif "name" in node and ("events" in node or "reports" in node):
        current_analyzer = str(node["name"])

    # Extract individual events if present
    if "events" in node and isinstance(node["events"], list):
        for ev in node["events"]:
            if not isinstance(ev, dict):
                msg = str(ev)
                ev_type = "Alert"
                ts = "N/A"
            else:
                ts = ev.get("timestamp", "N/A")
                inner = ev.get("event", ev)
                if isinstance(inner, dict):
                    ev_type = inner.get("event_type") or inner.get("severity") or ev.get("severity") or "Alert"
                    msg = inner.get("message") or inner.get("description") or json.dumps(inner)
                else:
                    ev_type = ev.get("event_type") or ev.get("severity") or "Alert"
                    msg = str(inner)

            # Filter out routine Diagnostic / Informational telemetry
            is_diagnostic = (
                "Diagnostic:" in msg
                or str(ev_type).lower() == "informational"
                or "Diagnostic Information" in current_analyzer
            )

            if not is_diagnostic:
                findings.append({
                    "Source_File": current_file,
                    "Analyzer": current_analyzer,
                    "Severity": ev_type,
                    "Timestamp": ts,
                    "Message": msg,
                })

    # Recurse into child containers (e.g., 'reports', 'results', 'files')
    for key, val in node.items():
        if key != "events" and isinstance(val, (dict, list)):
            extract_events(val, current_file, current_analyzer, findings)

    return findings


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Filter non-diagnostic threat alerts from RayHunter JSON reports into CSV."
    )
    parser.add_argument(
        "-i", "--input",
        default=INPUT_FILE,
        help=f"Input JSON report path (default: {INPUT_FILE})",
    )
    parser.add_argument(
        "-o", "--output",
        default=OUTPUT_CSV,
        help=f"Output CSV path (default: {OUTPUT_CSV})",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    input_file = args.input
    output_csv = args.output

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        print(f"[!] Error: {input_file} is missing or empty.")
        return

    print(f"[*] Scanning {input_file} for non-diagnostic threat alerts...\n")
    blocks = load_json_blocks(input_file)
    threats = extract_events(blocks)

    if not threats:
        print("[*] 0 non-diagnostic alerts found. All captured events were routine diagnostics.")
        return

    # Group display by source file in the console
    by_file = {}
    for t in threats:
        by_file.setdefault(t["Source_File"], []).append(t)

    for src_file, items in by_file.items():
        print(f"=== FILE: {src_file} ({len(items)} alert(s)) ===")
        for item in items:
            print(f"  [{item['Timestamp']}] [{item['Severity']}] {item['Analyzer']}")
            print(f"      -> {item['Message']}")
        print()

    # Export clean CSV for spreadsheet review
    out_path = Path(output_csv)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["Source_File", "Analyzer", "Severity", "Timestamp", "Message"],
        )
        writer.writeheader()
        writer.writerows(threats)

    print(f"[+] Isolated {len(threats)} threat alert(s) across {len(by_file)} file(s).")
    print(f"[+] Saved clean CSV report to: {out_path}")


if __name__ == "__main__":
    main()