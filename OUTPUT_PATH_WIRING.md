# Redirect reports + maps to  C:\RH\reports and maps

The folder name has spaces — fine for Python (it's just a string), but ALWAYS
keep it quoted on the command line and never split it. Three steps.

## STEP 0 — make the folder once
```powershell
mkdir "C:\RH\reports and maps"
```

## STEP 1 — config.yaml: add one key
Add this at the top level of config.yaml (any indent-0 position):
```yaml
output_dir: "C:/RH/reports and maps"
```
Use forward slashes — Python handles them on Windows and it avoids backslash
escaping headaches. (Backslashes also work if doubled: "C:\\RH\\reports and maps".)

## STEP 2 — main.py: JSON + HTML writers (~lines 907-923)

REPLACE this block:
```python
    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {args.output}")
        else:
            out_path = f"rayhunter_report_{int(time.time())}.json"
            Path(out_path).write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {out_path}")

    if args.html:
        try:
            from html_reporter_v2 import HTMLReporterV2
            html_path = (Path(args.output).with_suffix(".html") if args.output
                         else Path(f"rayhunter_report_{int(time.time())}.html"))
            HTMLReporterV2(cfg).generate(report, str(html_path))
            print(f"[OK] HTML report saved to: {html_path}")
        except ImportError:
            print("[WARN] html_reporter_v2.py not found ? HTML skipped.")
```

WITH:
```python
    # Resolve output directory (config output_dir, else current dir). Created if missing.
    _out_dir = Path(cfg.get("output_dir", ".")).expanduser()
    _out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("json", "both") or args.output:
        json_out = json.dumps(report, indent=2, default=str)
        if args.output:
            # explicit --output wins; if it's a bare filename, drop it in _out_dir
            _op = Path(args.output)
            if _op.parent == Path("."):
                _op = _out_dir / _op
            _op.write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {_op}")
        else:
            out_path = _out_dir / f"rayhunter_report_{int(time.time())}.json"
            out_path.write_text(json_out, encoding="utf-8")
            print(f"\n[OK] JSON report saved to: {out_path}")

    if args.html:
        try:
            from html_reporter_v2 import HTMLReporterV2
            html_path = (_out_dir / (Path(args.output).stem + ".html") if args.output
                         else _out_dir / f"rayhunter_report_{int(time.time())}.html")
            HTMLReporterV2(cfg).generate(report, str(html_path))
            print(f"[OK] HTML report saved to: {html_path}")
        except ImportError:
            print("[WARN] html_reporter_v2.py not found - HTML skipped.")
```

## STEP 3 — the KML (map) writer lives in detectors\kml_exporter.py

main.py only does `KMLExporter(cfg)` — the .kml filename is built inside that
file, so it must read output_dir too. Open detectors\kml_exporter.py and find
where it builds the filename, e.g. something like:
```python
        filename = f"rayhunter_forensic_map_{int(time.time())}.kml"
        # ...later... open(filename, "w")  OR  Path(filename).write_text(...)
```
Change it to prepend the configured dir:
```python
        from pathlib import Path
        _out_dir = Path(self.cfg.get("output_dir", ".")).expanduser()
        _out_dir.mkdir(parents=True, exist_ok=True)
        filename = str(_out_dir / f"rayhunter_forensic_map_{int(time.time())}.kml")
```
If the class stores config as something other than `self.cfg`, match that name
(grep `self\.` near the top of kml_exporter.py). If it doesn't keep a config
reference at all, paste the file and I'll give exact lines.

## Verify
```powershell
python main.py --dir "C:\Users\Jessum Chap\Desktop\June Ray Files\11.06.26"
dir "C:\RH\reports and maps"
```
You should see the timestamped .json (and .kml once Step 3 is in).
