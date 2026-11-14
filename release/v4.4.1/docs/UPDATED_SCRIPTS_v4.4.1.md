# Updated scripts — v4.4.1 (2026-10-21)

Complete copies of every file changed in this release live under:

`release/v4.4.1/`

## Core pipeline

| File | Role |
|------|------|
| `main.py` | CLI entry; imports `pipeline_extras` |
| `pipeline_extras.py` | **New** — Argus finding accessor, P7/RRC wiring, `output_dir` helper |
| `setup.py` | Package version 4.4.1 |
| `requirements.txt` | Runtime + pytest deps |
| `config.yaml` | Optional `output_dir`; use `config.yaml.example` for fresh installs |
| `detectors/kml_exporter.py` | Writes KML under `output_dir` |

## Standalone tools

| File | Role |
|------|------|
| `rayhunter_core.py` | NDJSON parser-gap CSV/MD summary |
| `baseline_rrc.py` | QMDL/PCAP file count baseline |

## Tests & CI

| File | Role |
|------|------|
| `tests/test_synthetic.py` | Fixed `sys.path`; ASCII-safe console output |
| `.github/workflows/pytest.yml` | CI (skips heavy integration test) |

## Config / repo hygiene

| File | Role |
|------|------|
| `config.yaml.example` | Template without secrets |
| `.gitignore` | Valid globs; ignores captures and reports |
| `CHANGELOG.md` | v4.4.1 release notes |

## Run

```powershell
pip install -r requirements.txt
python main.py --dir "C:\RH\captures" --castnet-api http://192.168.1.100:5000
python rayhunter_core.py --dir "C:\RH\captures" --output-dir "C:\RH\reports and maps"
python tests/test_synthetic.py
```
