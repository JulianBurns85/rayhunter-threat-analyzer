import csv
import json
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import parse_threats as pt


def test_cli_arguments_defaults_and_overrides():
    defaults = pt.parse_args([])
    assert defaults.input == pt.INPUT_FILE
    assert defaults.output == pt.OUTPUT_CSV

    custom = pt.parse_args(["-i", "custom_in.json", "--output", "out/threats.csv"])
    assert custom.input == "custom_in.json"
    assert custom.output == "out/threats.csv"


def test_streamed_json_blocks_and_diagnostic_filtering():
    block1 = {
        "capture_file": "001.qmdl",
        "analyzer": {"name": "IdentityHarvestDetector"},
        "events": [
            {"timestamp": 1792071242, "severity": "HIGH", "message": "Repeated IMSI requests"},
            {"timestamp": 1792071243, "severity": "Informational", "message": "Routine check"},
            {"timestamp": 1792071244, "severity": "LOW", "message": "Diagnostic: attach counter"},
        ],
    }
    block2 = {
        "source": "002.pcapng",
        "analyzer": "Diagnostic Information Collector",
        "events": [
            {"timestamp": 1792071300, "severity": "CRITICAL", "message": "Should be ignored under diagnostic analyzer"},
        ],
    }
    streamed = json.dumps(block1) + "\n\n" + json.dumps(block2)
    with NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
        tmp.write(streamed)
        tmp_path = tmp.name
    try:
        blocks = pt.load_json_blocks(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    assert len(blocks) == 2
    threats = pt.extract_events(blocks)
    assert len(threats) == 1
    assert threats[0]["Source_File"] == "001.qmdl"
    assert threats[0]["Analyzer"] == "IdentityHarvestDetector"
    assert threats[0]["Severity"] == "HIGH"
    assert threats[0]["Message"] == "Repeated IMSI requests"


def test_main_writes_filtered_csv(tmp_path):
    in_path = tmp_path / "report.json"
    out_path = tmp_path / "nested" / "threats.csv"

    payload = {
        "filepath": "capture_a.pcapng",
        "analyzer": {"name": "CipherDowngradeDetector"},
        "events": [
            {"timestamp": 1792071500, "severity": "MEDIUM", "message": "EEA0 selected"},
            {"timestamp": 1792071501, "severity": "LOW", "message": "Diagnostic: noise"},
        ],
    }
    in_path.write_text(json.dumps(payload), encoding="utf-8")

    pt.main(["--input", str(in_path), "--output", str(out_path)])

    assert out_path.exists()
    with out_path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["Source_File"] == "capture_a.pcapng"
    assert rows[0]["Analyzer"] == "CipherDowngradeDetector"
    assert rows[0]["Severity"] == "MEDIUM"
    assert rows[0]["Message"] == "EEA0 selected"
