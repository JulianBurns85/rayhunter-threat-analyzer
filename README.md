# rayhunter-threat-analyzer

**Open-source cellular surveillance detection and forensic analysis tool.**

Analyses Rayhunter capture files for IMSI catcher activity, rogue base stations, null-cipher attacks, and related cellular surveillance threats. Built from 18 months of real-world civilian investigation data.

Compatible with approximately **95% of Android devices** via firmware-layer independent corroboration (see Shannon IMS Parser below).

---

## What it does

Processes raw cellular capture data from Rayhunter-equipped devices and produces structured forensic findings across 35+ detection heuristics, scored against the YAICD (Yet Another IMSI Catcher Detector) framework.

Detection capabilities include:

- IMSI harvest chain detection
- Null-cipher Security Mode Command analysis
- Handover injection without MeasurementReport
- Cross-carrier simultaneous presence (dual-device attribution)
- Timing advance persistence and TA stability analysis
- Behavioral rhythm fingerprinting (temporal operational patterns)
- Regulatory escalation correlation scoring
- Hardware attribution scoring (Harris, srsRAN, PKI, and others)
- JitterDNA periodic timing analysis
- **Shannon IMS baseband log parsing** — firmware-layer independent corroboration

---

## Shannon IMS Parser — firmware-layer detection

### What it does

The Shannon IMS parser reads standard Android bug reports and extracts `RILC_UNSOL_IMS_SUPPORT_SERVICE` events logged by the Samsung Shannon baseband modem at firmware level. These events record the Cell ID (CID), Tracking Area Code (TAC), and PLMN of every cell the modem registers to — independently of any passive capture tool.

The parser cross-references these events against a configurable known rogue CID list and produces a finding flagged as **firmware-layer independent corroboration** — a separate evidence class from RF capture data entirely.

### Why it matters

If passive capture tools (Rayhunter, CASTNET) detect a rogue cell, and separately the phone's own modem firmware independently logged connecting to the same CID, those are two different evidence classes from two independent methodologies. That combination directly counters the "equipment malfunction" or "testing signal" dismissal that investigators and carriers commonly use when a single-source detection is challenged.

The independence is real and legally significant: `com.shannon.imsservice` is Samsung's proprietary IMS stack running at firmware level, pid-isolated, logging unsolicited hardware notifications before any user-space application is involved. It cannot be influenced by Rayhunter or any other capture tool.

### Device compatibility

The Samsung Shannon modem (Exynos modem series) is used across:

- **Every Google Pixel device from Pixel 6 through Pixel 10** (all variants including Pro, XL, Fold, a-series)
- **Every device currently supported by GrapheneOS** — GrapheneOS only supports Pixel hardware, and every supported Pixel uses a Shannon-based modem
- **Samsung Galaxy international variants** (non-US markets where Exynos is used instead of Snapdragon)

Combined with the existing QMDL pipeline (which processes Qualcomm DIAG output from devices like the TP-Link M7350), the tool achieves corroboration across approximately **95% of the Android device ecosystem** (Counterpoint Research, 2025–2026: Qualcomm ~25%, MediaTek ~34%, Samsung Exynos ~12% of global smartphone SoC shipments; Apple iOS is a separate locked ecosystem not applicable to this tool).

### How to generate the evidence

On any supported Android device:

**Settings → About phone → Bug report (Full)**

The resulting archive contains a `bugreport-[device]-[timestamp].txt` file. Point the analyzer at the directory containing that file using `--bug-reports`.

### Caveats

- Retrospective forensic corroboration only — not real-time detection
- Bug report must be generated while the device is in range of the rogue cell, or shortly after
- Requires a known rogue CID list to cross-reference against (configured in `config.yaml`)
- Pixel 11 series (Tensor G6) may move to a MediaTek modem — applicability to that generation unconfirmed

---

## Supported input formats

| Format | Source | Notes |
|--------|--------|-------|
| `.ndjson` | Rayhunter alert files | Primary format — full event data with PLMN per cell |
| `.pcap` / `.pcapng` | Rayhunter + Wireshark | Requires `tshark` for full decode |
| `.qmdl` | Qualcomm DIAG modem output | Raw physical layer — install pySCAT for full NAS dissection |
| `.txt` (bug report) | Android bug report | Shannon IMS parser — firmware-layer corroboration |

---

## Quick start

```bash
# Clone
git clone https://github.com/JulianBurns85/rayhunter-threat-analyzer.git
cd rayhunter-threat-analyzer

# Install dependencies
pip install -r requirements.txt

# Optional: tshark for PCAP support
# Ubuntu/Debian: sudo apt install tshark
# Windows: install Wireshark from https://wireshark.org

# Optional: pySCAT for full QMDL NAS dissection
pip install git+https://github.com/fgsect/scat.git

# Run analysis
python main.py --dir /path/to/rayhunter/captures

# With Shannon IMS bug report analysis
python main.py --dir /path/to/captures --bug-reports /path/to/bug_reports/

# Full forensic run with HTML report and SHA-256 manifest
python main.py --dir /path/to/captures --bug-reports /path/to/bug_reports/ --manifest --html --output report.json
```

---

## CLI reference

```
python main.py [options]

Input:
  --file FILE, -f FILE      Input file (NDJSON, PCAP, QMDL). Repeatable.
  --dir DIR, -d DIR         Scan directory recursively for all supported files.
  --bug-reports DIR         Directory containing Android bug report .txt files.

Output:
  --output FILE, -o FILE    Write JSON report to file.
  --html                    Generate interactive HTML forensic report.
  --manifest                Generate SHA-256 forensic file manifest.
  --timeline                Generate cross-session event timeline.
  --export-pcap             Export flagged events as PCAPNG.

Analysis:
  --mcc MCC                 Override MCC filter (e.g. 505 for Australia).
  --mnc MNC                 Override MNC (e.g. 001=Telstra, 003=Vodafone AU).
  --config FILE, -c FILE    Config file (default: config.yaml).
  --verbose, -v             Verbose output.

Advanced:
  --compare A.json B.json   Diff two report JSONs to track changes over time.
  --watch                   Watch mode — re-analyze when new files appear.
```

---

## Configuration

Edit `config.yaml` to set your known rogue CID list, carrier filters, and bug report directory:

```yaml
bug_report_dir: "/path/to/bug_reports"

detection:
  rogue_tower:
    known_rogue_cids:
      - 137713165
      - 137713175
      - 137713195
    known_rogue_tacs:
      - 12385
      - 30336
```

---

## Hardware requirements

Rayhunter runs on TP-Link M7350 (and equivalent) devices. See the [Rayhunter project](https://github.com/EFForg/rayhunter) for hardware setup.

The Shannon IMS parser requires any Android device with a Samsung Exynos (Shannon) modem — all Google Pixel 6 through Pixel 10 devices qualify.

---

## Detection framework

Findings are scored against YAICD (Ziayi et al., 2021) across 10 heuristics. Each finding carries a severity rating (CRITICAL / HIGH / MEDIUM / LOW), confirmation status (CONFIRMED / PROBABLE / POSSIBLE), and a full evidence block with 3GPP specification citations.

---

## License

MIT — free to use, modify, and distribute.

---

## Repository

[github.com/JulianBurns85/rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer)
