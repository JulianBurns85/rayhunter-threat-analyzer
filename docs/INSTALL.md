# Rayhunter Threat Analyzer v2.0 — Integration Guide

## What This Upgrade Does

Replaces the basic `hardware_fingerprint.py` with the full IntelligenceDB engine:
- **28 attack records** with 3GPP citations (from Tucker et al. 2025, Dabrowski 2016, SeaGlass, PKI catalogue)
- **13 device entries** — srsRAN, YateBTS, OsmocomBB, PKI 1625/1650/1540, Harris StingRay/Hailstorm/KingFish, DRT Dirtbox
- **5 attacker profiles** — automated srsRAN, LE passive, LE full intercept, state actor, amateur
- **Per-finding rating cards** with severity score, attack type, skill level, device attribution, 3GPP refs
- **IMSI Exposure Ratio** calculation (Tucker et al. methodology — <3% LTE = normal, >15% = anomaly)
- **Operator Assessment** panel — danger score, likely actor, matched profile
- **Forensic citation registry** — all source citations printed and saved to JSON

---

## File Layout After Integration

```
rayhunter-threat-analyzer/
├── main.py                          ← REPLACE with main.py from this package
├── reporter.py                      ← PATCH (add 5 methods — see Step 3)
├── intelligence/
│   ├── hardware_fingerprint.py      ← REPLACE with hardware_fingerprint.py from this package
│   ├── db_engine.py                 ← NEW — copy from this package
│   └── db/                          ← NEW — create this directory
│       ├── SCHEMA.md
│       ├── attacks/
│       │   ├── 01_identity_harvest.yaml
│       │   ├── 02_cipher_rat_downgrade.yaml
│       │   └── 03_rrc_paging_behavioral.yaml
│       ├── devices/
│       │   ├── 01_opensource_sdr.yaml
│       │   ├── 02_pki_electronic.yaml
│       │   └── 03_harris_drt_state.yaml
│       └── profiles/
│           └── attacker_profiles.yaml
└── ... (all other existing files unchanged)
```

---

## Step 1 — Copy the database files

In your repo root, create the `intelligence/db/` directory tree:

```powershell
# Windows PowerShell
mkdir intelligence\db\attacks
mkdir intelligence\db\devices
mkdir intelligence\db\profiles
```

Copy these files into those directories:
- `SCHEMA.md` → `intelligence/db/SCHEMA.md`
- `attacks/01_identity_harvest.yaml` → `intelligence/db/attacks/`
- `attacks/02_cipher_rat_downgrade.yaml` → `intelligence/db/attacks/`
- `attacks/03_rrc_paging_behavioral.yaml` → `intelligence/db/attacks/`
- `devices/01_opensource_sdr.yaml` → `intelligence/db/devices/`
- `devices/02_pki_electronic.yaml` → `intelligence/db/devices/`
- `devices/03_harris_drt_state.yaml` → `intelligence/db/devices/`
- `profiles/attacker_profiles.yaml` → `intelligence/db/profiles/`

---

## Step 2 — Replace intelligence/hardware_fingerprint.py

Backup the old file first:
```powershell
copy intelligence\hardware_fingerprint.py intelligence\hardware_fingerprint.py.bak
```

Then replace it with the new `hardware_fingerprint.py` from this package.

---

## Step 3 — Copy db_engine.py into the intelligence/ directory

```powershell
copy db_engine.py intelligence\db_engine.py
```

---

## Step 4 — Replace main.py

Backup first:
```powershell
copy main.py main.py.bak
```

Replace with the new `main.py` from this package.

---

## Step 5 — Patch reporter.py

Open your existing `reporter.py` and make these two changes:

### 5a — Add 5 new methods to ThreatReporter class

Copy these method bodies from `reporter_v2_additions.py` and paste them
inside the `class ThreatReporter:` block (anywhere after `__init__`):

- `print_rating_cards(self, enriched_findings)`
- `_print_rating_cards_plain(self, enriched_findings)`
- `print_operator_assessment(self, intel)`
- `_print_operator_assessment_plain(self, intel)`
- `print_citation_summary(self, enriched_findings)`
- `_serialize_enriched(self, data)`
- `_serialize_assessment(self, data)`

### 5b — Add v2.0 calls to print_terminal()

Find `print_terminal()` in reporter.py. After the section that prints
hardware candidates, add:

```python
# v2.0 — rating cards, operator assessment, citations
if report.get("enriched_findings"):
    self.print_rating_cards(report["enriched_findings"])
if report.get("intelligence_v2"):
    self.print_operator_assessment(report["intelligence_v2"])
if report.get("enriched_findings"):
    self.print_citation_summary(report["enriched_findings"])
```

### 5c — Add v2.0 keys to build_report()

Find `build_report()` in reporter.py. Before the `return report` line, add:

```python
# v2.0 intelligence enrichment
report["enriched_findings"] = self._serialize_enriched(data)
report["intelligence_v2"]   = self._serialize_assessment(data)
```

---

## Step 6 — Test

```powershell
cd C:\rayhunter-threat-analyzer-main
python main.py --dir C:\path\to\your\captures --verbose
```

You should see:
1. Banner updated to v2.0
2. `[IntelligenceDB] Loaded: 28 attacks, 13 devices, 5 profiles`
3. All existing findings (unchanged)
4. New **FINDING INTELLIGENCE — RATING CARDS** section
5. New **OPERATOR ASSESSMENT** panel with danger score
6. New **FORENSIC CITATION REGISTRY** at the bottom
7. JSON output now includes `intelligence_v2` and `enriched_findings` keys

---

## Troubleshooting

**"IntelligenceDB Warning: database not loaded"**
→ Check that `intelligence/db/` exists with the YAML files.
   Run: `dir intelligence\db\attacks\` — should show 3 YAML files.

**"Failed to load pyyaml"**
→ `pip install pyyaml --break-system-packages`

**"ModuleNotFoundError: intelligence.db_engine"**
→ Make sure `db_engine.py` is in `intelligence/` not in root.
   Also check `intelligence/__init__.py` exists (even empty is fine).

**Rating cards appear but all devices say "Unknown"**
→ YAML files not found. Check db/ path. Run with `--verbose`.

---

## Updating the Database

The database is plain YAML — add new attack or device entries by editing
the YAML files directly. No code changes needed. Restart the analyzer
and the new entries load automatically.

To add a new device entry, copy the structure from an existing device
YAML and fill in the fields. Source quality must be HIGH/MEDIUM/LOW.
All entries require at least one `sources` citation.
