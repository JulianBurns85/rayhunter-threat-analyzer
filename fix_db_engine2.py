# This script patches db_engine.py to handle both list-of-records format
# AND the existing document format (title/attack_taxonomy structure)

with open('intelligence/db_engine.py', encoding='utf-8') as f:
    content = f.read()

# Find the _load_attacks method and replace its core loop
# The existing YAMLs use 'title' not 'id', and have nested attack_taxonomy
# We need to handle both formats

old = """                with open(yaml_file, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or []
                if isinstance(raw, dict):
                    records = [raw]
                elif isinstance(raw, list):
                    records = raw
                else:
                    records = []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    attack = AttackRecord(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        category=rec.get("category", ""),
                        severity_score=rec.get("severity", {}).get("score", 5),
                        severity_level=rec.get("severity", {}).get("level", "MEDIUM"),
                        severity_rationale=rec.get("severity", {}).get("rationale", ""),
                        description=rec.get("description", ""),
                        detection_signature=rec.get("detection_signature", {}),
                        automation=rec.get("automation", {}),
                        skill_required=rec.get("skill_required", "UNKNOWN"),
                        compatible_devices=rec.get("compatible_devices", []),
                        sources=rec.get("sources", []),
                        generation=rec.get("generation", []),
                        standard_ref=rec.get("standard_ref", ""),
                    )
                    if attack.id:
                        self.attacks[attack.id] = attack
                        count += 1"""

new = """                with open(yaml_file, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                # Handle both formats:
                # Format A: list of {id, name, category, ...} records
                # Format B: document with {title, attack_taxonomy, ...} structure
                if isinstance(raw, list):
                    records = raw
                elif isinstance(raw, dict):
                    # Check if it's a document-format YAML
                    if "attack_taxonomy" in raw or "title" in raw:
                        # Build a single AttackRecord from the document
                        doc_id = yaml_file.stem
                        rec = {
                            "id": doc_id,
                            "name": raw.get("title", doc_id),
                            "category": "imsi_catcher_technique",
                            "severity": {"score": 7, "level": "HIGH", "rationale": ""},
                            "description": raw.get("title", ""),
                            "detection_signature": {},
                            "automation": {},
                            "skill_required": "MEDIUM",
                            "compatible_devices": [],
                            "sources": [raw.get("url", "")],
                            "generation": ["LTE"],
                            "standard_ref": "",
                        }
                        records = [rec]
                    else:
                        records = [raw]
                else:
                    records = []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    attack = AttackRecord(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        category=rec.get("category", ""),
                        severity_score=rec.get("severity", {}).get("score", 5),
                        severity_level=rec.get("severity", {}).get("level", "MEDIUM"),
                        severity_rationale=rec.get("severity", {}).get("rationale", ""),
                        description=rec.get("description", ""),
                        detection_signature=rec.get("detection_signature", {}),
                        automation=rec.get("automation", {}),
                        skill_required=rec.get("skill_required", "UNKNOWN"),
                        compatible_devices=rec.get("compatible_devices", []),
                        sources=rec.get("sources", []),
                        generation=rec.get("generation", []),
                        standard_ref=rec.get("standard_ref", ""),
                    )
                    if attack.id:
                        self.attacks[attack.id] = attack
                        count += 1"""

if old in content:
    content = content.replace(old, new, 1)
    print("Fixed _load_attacks")
else:
    print("WARNING: _load_attacks pattern not found — checking what's there")
    # Find approximate location
    idx = content.find("with open(yaml_file, encoding")
    if idx > 0:
        print(f"Found encoding open at char {idx}")
        print(repr(content[idx:idx+200]))

# Fix _load_devices similarly
old2 = """                with open(yaml_file) as f:
                    records = yaml.safe_load(f) or []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    device = DeviceRecord("""

new2 = """                with open(yaml_file, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                if isinstance(raw, list):
                    records = raw
                elif isinstance(raw, dict):
                    if "manufacturer" in raw or "device_family" in raw or "metadata" in raw:
                        doc_id = yaml_file.stem
                        meta = raw.get("metadata", raw)
                        rec = {
                            "id": doc_id,
                            "name": meta.get("title", doc_id),
                            "tier": "COMMERCIAL",
                            "manufacturer": meta.get("manufacturer", raw.get("manufacturer", "Unknown")),
                            "supported_rats": raw.get("capabilities", {}).get("network_generations", []),
                            "attack_capabilities": raw.get("capabilities", {}).get("attack_modes", []),
                            "behavioral_fingerprints": [],
                            "operator_skill_required": "HIGH",
                            "source_quality": "MEDIUM",
                            "sources": raw.get("references", []),
                            "description": meta.get("title", ""),
                            "specifications": {},
                        }
                        records = [rec]
                    else:
                        records = [raw]
                else:
                    records = []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    device = DeviceRecord("""

if old2 in content:
    content = content.replace(old2, new2, 1)
    print("Fixed _load_devices")
else:
    # Try the already-patched version
    old2b = """                with open(yaml_file, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or []
                if isinstance(raw, dict):
                    records = [raw]
                elif isinstance(raw, list):
                    records = raw
                else:
                    records = []
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    device = DeviceRecord("""

    if old2b in content:
        content = content.replace(old2b, new2, 1)
        print("Fixed _load_devices (patched version)")
    else:
        print("WARNING: _load_devices pattern not found")

with open('intelligence/db_engine.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done.")
