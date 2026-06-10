with open('intelligence/db_engine.py', encoding='utf-8') as f:
    content = f.read()

# Fix _load_attacks: handle document formats with attack_id, title, or id
# Also handle srsran/heuristic format with attack_id key
old = """                    attack = AttackRecord(
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

new = """                    # Support multiple ID field names across YAML formats
                    rec_id = (rec.get("id") or rec.get("attack_id") or
                              rec.get("device_id") or rec.get("title") or
                              yaml_file.stem)
                    attack = AttackRecord(
                        id=rec_id,
                        name=rec.get("name", rec.get("title", rec_id)),
                        category=rec.get("category", "imsi_catcher_technique"),
                        severity_score=rec.get("severity", {}).get("score", 5) if isinstance(rec.get("severity"), dict) else 5,
                        severity_level=rec.get("severity", {}).get("level", "MEDIUM") if isinstance(rec.get("severity"), dict) else "MEDIUM",
                        severity_rationale=rec.get("severity", {}).get("rationale", "") if isinstance(rec.get("severity"), dict) else "",
                        description=rec.get("description", rec.get("title", "")),
                        detection_signature=rec.get("detection_signature", {}),
                        automation=rec.get("automation", {}),
                        skill_required=rec.get("skill_required", "UNKNOWN"),
                        compatible_devices=rec.get("compatible_devices", []),
                        sources=rec.get("sources", []),
                        generation=rec.get("generation", ["LTE"]),
                        standard_ref=rec.get("standard_ref", ""),
                    )
                    if attack.id:
                        self.attacks[attack.id] = attack
                        count += 1"""

if old in content:
    content = content.replace(old, new, 1)
    print("Fixed AttackRecord construction")
else:
    print("WARNING: AttackRecord pattern not found")

# Fix _load_devices: handle device_id field name
old2 = """                    device = DeviceRecord(
                        id=rec.get("id", ""),
                        name=rec.get("name", ""),
                        tier=rec.get("tier", "UNKNOWN"),
                        manufacturer=rec.get("manufacturer", "Unknown"),
                        supported_rats=rec.get("supported_rats", []),
                        attack_capabilities=rec.get("attack_capabilities", []),
                        behavioral_fingerprints=rec.get("behavioral_fingerprints", []),
                        operator_skill_required=rec.get("operator_skill_required", "UNKNOWN"),
                        source_quality=rec.get("source_quality", "LOW"),
                        sources=rec.get("sources", []),
                        description=rec.get("description", ""),
                        specifications=rec.get("specifications", {}),
                    )
                    if device.id:
                        self.devices[device.id] = device
                        count += 1"""

new2 = """                    # Support multiple ID field names across YAML formats
                    rec_id = (rec.get("id") or rec.get("device_id") or
                              rec.get("attack_id") or rec.get("title") or
                              yaml_file.stem)
                    meta = rec.get("metadata", rec)
                    device = DeviceRecord(
                        id=rec_id,
                        name=rec.get("name", meta.get("title", rec_id)),
                        tier=rec.get("tier", rec.get("access_tier", "UNKNOWN")),
                        manufacturer=rec.get("manufacturer", meta.get("manufacturer", "Unknown")),
                        supported_rats=rec.get("supported_rats", rec.get("capabilities", {}).get("network_generations", [])),
                        attack_capabilities=rec.get("attack_capabilities", rec.get("capabilities", {}).get("attack_modes", [])),
                        behavioral_fingerprints=rec.get("behavioral_fingerprints", []),
                        operator_skill_required=rec.get("operator_skill_required", "UNKNOWN"),
                        source_quality=rec.get("source_quality", meta.get("source_confidence", "LOW")),
                        sources=rec.get("sources", rec.get("references", [])),
                        description=rec.get("description", meta.get("title", "")),
                        specifications=rec.get("specifications", rec.get("timing_signatures", {})),
                    )
                    if device.id:
                        self.devices[device.id] = device
                        count += 1"""

if old2 in content:
    content = content.replace(old2, new2, 1)
    print("Fixed DeviceRecord construction")
else:
    print("WARNING: DeviceRecord pattern not found")

with open('intelligence/db_engine.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done.")
