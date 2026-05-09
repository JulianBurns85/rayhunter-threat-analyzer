#!/usr/bin/env python3
"""
Manifest Generator — SHA-256 Forensic File Manifest
=====================================================
Generates a tamper-evident SHA-256 manifest of all input files.
Essential for legal admissibility — establishes chain of custody
and proves files have not been modified since analysis.

Usage (via main.py):
    python main.py --dir C:\ray --manifest

Output: rayhunter_manifest_<timestamp>.csv + .json
"""

import hashlib
import json
import csv
import time
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 hash of a file. Returns hex digest."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError) as e:
        return f"ERROR: {e}"


def generate_manifest(files: Dict[str, List[str]], output_dir: str = ".") -> Dict:
    """
    Generate SHA-256 manifest for all input files.
    
    Args:
        files: dict of {type: [filepath, ...]} from main.py collect_files()
        output_dir: where to write manifest files
    
    Returns:
        manifest dict with all hashes and metadata
    """
    generated_at = datetime.now(tz=timezone.utc).isoformat()
    
    manifest = {
        "manifest_version": "1.0",
        "generated_at": generated_at,
        "tool": "Rayhunter Threat Analyzer v1.0",
        "purpose": "SHA-256 forensic file manifest for legal chain of custody",
        "legal_note": (
            "This manifest was generated at the time of forensic analysis. "
            "Each file's SHA-256 hash can be independently verified to confirm "
            "the files have not been modified since this manifest was produced."
        ),
        "files": [],
        "summary": {
            "total_files": 0,
            "total_bytes": 0,
            "ndjson_count": 0,
            "pcap_count": 0,
            "qmdl_count": 0,
            "errors": 0,
        }
    }

    all_files = []
    for file_type, paths in files.items():
        for path in paths:
            all_files.append((file_type, path))

    print(f"\n  Generating SHA-256 manifest for {len(all_files)} files...")

    for idx, (file_type, filepath) in enumerate(sorted(all_files, key=lambda x: x[1])):
        p = Path(filepath)
        
        try:
            size = p.stat().st_size
            mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            size = 0
            mtime = "UNKNOWN"

        if (idx + 1) % 50 == 0:
            print(f"    Hashed {idx + 1}/{len(all_files)} files...")

        sha256 = sha256_file(filepath)
        is_error = sha256.startswith("ERROR")

        entry = {
            "filename": p.name,
            "filepath": str(filepath),
            "file_type": file_type,
            "size_bytes": size,
            "sha256": sha256,
            "modified_at": mtime,
            "hash_error": is_error,
        }
        manifest["files"].append(entry)

        # Update summary
        manifest["summary"]["total_files"] += 1
        manifest["summary"]["total_bytes"] += size
        if is_error:
            manifest["summary"]["errors"] += 1
        if file_type == "ndjson":
            manifest["summary"]["ndjson_count"] += 1
        elif file_type == "pcap":
            manifest["summary"]["pcap_count"] += 1
        elif file_type == "qmdl":
            manifest["summary"]["qmdl_count"] += 1

    # Generate manifest hash (hash of all hashes — tamper detection)
    all_hashes = "".join(
        e["sha256"] for e in manifest["files"] 
        if not e.get("hash_error")
    )
    manifest["manifest_hash"] = hashlib.sha256(all_hashes.encode()).hexdigest()
    manifest["summary"]["total_size_mb"] = round(
        manifest["summary"]["total_bytes"] / 1024 / 1024, 2
    )

    # Write JSON manifest
    ts = int(time.time())
    json_path = Path(output_dir) / f"rayhunter_manifest_{ts}.json"
    csv_path  = Path(output_dir) / f"rayhunter_manifest_{ts}.csv"

    with open(json_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Write CSV manifest (easier to open in Excel/court exhibits)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Filename", "File Type", "Size (bytes)", "SHA-256",
            "Modified At", "Full Path", "Hash Error"
        ])
        for entry in manifest["files"]:
            writer.writerow([
                entry["filename"],
                entry["file_type"],
                entry["size_bytes"],
                entry["sha256"],
                entry["modified_at"],
                entry["filepath"],
                "YES" if entry["hash_error"] else "NO",
            ])

    print(f"\n  Manifest generated:")
    print(f"    Files hashed:    {manifest['summary']['total_files']}")
    print(f"    Total size:      {manifest['summary']['total_size_mb']} MB")
    print(f"    Errors:          {manifest['summary']['errors']}")
    print(f"    Manifest hash:   {manifest['manifest_hash'][:32]}...")
    print(f"    JSON:            {json_path}")
    print(f"    CSV:             {csv_path}")

    return manifest
