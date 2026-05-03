#!/usr/bin/env python3
"""Config loader — reads config.yaml with fallback defaults."""
import os
import yaml
from pathlib import Path


DEFAULTS = {
    "network": {
        "mcc": "505",
        "mnc": "001",           # Telstra AU default; override to 003 for Vodafone
        "country": "AU",
        "operator": "Telstra",
    },
    "opencellid": {
        "enabled": False,       # Set True and add api_key to enable live lookups
        "api_key": "",
        "cache_file": "cell_cache.json",
        "timeout_seconds": 5,
    },
    "thresholds": {
        "identity_request_window_seconds": 120,
        "identity_request_max_normal": 2,
        "earfcn_change_window_seconds": 60,
        "earfcn_change_max_normal": 3,
        "paging_imsi_ratio_threshold": 0.2,  # >20% IMSI paging = suspicious
        "handover_max_without_measreport": 2,
    },
    "known_rogue_cells": {
        # Pre-populate with confirmed rogue cells from your investigation.
        # Format: "MCC-MNC-CellID": {"earfcn": X, "notes": "..."}
        "505-001-ROGUE1": {
            "notes": "Confirmed rogue - investigation CIRS-20260331-141"
        }
    },
    "known_rogue_earfcns": [
        # EARFCNs seen simultaneously across rogue cells in your investigation.
        # Add confirmed anomalous EARFCNs here.
    ],
    "ubiquiti_oui": ["24:A4:3C", "FC:EC:DA", "78:8A:20", "B4:FB:E4", "00:27:22"],
    "hak5_oui": ["00:13:37"],
    "output": {
        "color": True,
        "show_raw_evidence": True,
        "max_evidence_lines": 5,
    },
}


def load(config_path: str = "config.yaml") -> dict:
    """Load config from YAML file, merging with defaults."""
    cfg = _deep_copy(DEFAULTS)

    path = Path(config_path)
    if path.exists():
        try:
            with open(path) as f:
                user_cfg = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, user_cfg)
        except Exception as e:
            print(f"[WARN] Could not load config {config_path}: {e}. Using defaults.")
    else:
        if config_path != "config.yaml":
            print(f"[WARN] Config file not found: {config_path}. Using defaults.")

    return cfg


def _deep_copy(d):
    import copy
    return copy.deepcopy(d)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
