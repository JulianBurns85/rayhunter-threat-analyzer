#!/usr/bin/env python3
"""
Cell Database — OpenCelliD API Wrapper + Local Cache
=====================================================
Provides cell tower lookup against OpenCelliD crowd-sourced database.
Results are cached locally to minimise API calls.

Free API key: https://opencellid.org/register
Rate limit:   1000 requests/day on free tier

Usage:
    db = CellDB(cfg)
    result = db.lookup(mcc="505", mnc="001", tac="1234", cell_id="987654")
    if result is None:
        print("Cell not in database — possible rogue tower")
    elif result:
        print(f"Cell registered at {result['lat']},{result['lon']}")
"""

import json
import time
from pathlib import Path
from typing import Optional, Dict


class CellDB:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        oc_cfg = cfg.get("opencellid", {})
        self.enabled = oc_cfg.get("enabled", False)
        self.api_key = oc_cfg.get("api_key", "")
        self.timeout = oc_cfg.get("timeout_seconds", 5)
        self.cache_file = Path(oc_cfg.get("cache_file", "cell_cache.json"))
        self._cache: Dict[str, Optional[dict]] = self._load_cache()
        self._last_request = 0.0
        self._min_interval = 1.0  # 1 second between requests

    def lookup(self, mcc: str, mnc: str, tac: str,
               cell_id: str) -> Optional[dict]:
        """
        Look up a cell in OpenCelliD.

        Returns:
            dict  — cell is registered (contains lat, lon, range, etc.)
            None  — cell is NOT in database (rogue tower indicator)
            {}    — lookup skipped (disabled or no API key)
        """
        if not self.enabled or not self.api_key:
            return {}

        cache_key = f"{mcc}-{mnc}-{tac}-{cell_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Rate limiting
        now = time.time()
        if now - self._last_request < self._min_interval:
            time.sleep(self._min_interval - (now - self._last_request))
        self._last_request = time.time()

        try:
            import requests
            resp = requests.get(
                "https://opencellid.org/cell/get",
                params={
                    "token": self.api_key,
                    "mcc": mcc,
                    "mnc": mnc,
                    "lac": tac,
                    "cellid": cell_id,
                    "format": "json",
                },
                timeout=self.timeout,
            )
            data = resp.json()
            if data.get("status") == "ok":
                result = {
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "range": data.get("range"),

                    "samples": data.get("samples"),
                    "source": "opencellid",
                }
                self._cache[cache_key] = result
                self._save_cache()
                return result
            else:
                # status == "error" → cell not found
                self._cache[cache_key] = None
                self._save_cache()
                return None

        except Exception as e:
            # Network error — don't cache, just return empty
            return {}

    def add_known_rogue(self, mcc: str, mnc: str, tac: str,
                        cell_id: str, notes: str = ""):
        """Manually mark a cell as confirmed rogue in local cache."""
        key = f"{mcc}-{mnc}-{tac}-{cell_id}"
        self._cache[key] = {"rogue": True, "notes": notes, "source": "manual"}
        self._save_cache()

    def is_known_rogue(self, mcc: str, mnc: str, tac: str,
                       cell_id: str) -> bool:
        """Check if cell is manually marked as rogue."""
        key = f"{mcc}-{mnc}-{tac}-{cell_id}"
        entry = self._cache.get(key)
        return bool(entry and entry.get("rogue"))

    def _load_cache(self) -> dict:
        try:
            with open(self.cache_file) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    @property
    def cache_size(self) -> int:
        return len(self._cache)
