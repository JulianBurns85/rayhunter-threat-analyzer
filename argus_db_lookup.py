"""
argus_db_lookup.py — Standalone Argus-DB Lookup Module
Shared utility for SENTRY (RF monitor) and rayhunter-threat-analyzer.

Usage from SENTRY alert pipeline:
    from argus_db_lookup import ArgusDbLookup
    db = ArgusDbLookup()
    match = db.lookup_vendor("harris")
    if match:
        print(f"argus-db: {match['description']} [conf={match['confidence']}]")

Usage for MAC OUI lookup (if BLE/WiFi scan alongside cellular):
    match = db.lookup_mac("e4:aa:ea")
    if match:
        print(f"Known surveillance device: {match['description']}")

Source: github.com/kevwillow/argus-db
License: ODbL-1.0 (data)
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# The JSON export files are metadata-only (no records embedded).
# All identifier records live in the CSV export.
ARGUS_CSV_URL = (
    "https://raw.githubusercontent.com/kevwillow/argus-db/main/"
    "exports/argus_export.csv"
)
# Keep JSON URLs for future use if format changes
ARGUS_BEHAVIORAL_URL = (
    "https://raw.githubusercontent.com/kevwillow/argus-db/main/"
    "exports/argus_export_behavioral_signatures.json"
)
ARGUS_HIGH_CONF_URL = (
    "https://raw.githubusercontent.com/kevwillow/argus-db/main/"
    "exports/argus_export_high_confidence.json"
)

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".argus_cache")
BEHAVIORAL_CACHE = os.path.join(CACHE_DIR, "argus_behavioral.json")
HIGHCONF_CACHE   = os.path.join(CACHE_DIR, "argus_highconf.json")
CSV_CACHE        = os.path.join(CACHE_DIR, "argus_export.csv")
CACHE_META       = os.path.join(CACHE_DIR, "cache_meta.json")
CACHE_TTL_HOURS  = 24

VENDOR_FRAGMENTS = {
    "harris":    ["harris", "l3harris", "hailstorm", "stingray"],
    "septier":   ["septier"],
    "rohde":     ["rohde", "r&s", "rohde & schwarz"],
    "cognyte":   ["cognyte", "nice systems", "verint"],
    "trovicor":  ["trovicor"],
    "ss8":       ["ss8 networks"],
    "cellebrite":["cellebrite"],
    "anduril":   ["anduril"],
    "flock":     ["flock safety", "flock"],
    "grayshift": ["grayshift"],
}


class ArgusDbLookup:
    """
    Thin lookup interface for argus-db exports.
    Safe to instantiate multiple times — caches are shared on disk.
    """

    def __init__(self, cache_dir: str = CACHE_DIR, ttl_hours: int = CACHE_TTL_HOURS):
        self.cache_dir        = cache_dir
        self.behavioral_cache = os.path.join(cache_dir, "argus_behavioral.json")
        self.highconf_cache   = os.path.join(cache_dir, "argus_highconf.json")
        self.csv_cache        = os.path.join(cache_dir, "argus_export.csv")
        self.meta_cache       = os.path.join(cache_dir, "cache_meta.json")
        self.ttl_hours        = ttl_hours
        self._behavioral: list = []
        self._highconf: list   = []
        self._loaded = False

    def load(self, force_refresh: bool = False) -> bool:
        """Load argus-db exports into memory. Returns True on success."""
        os.makedirs(self.cache_dir, exist_ok=True)
        if force_refresh or not self._cache_fresh():
            self._refresh()
        # The JSON exports are metadata-only in argus-db v1.6.5+.
        # All identifier records are in the CSV export.
        self._behavioral = self._read_csv_cache(self.csv_cache, category_filter={
            "network_surveillance", "imsi_catcher", "cell_site_simulator",
        })
        self._highconf = self._read_csv_cache(self.csv_cache)  # all categories
        self._loaded = bool(self._highconf)
        if self._loaded:
            logger.debug(
                f"[ARGUS_DB] Loaded {len(self._highconf)} total rows "
                f"({len(self._behavioral)} network_surveillance)"
            )
        return self._loaded

    # ── Public lookup methods ─────────────────────────────────────────────────

    def lookup_vendor(self, vendor_key: str) -> Optional[dict]:
        """
        Look up a vendor by key (e.g. 'harris', 'rohde', 'septier').
        Returns the highest-confidence matching row, or None.
        """
        if not self._loaded:
            self.load()
        fragments = VENDOR_FRAGMENTS.get(vendor_key.lower(), [vendor_key.lower()])
        best = None
        for row in self._all_rows():
            text = self._row_text(row)
            if any(f in text for f in fragments):
                if best is None or row.get("confidence", 0) > best.get("confidence", 0):
                    best = row
        return best

    def lookup_mac(self, mac_prefix: str) -> Optional[dict]:
        """
        Look up a MAC address or OUI prefix (e.g. 'e4:aa:ea' or 'e4:aa:ea:80:a1:9b').
        Returns the best match or None.
        """
        if not self._loaded:
            self.load()
        mac_lower = mac_prefix.lower().strip()
        # Normalise to colon-separated lowercase
        mac_clean = mac_lower.replace("-", ":").replace(".", ":")
        oui = ":".join(mac_clean.split(":")[:3])   # First 3 octets = OUI
        for row in self._all_rows():
            if str(row.get("pattern_type", "")).lower() in ("mac", "oui"):
                pattern = str(row.get("pattern", "")).lower()
                if pattern.startswith(oui) or mac_clean.startswith(pattern):
                    return row
        return None

    def lookup_enb_vendor(self, enb_id: int) -> Optional[dict]:
        """
        Look up an eNB ID against known surveillance hardware ranges.
        Returns a match if the eNB ID falls within a known surveillance vendor range.
        Note: argus-db doesn't currently index by eNB ID, but this method
        provides a hook for future integration when such data is available.
        """
        # Placeholder — currently eNB IDs aren't indexed in argus-db
        # Future: when argus-db adds cellular_cell_id pattern_type
        return None

    def network_surveillance_vendors(self) -> list:
        """Return all active network_surveillance category rows."""
        if not self._loaded:
            self.load()
        return [
            r for r in self._all_rows()
            if "surveillance" in str(r.get("device_category", "")).lower()
            or "imsi" in str(r.get("device_category", "")).lower()
        ]

    def behavioral_signatures_for_category(self, category: str) -> list:
        """Return behavioral signatures matching a device category."""
        if not self._loaded:
            self.load()
        return [
            r for r in self._behavioral
            if category.lower() in str(r.get("device_category", "")).lower()
        ]

    def stats(self) -> dict:
        """Return dataset statistics."""
        if not self._loaded:
            self.load()
        meta = {}
        if os.path.exists(self.meta_cache):
            try:
                with open(self.meta_cache) as f:
                    meta = json.load(f)
            except Exception:
                pass
        return {
            "behavioral_rows": len(self._behavioral),
            "highconf_rows": len(self._highconf),
            "cache_fresh": self._cache_fresh(),
            "fetched_at": meta.get("fetched_at", "unknown"),
            "network_surveillance_rows": len(self.network_surveillance_vendors()),
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _all_rows(self) -> list:
        def _as_list(x):
            if isinstance(x, list):  return x
            if isinstance(x, dict):  return list(x.values()) if x else []
            return []
        return _as_list(self._behavioral) + _as_list(self._highconf)

    @staticmethod
    def _row_text(row: dict) -> str:
        return " ".join([
            str(row.get("description", "")),
            str(row.get("manufacturer", "")),
            str(row.get("pattern", "")),
            str(row.get("notes", "")),
        ]).lower()

    def _cache_fresh(self) -> bool:
        if not os.path.exists(self.meta_cache):
            return False
        try:
            with open(self.meta_cache) as f:
                ts = datetime.fromisoformat(json.load(f).get("fetched_at", "2000-01-01"))
            return (datetime.now(timezone.utc) - ts) < timedelta(hours=self.ttl_hours)
        except Exception:
            return False

    def _refresh(self) -> None:
        logger.info("[ARGUS_DB] Fetching argus-db CSV export ...")
        # Records are in the CSV (JSON files are metadata-only in v1.6.5+)
        csv_data = self._fetch_csv(ARGUS_CSV_URL)
        if csv_data is not None:
            with open(self.csv_cache, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
            logger.info(f"[ARGUS_DB] CSV saved ({len(csv_data)} bytes)")
        with open(self.meta_cache, "w") as f:
            json.dump({"fetched_at": datetime.now(timezone.utc).isoformat()}, f)

    @staticmethod
    def _fetch_csv(url: str) -> Optional[str]:
        """Fetch raw CSV text from argus-db."""
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            return r.text
        except Exception as e:
            logger.warning(f"[ARGUS_DB] CSV fetch failed {url}: {e}")
            return None

    @staticmethod
    def _fetch(url: str) -> Optional[list]:
        """Legacy JSON fetch — kept for compatibility."""
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("identifiers", "behavioral_signatures",
                            "records", "data", "results", "items"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                all_lists = [v for v in data.values() if isinstance(v, list)]
                if all_lists:
                    return [item for sub in all_lists for item in sub]
            return []
        except Exception as e:
            logger.warning(f"[ARGUS_DB] JSON fetch failed {url}: {e}")
            return None

    @staticmethod
    def _read_cache(path: str) -> list:
        """Legacy JSON cache reader — kept for compatibility."""
        if not os.path.exists(path):
            return []
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("identifiers", "behavioral_signatures",
                            "records", "data", "results", "items"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
            return []
        except Exception:
            return []

    @staticmethod
    def _read_csv_cache(path: str,
                        category_filter: Optional[set] = None) -> list:
        """
        Parse the argus-db CSV export into a list of dicts.
        Line 1: # meta: comment (skipped)
        Line 2: column headers
        Lines 3+: data rows
        category_filter: if set, only return rows where device_category is in filter.
        """
        if not os.path.exists(path):
            return []
        import csv as _csv
        rows = []
        try:
            with open(path, encoding="utf-8", newline="") as f:
                reader = _csv.DictReader(
                    (line for line in f if not line.startswith("#"))
                )
                for row in reader:
                    if category_filter is not None:
                        cat = row.get("device_category", "").lower()
                        if not any(c in cat for c in category_filter):
                            continue
                    # Normalise to the shape our lookup methods expect
                    rows.append({
                        "pattern":         row.get("identifier", ""),
                        "pattern_type":    row.get("identifier_type", ""),
                        "description":     (row.get("manufacturer", "") + " " +
                                           row.get("model", "")).strip(),
                        "manufacturer":    row.get("manufacturer", ""),
                        "confidence":      int(row.get("confidence", 0) or 0),
                        "device_category": row.get("device_category", ""),
                        "source_type":     row.get("source_type", ""),
                        "geographic_scope":row.get("geographic_scope", ""),
                        "notes":           row.get("notes", ""),
                        "argus_record_id": row.get("argus_record_id", ""),
                    })
        except Exception as e:
            logger.warning(f"[ARGUS_DB] CSV parse error: {e}")
        return rows


# ── SENTRY integration helper ─────────────────────────────────────────────────

def sentry_alert_enrich(alert: dict) -> dict:
    """
    Enrich a SENTRY alert dict with argus-db vendor attribution.

    Call from SENTRY alert pipeline:
        from argus_db_lookup import sentry_alert_enrich
        alert = sentry_alert_enrich(alert)

    Adds 'argus_db' key to alert if a match is found.
    """
    db = ArgusDbLookup()
    if not db.load():
        return alert

    enriched = dict(alert)
    matches = []

    # Check vendor hints from alert
    vendor_hint = str(alert.get("hardware_hint", "") or alert.get("vendor", "")).lower()
    for vendor_key in VENDOR_FRAGMENTS:
        if any(f in vendor_hint for f in VENDOR_FRAGMENTS[vendor_key]):
            match = db.lookup_vendor(vendor_key)
            if match:
                matches.append({
                    "vendor": vendor_key,
                    "argus_description": match.get("description"),
                    "argus_confidence": match.get("confidence"),
                    "argus_source": match.get("source_type"),
                    "device_category": match.get("device_category"),
                })

    # Check any MAC addresses in alert
    for mac_field in ("mac", "bssid", "mac_address"):
        mac = alert.get(mac_field)
        if mac:
            match = db.lookup_mac(str(mac))
            if match:
                matches.append({
                    "vendor": "MAC_OUI",
                    "argus_description": match.get("description"),
                    "argus_confidence": match.get("confidence"),
                    "argus_source": match.get("source_type"),
                    "device_category": match.get("device_category"),
                    "matched_pattern": match.get("pattern"),
                })

    if matches:
        enriched["argus_db"] = {
            "matches": matches,
            "source": "github.com/kevwillow/argus-db",
            "license": "ODbL-1.0",
        }

    return enriched


if __name__ == "__main__":
    # Quick self-test
    import sys
    logging.basicConfig(level=logging.INFO)
    db = ArgusDbLookup()
    if not db.load():
        print("FAILED: could not load argus-db exports")
        sys.exit(1)
    stats = db.stats()
    print(f"argus-db loaded:")
    print(f"  Behavioral signatures : {stats['behavioral_rows']}")
    print(f"  High-confidence rows  : {stats['highconf_rows']}")
    print(f"  Network surveillance  : {stats['network_surveillance_rows']}")
    print(f"  Cache fresh           : {stats['cache_fresh']}")
    print(f"  Fetched at            : {stats['fetched_at']}")
    print()
    for vendor in ["harris", "rohde", "septier", "cognyte"]:
        match = db.lookup_vendor(vendor)
        if match:
            print(f"  [{vendor}] → {match.get('description')} "
                  f"[conf={match.get('confidence')}] "
                  f"[cat={match.get('device_category')}]")
        else:
            print(f"  [{vendor}] → no match in current export")
