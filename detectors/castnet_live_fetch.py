#!/usr/bin/env python3
"""
castnet_live_fetcher.py — Live CASTNET API ingestion for CrossSourceCorrelator.

Fetches rogue CID detections directly from the CASTNET Pi API and converts
them into the format expected by CrossSourceCorrelator.ingest_castnet_findings().

API endpoint: GET http://<host>:5000/api/v1/detections
Response field mapping:
    ci          → cell identity (maps to rogue CID)
    timestamp   → ISO8601 detection time
    node_id     → which CASTNET node saw it
    rsrp        → signal strength
    tac         → tracking area code
    latitude    → GPS lat (when available)
    longitude   → GPS lon (when available)
    confirmed_rogue → 1 if confirmed in CASTNET known list
    timing_advance  → TA value (useful for corroboration with TA=7/8 finding)

Default Pi API: http://192.168.1.239:5000  (LAN)
Tailscale fallback: http://100.68.146.48:5000
"""

import urllib.request
import urllib.error
import json
import ssl
from typing import List, Dict, Optional, Set

# Known rogue CIDs — matches cross_source_correlator.ROGUE_CIDS_ALL
CASTNET_ROGUE_CIDS = {
    137713155, 137713165, 137713175, 137713195,  # eNB 537942 / TAC 12385 / Telstra
    8409357, 8409367, 8409387, 8409397,           # eNB 32849  / TAC 30336 / Vodafone
    8666381, 8666391, 8666411,                    # post-ACMA cluster
}

# API endpoints to try in order
CASTNET_API_ENDPOINTS = [
    "http://192.168.1.239:5000",   # LAN (fastest, always available on home network)
    "http://100.68.146.48:5000",   # Tailscale (when remote)
]

DEFAULT_TIMEOUT_S = 5
DEFAULT_LIMIT     = 5000   # fetch up to 5000 most recent detections


def fetch_castnet_detections(
    known_rogue_cids: Optional[Set[int]] = None,
    limit: int = DEFAULT_LIMIT,
    timeout: float = DEFAULT_TIMEOUT_S,
    castnet_api_url: Optional[str] = None,
) -> tuple[List[Dict], str, int]:
    """
    Fetch rogue CID detections from the live CASTNET API.

    Returns (findings_list, endpoint_used, total_rogue_count)
    where findings_list is in CrossSourceCorrelator.ingest_castnet_findings() format.

    Returns ([], "", 0) on failure — never raises, never crashes the analyzer.
    """
    rogue_cids = known_rogue_cids or CASTNET_ROGUE_CIDS

    endpoints = [castnet_api_url] if castnet_api_url else CASTNET_API_ENDPOINTS

    for endpoint in endpoints:
        url = f"{endpoint}/api/v1/detections?limit={limit}"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "rayhunter-threat-analyzer/4.4"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)

            if not isinstance(data, list):
                continue

            # Filter to rogue CIDs only and convert to correlator finding format
            findings = []
            rogue_count = 0
            seen_cids: Set[int] = set()

            for det in data:
                ci = det.get("ci")
                if ci is None:
                    continue
                try:
                    ci = int(ci)
                except (ValueError, TypeError):
                    continue

                if ci not in rogue_cids:
                    continue

                rogue_count += 1
                seen_cids.add(ci)

                # Build a finding dict that CrossSourceCorrelator understands
                finding = {
                    "title": (
                        f"CASTNET detection: CID={ci} "
                        f"node={det.get('node_id','?')} "
                        f"rsrp={det.get('rsrp','?')}dBm"
                    ),
                    "found_at":    det.get("timestamp", ""),
                    "timestamp":   det.get("timestamp", ""),
                    "ci":          ci,
                    "tac":         det.get("tac"),
                    "rsrp":        det.get("rsrp"),
                    "node_id":     det.get("node_id", "unknown"),
                    "latitude":    det.get("latitude"),
                    "longitude":   det.get("longitude"),
                    "timing_advance": det.get("timing_advance"),
                    "confirmed_rogue": det.get("confirmed_rogue", 0),
                    "evidence": str(ci),   # correlator searches this field for CID match
                    "source":  "castnet_live_api",
                    "detector": "CASTNET",
                }
                findings.append(finding)

            return findings, endpoint, rogue_count

        except (urllib.error.URLError, OSError, json.JSONDecodeError, Exception):
            # Try next endpoint
            continue

    # All endpoints failed — return empty, analyzer continues without CASTNET
    return [], "", 0


def fetch_castnet_summary(
    timeout: float = DEFAULT_TIMEOUT_S,
    castnet_api_url: Optional[str] = None,
) -> Optional[Dict]:
    """
    Fetch the /api/v1/summary endpoint for logging purposes.
    Returns None on failure.
    """
    endpoints = [castnet_api_url] if castnet_api_url else CASTNET_API_ENDPOINTS

    for endpoint in endpoints:
        url = f"{endpoint}/api/v1/summary"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "rayhunter-threat-analyzer/4.4"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
    return None
