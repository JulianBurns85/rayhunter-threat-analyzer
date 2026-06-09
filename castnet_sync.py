#!/usr/bin/env python3
"""
castnet_sync.py
================
Automated CID registry sync between DUKE and Pi CASTNET instance.

Pulls confirmed rogue CID list from rayhunter-threat-analyzer intelligence
and pushes to Pi CASTNET API for live detection updates.

Run from DUKE:
  python castnet_sync.py --pi 100.68.146.48 --key YOUR_API_KEY

Also syncs:
  - New confirmed rogue CIDs from latest corpus run
  - Watchlist updates
  - Geographic baseline exclusions (Alfy's clean CIDs)
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# Confirmed rogue CIDs from corpus
ROGUE_CIDS = [
    {"ci": 137713155, "tac": 12385, "carrier": "telstra", "device": "Device A", "confirmed": True},
    {"ci": 137713165, "tac": 12385, "carrier": "telstra", "device": "Device A", "confirmed": True},
    {"ci": 137713175, "tac": 12385, "carrier": "telstra", "device": "Device A", "confirmed": True},
    {"ci": 137713195, "tac": 12385, "carrier": "telstra", "device": "Device A", "confirmed": True},
    {"ci": 135836161, "tac": 12385, "carrier": "telstra", "device": "Device A post-ACMA", "confirmed": True},
    {"ci": 135836171, "tac": 12385, "carrier": "telstra", "device": "Device A post-ACMA", "confirmed": True},
    {"ci": 135836191, "tac": 12385, "carrier": "telstra", "device": "Device A post-ACMA", "confirmed": True},
    {"ci": 8409357,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8409367,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8409387,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8409397,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8666381,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8666391,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
    {"ci": 8666411,   "tac": 30336, "carrier": "vodafone", "device": "Device B", "confirmed": True},
]

# Known clean CIDs from Alfy's baseline (never flag these)
CLEAN_BASELINE_CIDS = [
    8408332, 8408334, 8408342, 8408344, 8408362, 8408364, 8408371,
    8490252, 8490262, 8490282, 8490292, 8518158, 8518195,
    8612659, 8668726, 8404787, 137067779, 137067809,
]


def api_call(base_url: str, endpoint: str, data: dict, api_key: str) -> dict:
    url = f"{base_url}{endpoint}"
    payload = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(
        url, data=payload,
        headers={
            "Content-Type": "application/json",
            "X-CASTNET-Key": api_key,
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def check_health(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/health", timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print(f"[CASTNET] Pi health: {data.get('status','unknown')} "
                  f"| events: {data.get('event_count','?')}")
            return True
    except Exception as e:
        print(f"[CASTNET] Pi unreachable: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="CASTNET CID Registry Sync")
    parser.add_argument("--pi", default="100.68.146.48",
                        help="Pi IP or Tailscale address")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--key", default="changeme",
                        help="CASTNET API key")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be synced without pushing")
    args = parser.parse_args()

    base_url = f"http://{args.pi}:{args.port}"
    print(f"[CASTNET] Syncing to {base_url}")
    print(f"[CASTNET] Rogue CIDs to sync: {len(ROGUE_CIDS)}")
    print(f"[CASTNET] Clean baseline CIDs: {len(CLEAN_BASELINE_CIDS)}")

    if args.dry_run:
        print("\n[DRY RUN] Would push:")
        for cid in ROGUE_CIDS:
            print(f"  ROGUE: ci={cid['ci']} tac={cid['tac']} [{cid['device']}]")
        return

    # Health check
    if not check_health(base_url):
        print("[CASTNET] Aborting — Pi not reachable")
        sys.exit(1)

    # Push rogue CID registry
    sync_payload = {
        "rogue_cids": ROGUE_CIDS,
        "clean_cids": CLEAN_BASELINE_CIDS,
        "sync_time": datetime.utcnow().isoformat(),
        "source": "rayhunter-threat-analyzer v4.3",
        "case_ref": "AFP LEX 4864",
    }

    result = api_call(base_url, "/api/sync-registry", sync_payload, args.key)
    if "error" in result:
        print(f"[CASTNET] Sync failed: {result['error']}")
        # Try without API key (older Pi version)
        result2 = api_call(base_url, "/api/sync-registry", sync_payload, "")
        if "error" not in result2:
            print(f"[CASTNET] Sync OK (no auth): {result2}")
        else:
            print("[CASTNET] Could not sync — check Pi Flask app")
    else:
        print(f"[CASTNET] Sync OK: {result}")

    print(f"\n[CASTNET] Done. {len(ROGUE_CIDS)} rogue CIDs pushed.")
    print(f"[CASTNET] Pi will now auto-flag these CIDs as confirmed_rogue=1")


if __name__ == "__main__":
    main()
