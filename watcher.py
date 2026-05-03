#!/usr/bin/env python3
"""
Watcher — Live Directory Monitor
=================================
Monitors a directory for new Rayhunter capture files and triggers
analysis automatically when new NDJSON, PCAP, or QMDL files appear.

Usage:
    python main.py --dir ./captures --watch
    python main.py --dir ./captures --watch --watch-interval 30

How it works:
    - Scans the target directory every N seconds (default 15)
    - Tracks which files have already been analysed by path + mtime
    - When a new or modified file appears, re-runs full analysis
    - Prints a diff of new findings since the last run
    - Sends a terminal bell on CRITICAL findings
"""

import os
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Set, List, Optional, Callable


SUPPORTED_EXTENSIONS = {".ndjson", ".pcap", ".pcapng", ".qmdl"}


class DirectoryWatcher:
    def __init__(
        self,
        directories: List[str],
        interval_seconds: int = 15,
        on_new_files: Optional[Callable] = None,
    ):
        self.directories = [Path(d) for d in directories]
        self.interval = interval_seconds
        self.on_new_files = on_new_files
        # file_path -> (mtime, size) of last seen state
        self._seen: Dict[str, tuple] = {}
        self._run_count = 0

    def _scan(self) -> List[Path]:
        """Return list of new or modified supported files."""
        new_or_changed = []
        for directory in self.directories:
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue
                try:
                    stat = path.stat()
                    key = str(path)
                    current = (stat.st_mtime, stat.st_size)
                    if key not in self._seen or self._seen[key] != current:
                        new_or_changed.append(path)
                        self._seen[key] = current
                except OSError:
                    continue
        return new_or_changed

    def run_once(self) -> List[Path]:
        """Single scan — return new/changed files."""
        return self._scan()

    def watch(self):
        """Block and monitor. Calls on_new_files(paths) when changes detected."""
        dirs_str = ", ".join(str(d) for d in self.directories)
        print(f"\n  [WATCH] Monitoring: {dirs_str}")
        print(f"  [WATCH] Interval: {self.interval}s — Ctrl+C to stop\n")

        # Initial scan to establish baseline (don't trigger on existing files)
        self._scan()
        print(f"  [WATCH] Baseline established — watching for new captures...")

        try:
            while True:
                time.sleep(self.interval)
                new_files = self._scan()
                if new_files:
                    self._run_count += 1
                    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    print(f"\n  [WATCH] {now} — {len(new_files)} new/changed file(s):")
                    for f in new_files:
                        print(f"    + {f.name}")
                    if self.on_new_files:
                        self.on_new_files(new_files)
        except KeyboardInterrupt:
            print(f"\n  [WATCH] Stopped after {self._run_count} triggered run(s).")


def print_watch_diff(old_findings: List[Dict], new_findings: List[Dict]):
    """
    Print only findings that are new or have increased event counts
    since the previous run. Suppresses findings already seen.
    """
    def finding_key(f: Dict) -> str:
        return f.get("title", "") + "|" + f.get("technique", "")

    old_map = {finding_key(f): f for f in old_findings}

    new_count = 0
    for f in new_findings:
        key = finding_key(f)
        old = old_map.get(key)

        if old is None:
            # Brand new finding
            sev = f.get("severity", "?")
            print(f"\n  [NEW FINDING] {sev}: {f.get('title', '?')}")
            if f.get("evidence"):
                for line in f["evidence"][:3]:
                    print(f"    {line}")
            new_count += 1
        else:
            # Check if event count increased
            old_ev = len(old.get("events", old.get("evidence", [])))
            new_ev = len(f.get("events", f.get("evidence", [])))
            if new_ev > old_ev:
                print(f"\n  [ESCALATED] {f.get('title', '?')}: "
                      f"{old_ev} → {new_ev} events (+{new_ev - old_ev})")
                new_count += 1

    if new_count == 0:
        print("  [WATCH] No new findings since last run.")
    else:
        print(f"\n  [WATCH] {new_count} finding(s) changed.")
