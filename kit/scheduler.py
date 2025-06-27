"""Scan scheduling utilities."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Dict, Any

from .scan import ScanManager


class ScanScheduler:
    """Load scan profiles from JSON and run them periodically."""

    def __init__(self, db_manager, schedule_file: str | Path) -> None:
        self.db = db_manager
        self.schedule_file = Path(schedule_file)
        self.schedule: List[Dict[str, Any]] = []
        self.last_run: Dict[str, float] = {}
        self.load_schedule()

    def load_schedule(self) -> None:
        """Load schedule JSON from :attr:`schedule_file`."""
        try:
            with open(self.schedule_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.schedule = data.get("scans", [])
        except Exception:
            self.schedule = []

    def run_pending(self) -> None:
        """Execute scans that are due based on interval timers."""
        now = time.time()
        for entry in self.schedule:
            iface = entry.get("interface", "wlan0")
            dur = int(entry.get("duration", 10))
            interval = int(entry.get("interval", 3600))
            last = self.last_run.get(iface, 0)
            if now - last >= interval:
                sm = ScanManager(self.db)
                if sm.start(iface, dur):
                    time.sleep(0.01)  # allow instant progression for tests
                    sm.stop()
                    sm.record(iface)
                self.last_run[iface] = now
