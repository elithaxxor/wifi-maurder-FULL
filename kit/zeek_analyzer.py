"""Background Zeek analyzer for PCAP files."""
from __future__ import annotations

import subprocess
from pathlib import Path
from threading import Thread
from queue import Queue, Empty


class ZeekAnalyzer(Thread):
    """Run Zeek on a pcap file and stream alerts via a queue."""

    def __init__(self, pcap: Path, queue: Queue[str]):
        super().__init__(daemon=True)
        self.pcap = pcap
        self.queue = queue

    def run(self) -> None:  # noqa: D401
        cmd = ["zeek", str(self.pcap)]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            assert proc.stdout is not None
            for line in proc.stdout:
                self.queue.put(line.strip())
        except Exception as exc:  # noqa: BLE001
            self.queue.put(f"Zeek error: {exc}")

