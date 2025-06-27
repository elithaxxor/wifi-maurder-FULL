"""Wrapper for Wifite2 to run common attacks."""
from __future__ import annotations

import subprocess
from typing import Optional


def run_wifite(target: Optional[str] = None) -> int:
    """Run Wifite2 with optional target BSSID."""
    cmd = ["wifite", "--no-ivs"]
    if target:
        cmd += ["-b", target]
    try:
        subprocess.run(cmd, check=True)
        return 0
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"wifite failed: {exc}")

