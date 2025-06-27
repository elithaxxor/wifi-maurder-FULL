"""Bettercap MITM and BLE controls."""
from __future__ import annotations

import subprocess
from typing import Optional


def start_mitm(interface: str, ble: bool = False) -> subprocess.Popen:
    """Start bettercap with optional BLE module."""
    args = ["bettercap", "-iface", interface]
    if ble:
        args += ["--eval", "ble.recon on"]
    try:
        return subprocess.Popen(args)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"bettercap failed: {exc}")


def stop_mitm(proc: subprocess.Popen) -> None:
    """Terminate a running bettercap process."""
    if proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=5)

