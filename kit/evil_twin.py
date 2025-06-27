"""Evil Twin access point management."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


def start_evil_ap(conf_dir: str) -> subprocess.Popen:
    """Start hostapd-mana and dnsmasq using config templates."""
    hostapd_conf = Path(conf_dir) / "hostapd.conf"
    dns_conf = Path(conf_dir) / "dnsmasq.conf"
    mana_cmd = ["hostapd-mana", str(hostapd_conf)]
    dns_cmd = ["dnsmasq", "-C", str(dns_conf)]
    try:
        mana_proc = subprocess.Popen(mana_cmd)
        dns_proc = subprocess.Popen(dns_cmd)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"EvilAP start failed: {exc}")
    return mana_proc


def stop_evil_ap(proc: subprocess.Popen) -> None:
    """Stop the running hostapd-mana process."""
    if proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=5)

