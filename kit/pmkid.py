"""PMKID and 4-way handshake capture + cracking helpers."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


def capture_handshakes(interface: str, out_dir: str) -> Path:
    """Run hcxdumptool to capture PMKID and handshakes."""
    out_path = Path(out_dir) / "capture.pcapng"
    cmd = ["hcxdumptool", "-i", interface, "-o", str(out_path), "--enable_status=1"]
    try:
        subprocess.Popen(cmd)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"hcxdumptool failed: {exc}")
    return out_path


def crack_capture(capture: Path, wordlist: Path, gpu: bool = True) -> Optional[str]:
    """Invoke hashcat on the capture; return key if found."""
    hash_file = capture.with_suffix(".hash")
    cmd_hcx = ["hcxpcapngtool", "-o", str(hash_file), str(capture)]
    try:
        subprocess.run(cmd_hcx, check=True)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"hcxpcapngtool failed: {exc}")
    mode = "-O" if gpu else "-D"  # placeholder
    cmd_hashcat = ["hashcat", mode, str(hash_file), str(wordlist)]
    try:
        subprocess.run(cmd_hashcat, check=True)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"hashcat failed: {exc}")
    return None

