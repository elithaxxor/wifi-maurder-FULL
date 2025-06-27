"""GPU monitoring helpers using nvidia-smi or rocm-smi."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class GPUStats:
    utilization: int
    temperature: int


def query_gpu() -> Optional[GPUStats]:
    """Return GPU utilisation and temperature if available."""
    commands = [
        ["nvidia-smi", "--query-gpu=utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits"],
        ["rocm-smi", "--showuse", "--showtemp"],
    ]
    for cmd in commands:
        try:
            out = subprocess.check_output(cmd, text=True).strip()
        except Exception:
            continue
        clean = out.replace("%", "").replace(",", " ")
        parts = [int(p) for p in clean.split() if p.isdigit()]
        if len(parts) >= 2:
            return GPUStats(utilization=parts[0], temperature=parts[1])
    return None

