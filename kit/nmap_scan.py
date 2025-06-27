"""Run and parse Nmap scans."""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional


def run_scan(target: str, flags: Optional[str] = "-sV") -> str:
    """Run nmap scan with *flags* against *target* and return XML output."""
    cmd = ["nmap"]
    if flags:
        cmd.extend(flags.split())
    cmd += ["-oX", "-", target]
    try:
        return subprocess.check_output(cmd, text=True)
    except Exception as exc:  # pragma: no cover - real binary may not be present
        raise RuntimeError(f"nmap failed: {exc}")


def parse_xml(xml_data: str) -> List[Dict[str, object]]:
    """Parse nmap XML output and return simplified host results."""
    hosts: List[Dict[str, object]] = []
    root = ET.fromstring(xml_data)
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        ports_data = []
        for port in host.findall("ports/port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            state_el = port.find("state")
            service_el = port.find("service")
            ports_data.append({
                "port": portid,
                "protocol": proto,
                "state": state_el.get("state") if state_el is not None else "",
                "service": service_el.get("name") if service_el is not None else "",
            })
        hosts.append({"ip": ip, "ports": ports_data})
    return hosts
