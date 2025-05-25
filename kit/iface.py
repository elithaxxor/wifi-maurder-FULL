"""
Interface detection and monitor mode control for WiFi Marauder.
"""
import subprocess

def detect_interfaces():
    """Return a list of wireless interfaces by parsing iwconfig output."""
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
        ifaces = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) > 0 and "IEEE 802.11" in line:
                iface = parts[0]
                if iface not in ifaces:
                    ifaces.append(iface)
        return ifaces if ifaces else ["wlan0"]
    except Exception:
        return ["wlan0"]

def toggle_monitor_mode(interface):
    """Enable monitor mode on the given interface using airmon-ng."""
    cmd = ["airmon-ng", "start", interface]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        return proc.returncode == 0
    except Exception:
        return False