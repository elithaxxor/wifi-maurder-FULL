"""
Analytics helpers for WiFi Marauder.
"""
import json
from collections import Counter

def count_vendors(scan_logs, lookup_vendor):
    """Return Counter of OUI vendors from scan log entries."""
    vendor_counts = Counter()
    for _id, ts, iface, dur, output in scan_logs:
        try:
            nets = json.loads(output)
        except Exception:
            continue
        for net in nets:
            vendor = lookup_vendor(net.get('bssid', '')) or 'Unknown'
            vendor_counts[vendor] += 1
    return vendor_counts

def count_handshakes(captures):
    """Return Counter of handshakes per ESSID."""
    return Counter([c[3] for c in captures])

def count_attacks(deauths, captures, decoys):
    """Return dict of total deauth, handshake, and decoy counts."""
    return {'Deauths': len(deauths), 'Captures': len(captures), 'Decoys': len(decoys)}

def plot_bar(ax, counter, title):
    """Plot a bar chart of counter on ax."""
    labels = list(counter.keys())
    values = [counter[k] for k in labels]
    ax.clear()
    ax.bar(labels, values)
    ax.set_title(title)
    ax.set_xticklabels(labels, rotation=45, ha='right')

def plot_pie(ax, data_dict, title):
    """Plot a pie chart of data_dict on ax."""
    ax.clear()
    ax.pie(data_dict.values(), labels=data_dict.keys(), autopct='%1.0f%%')
    ax.set_title(title)