"""Wigle geolocation helpers."""
from __future__ import annotations

from pathlib import Path
try:
    import folium
except Exception as exc:  # noqa: BLE001
    folium = None
from osint_integrations import WigleClient


def map_network(ssid: str, out_file: Path) -> None:
    """Render a folium map with Wigle search results."""
    if folium is None:
        raise RuntimeError("folium not available")
    client = WigleClient()
    data = client.search_networks(ssid=ssid, results_per_page=20)
    m = folium.Map(location=[0, 0], zoom_start=2)
    for res in data.get("results", []):
        lat = res.get("trilat")
        lon = res.get("trilong")
        if lat and lon:
            folium.Marker([lat, lon], popup=res.get("ssid")).add_to(m)
    m.save(out_file)

