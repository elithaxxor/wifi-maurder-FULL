"""Network topology graph helpers."""
from __future__ import annotations

try:
    from pyvis.network import Network
except Exception as exc:  # noqa: BLE001
    Network = None
from pathlib import Path


def graph_from_airgraph(graphml_file: Path, out_html: Path) -> None:
    """Convert GraphML to interactive HTML using pyvis."""
    try:
        import networkx as nx
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("networkx required for topology graphs") from exc
    if Network is None:
        raise RuntimeError("pyvis not available")
    g = nx.read_graphml(graphml_file)
    net = Network(height="600px", width="100%", directed=False)
    net.from_nx(g)
    net.show(str(out_html))

