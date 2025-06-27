"""IP/MAC enrichment using Shodan and Censys."""
from __future__ import annotations

from typing import Dict, Any

import os
import requests
from osint_integrations import ShodanClient


class CensysClient:
    """Minimal Censys REST API helper."""

    BASE_URL = "https://search.censys.io/api"

    def __init__(self, api_id: str | None = None, api_secret: str | None = None) -> None:
        self.api_id = api_id or os.getenv("CENSYS_API_ID")
        self.api_secret = api_secret or os.getenv("CENSYS_API_SECRET")
        if not self.api_id or not self.api_secret:
            raise ValueError("Censys API credentials missing")
        self.session = requests.Session()
        self.session.auth = (self.api_id, self.api_secret)

    def host_info(self, ip: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/v1/hosts/{ip}"
        r = self.session.get(url, timeout=10)
        r.raise_for_status()
        return r.json()


def enrich_ip(ip: str) -> Dict[str, Any]:
    """Combine Shodan and Censys data for an IP."""
    shodan_data = ShodanClient().host_info(ip)
    censys_data = CensysClient().host_info(ip)
    return {"shodan": shodan_data, "censys": censys_data}

