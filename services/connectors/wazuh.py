"""Bounded, read-only queries against the Wazuh alert indexer API."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import httpx


class WazuhUnavailable(Exception):
    pass


class WazuhIndexerReader:
    """Search only the alerts index using a separately scoped read identity.

    POST to ``_search`` is an indexer read operation. The account and network
    policy must independently deny every write and administrative endpoint.
    """

    def __init__(self, endpoint: str, token: str, *, ca_bundle: Path | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        parsed = urlsplit(endpoint)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("Wazuh indexer needs a numeric private address") from exc
        private = address.is_loopback or any(address in network for network in (
            ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("fc00::/7")))
        if (parsed.scheme != "https" or not private
                or not parsed.port or parsed.path not in ("", "/") or parsed.query
                or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("Wazuh indexer must be an HTTPS private endpoint")
        if not token or len(token) > 4096 or "\n" in token or "\r" in token:
            raise ValueError("invalid Wazuh read token")
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.ca_bundle = ca_bundle
        self.transport = transport

    def alerts(self, *, limit: int = 50) -> list[dict[str, object]]:
        if not 1 <= limit <= 100:
            raise ValueError("alert limit out of bounds")
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["id", "timestamp", "rule.id", "rule.level", "rule.description",
                        "agent.id", "agent.name", "data.srcip", "data.dstip",
                        "data.srcport", "data.dstport", "data.action", "data.vlan",
                        "decoder.name", "location"],
            "query": {"match_all": {}},
        }
        try:
            with httpx.Client(timeout=10, verify=str(self.ca_bundle) if self.ca_bundle else True,
                              trust_env=False, follow_redirects=False, transport=self.transport) as client:
                response = client.post(f"{self.endpoint}/wazuh-alerts*/_search", json=query,
                                       headers={"Authorization": f"Bearer {self.token}"})
                response.raise_for_status()
                hits = response.json()["hits"]["hits"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
            raise WazuhUnavailable("Wazuh alert search unavailable") from exc
        if not isinstance(hits, list) or len(hits) > limit:
            raise WazuhUnavailable("Wazuh returned invalid alert count")
        result = []
        for hit in hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("_id"), str) or not isinstance(hit.get("_source"), dict):
                raise WazuhUnavailable("Wazuh returned malformed alert")
            result.append({"index_id": hit["_id"], "source": hit["_source"]})
        return result
