"""Bounded, read-only queries against the Wazuh alert indexer API."""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import ssl
import stat
from urllib.parse import urlsplit

import httpx


class WazuhUnavailable(Exception):
    pass


_INDEX_NAME = re.compile(r"wazuh-alerts-[A-Za-z0-9._-]{1,80}\Z")
_DOCUMENT_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")
SUPPORTED_DECODERS = ("fortigate", "switch-syslog", "host-agent")
MAX_ALERT_RESPONSE = 2 * 1024 * 1024
MAX_CA_BYTES = 64 * 1024


def _unambiguous_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Wazuh response field")
        result[key] = value
    return result


def _private_ca_context(path: Path) -> ssl.SSLContext:
    """Snapshot a private CA so a later path replacement cannot change trust."""
    if not path.is_absolute():
        raise ValueError("Wazuh CA path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                    or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) & 0o077
                    or not 0 < details.st_size <= MAX_CA_BYTES):
                raise ValueError("unsafe Wazuh CA file")
            payload = source.read(MAX_CA_BYTES + 1)
        if not 0 < len(payload) <= MAX_CA_BYTES:
            raise ValueError("invalid Wazuh CA length")
        return ssl.create_default_context(cadata=payload.decode("ascii"))
    except (OSError, UnicodeError, ssl.SSLError) as exc:
        raise ValueError("invalid Wazuh CA file") from exc


def parse_incident_id(incident_id: str) -> tuple[str, str]:
    if not isinstance(incident_id, str):
        raise ValueError("invalid incident id")
    index_name, separator, document_id = incident_id.partition(":")
    if not separator or not _INDEX_NAME.fullmatch(index_name) or not _DOCUMENT_ID.fullmatch(document_id):
        raise ValueError("invalid incident id")
    return index_name, document_id


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
        self._tls_context = _private_ca_context(ca_bundle) if ca_bundle else None
        self.transport = transport

    def alerts(self, *, limit: int = 50, since: datetime | None = None,
               until: datetime | None = None, incident_id: str | None = None) -> list[dict[str, object]]:
        if not 1 <= limit <= 100:
            raise ValueError("alert limit out of bounds")
        index_name, document_id = parse_incident_id(incident_id) if incident_id is not None else (None, None)
        if since is not None or until is not None:
            if since is None or until is None or since.tzinfo is None or until.tzinfo is None:
                raise ValueError("bounded UTC alert interval required")
            since = since.astimezone(timezone.utc)
            until = until.astimezone(timezone.utc)
            if not since < until or until - since > timedelta(days=7):
                raise ValueError("alert interval out of bounds")
        filters: list[dict[str, object]] = [{"terms": {"decoder.name": list(SUPPORTED_DECODERS)}}]
        if since is not None and until is not None:
            filters.append({"range": {"timestamp": {"gte": since.isoformat(), "lt": until.isoformat()}}})
        if document_id is not None:
            filters.extend([{"term": {"_index": index_name}}, {"ids": {"values": [document_id]}}])
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["id", "timestamp", "rule.id", "rule.level", "rule.description",
                        "agent.id", "agent.name", "data.srcip", "data.dstip",
                        "data.srcport", "data.dstport", "data.action", "data.vlan",
                        "data.devname", "data.device_name",
                        "decoder.name", "location"],
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        }
        try:
            with httpx.Client(timeout=10, verify=self._tls_context or True,
                              trust_env=False, follow_redirects=False, transport=self.transport) as client:
                with client.stream("POST", f"{self.endpoint}/wazuh-alerts*/_search", json=query,
                                   headers={"Authorization": f"Bearer {self.token}"}) as response:
                    response.raise_for_status()
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        body.extend(chunk)
                        if len(body) > MAX_ALERT_RESPONSE:
                            raise ValueError("oversized Wazuh alert response")
                    hits = json.loads(body, object_pairs_hook=_unambiguous_object)["hits"]["hits"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError, UnicodeError) as exc:
            raise WazuhUnavailable("Wazuh alert search unavailable") from exc
        if not isinstance(hits, list) or len(hits) > limit:
            raise WazuhUnavailable("Wazuh returned invalid alert count")
        result = []
        for hit in hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("_id"), str) or not isinstance(hit.get("_source"), dict):
                raise WazuhUnavailable("Wazuh returned malformed alert")
            if not _INDEX_NAME.fullmatch(str(hit.get("_index", ""))) or not _DOCUMENT_ID.fullmatch(hit["_id"]):
                raise WazuhUnavailable("Wazuh returned invalid alert identity")
            if incident_id is not None and (hit["_index"], hit["_id"]) != (index_name, document_id):
                raise WazuhUnavailable("Wazuh returned mismatched alert")
            result.append({"index_name": hit["_index"], "index_id": hit["_id"], "source": hit["_source"]})
        return result
