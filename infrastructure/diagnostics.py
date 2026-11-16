"""Bounded, read-only local health probes with a metadata-only report."""

from __future__ import annotations

import ipaddress
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from urllib.parse import quote, urlsplit

import httpx

MAX_RESPONSE = 4096


class DiagnosticConfigError(ValueError):
    """An unsafe or malformed diagnostic configuration."""


def _endpoint(check: dict[str, object], allowed: list[ipaddress._BaseNetwork]) -> None:
    url = check.get("url")
    if not isinstance(url, str):
        raise DiagnosticConfigError("HTTPS URL required")
    try:
        parsed = urlsplit(url)
        host = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise DiagnosticConfigError("numeric local endpoint required") from exc
    if (parsed.scheme != "https" or not port or parsed.path != "/health"
            or parsed.query or parsed.fragment or parsed.username or parsed.password
            or not any(host in network for network in allowed)):
        raise DiagnosticConfigError("endpoint must be allowed local HTTPS /health")


def _validate(config: dict[str, object], base: Path) -> tuple[list[dict[str, object]], list[ipaddress._BaseNetwork]]:
    if not isinstance(config, dict) or set(config) != {"schema", "mode", "allowed_cidrs", "checks"}:
        raise DiagnosticConfigError("invalid configuration fields")
    if config["schema"] != 1 or config["mode"] not in ("synthetic-loopback", "local"):
        raise DiagnosticConfigError("invalid configuration schema or mode")
    cidrs = config["allowed_cidrs"]
    if not isinstance(cidrs, list) or not cidrs or not all(isinstance(value, str) for value in cidrs):
        raise DiagnosticConfigError("nonempty CIDR allowlist required")
    try:
        networks = [ipaddress.ip_network(value, strict=True) for value in cidrs]
    except ValueError as exc:
        raise DiagnosticConfigError("invalid CIDR") from exc
    if not all(network.is_private or network.is_loopback for network in networks):
        raise DiagnosticConfigError("public CIDR is forbidden")
    checks = config["checks"]
    if not isinstance(checks, list) or not checks or len(checks) > 32:
        raise DiagnosticConfigError("1 to 32 checks required")
    names: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise DiagnosticConfigError("invalid check")
        kind = check.get("kind")
        required = ({"name", "kind", "url", "ca_file", "expected_service"} if kind == "https"
                    else {"name", "kind", "path"} if kind == "sqlite" else set())
        name = check.get("name")
        if not required or set(check) != required or not isinstance(name, str) or not name.isidentifier():
            raise DiagnosticConfigError("invalid check fields or name")
        if name in names:
            raise DiagnosticConfigError("duplicate check name")
        names.add(name)
        if kind == "https":
            _endpoint(check, networks)
            if not isinstance(check["expected_service"], str) or not check["expected_service"]:
                raise DiagnosticConfigError("expected service required")
            ca = check["ca_file"]
            if not isinstance(ca, str) or not (base / ca).is_file():
                raise DiagnosticConfigError("CA file required")
        else:
            path = check["path"]
            if not isinstance(path, str) or not path or "\x00" in path:
                raise DiagnosticConfigError("database path required")
    return checks, networks


def _https(check: dict[str, object], base: Path, transport: httpx.BaseTransport | None) -> tuple[str, str]:
    try:
        options: dict[str, object] = {"timeout": 2.0, "trust_env": False, "follow_redirects": False}
        if transport is None:
            options["verify"] = str((base / str(check["ca_file"])).resolve())
        else:  # Test transport only; normal CLI always validates the configured CA.
            options["transport"] = transport
        with httpx.Client(**options) as client:
            with client.stream("GET", str(check["url"])) as response:
                if response.status_code != 200:
                    return "down", "http_status"
                if response.headers.get("content-encoding", "identity") != "identity":
                    return "down", "encoded_response"
                raw = bytearray()
                for chunk in response.iter_raw(chunk_size=MAX_RESPONSE + 1):
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE:
                        return "down", "response_too_large"
        payload = json.loads(raw)
        if (not isinstance(payload, dict) or payload.get("status") != "ok"
                or payload.get("service") != check["expected_service"]):
            return "down", "unexpected_response"
        return "ok", "verified"
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError):
        return "down", "probe_failed"


def _sqlite(check: dict[str, object], base: Path) -> tuple[str, str]:
    path = (base / str(check["path"])).resolve()
    if not path.is_file():
        return "down", "database_missing"
    try:
        uri = f"file:{quote(str(path), safe='/')}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as connection:
            result = connection.execute("PRAGMA quick_check(1)").fetchone()
        return ("ok", "verified") if result == ("ok",) else ("down", "integrity_failed")
    except (sqlite3.Error, OSError):
        return "down", "probe_failed"


def diagnose(config: dict[str, object], base: Path, *, transport: httpx.BaseTransport | None = None) -> dict[str, object]:
    """Validate every target before probing any; return no URLs or data values."""
    checks, _ = _validate(config, base)
    results = []
    for check in checks:
        status, reason = (_https(check, base, transport) if check["kind"] == "https"
                          else _sqlite(check, base))
        results.append({"name": check["name"], "kind": check["kind"],
                        "status": status, "reason": reason})
    return {"schema": 1, "mode": config["mode"], "all_ok": all(row["status"] == "ok" for row in results),
            "checks": results}
