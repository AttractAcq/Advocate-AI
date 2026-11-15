"""Parse representative FortiOS key-value syslog without retaining raw log text."""

from __future__ import annotations

import ipaddress
import shlex


def parse_fortigate_syslog(line: str) -> dict[str, str]:
    if not isinstance(line, str) or len(line) > 4096 or "\n" in line or "\r" in line:
        raise ValueError("invalid FortiGate log")
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        raise ValueError("invalid FortiGate log") from exc
    fields: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue  # Syslog envelope is collector-owned; ignore it here.
        key, value = token.split("=", 1)
        if key in fields:
            raise ValueError("duplicate FortiGate field")
        fields[key] = value
    needed = ("date", "time", "logid", "srcip", "dstip", "action")
    if any(not fields.get(key) for key in needed):
        raise ValueError("incomplete FortiGate log")
    ipaddress.ip_address(fields["srcip"])
    ipaddress.ip_address(fields["dstip"])
    if fields["action"] not in {"deny", "accept", "close", "timeout"}:
        raise ValueError("unsupported FortiGate action")
    return {key: fields[key] for key in needed}
