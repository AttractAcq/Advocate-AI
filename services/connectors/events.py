"""Normalise fictional lab events, rejecting unknown equipment actions."""

from __future__ import annotations

from collections.abc import Mapping


def normalise_event(raw: Mapping[str, object]) -> dict[str, object]:
    required = ("event_id", "timestamp", "source", "severity", "message")
    if any(not isinstance(raw.get(key), str) or not raw[key] for key in required):
        raise ValueError("incomplete event")
    if raw["source"] not in ("fortigate-sim", "switch-sim", "host-sim"):
        raise ValueError("source not allowlisted")
    if raw["severity"] not in ("low", "medium", "high", "critical"):
        raise ValueError("invalid severity")
    return {key: raw[key] for key in required} | {
        "asset_id": raw.get("asset_id") if isinstance(raw.get("asset_id"), str) else None,
        "read_only": True,
    }
