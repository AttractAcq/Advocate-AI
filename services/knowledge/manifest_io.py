"""Bounded, regular-file intake for the approved source manifest."""

from __future__ import annotations

import json
from pathlib import Path

from services.policy.regular_file import read_regular_file

MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def read_manifest_bytes(path: Path) -> bytes:
    return read_regular_file(path, MAX_MANIFEST_BYTES)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate source manifest key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid source manifest constant: {value}")


def load_manifest(path: Path) -> object:
    """Read one unambiguous JSON value from the approved manifest file."""
    return json.loads(read_manifest_bytes(path), object_pairs_hook=_unique_pairs,
                      parse_constant=_reject_constant)
