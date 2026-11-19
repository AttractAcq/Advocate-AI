"""Bounded, regular-file intake for the approved source manifest."""

from __future__ import annotations

from pathlib import Path

from services.policy.regular_file import read_regular_file

MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def read_manifest_bytes(path: Path) -> bytes:
    return read_regular_file(path, MAX_MANIFEST_BYTES)
