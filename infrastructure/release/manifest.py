"""Validate a synthetic release manifest before Phase 5 signing exists."""

from __future__ import annotations

import hashlib
from pathlib import Path


def validate_files(root: Path, manifest: dict[str, object]) -> bool:
    if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), list) or not manifest["files"]:
        return False
    for item in manifest["files"]:
        if not isinstance(item, dict):
            return False
        name, digest = item.get("path"), item.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            return False
        candidate = (root / name).resolve()
        if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
            return False
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            return False
    return True
