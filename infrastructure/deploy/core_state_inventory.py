"""Bounded source inventory for synthetic, manifest-backed Core recovery."""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
import re

from services.knowledge.paths import read_source_bytes
from services.policy.regular_file import read_regular_file


FIELDS = ("document_id", "relative_path", "collection", "classification",
          "version", "sha256", "owner", "source_type")
MAX_SOURCES = 122
MAX_SOURCE_BYTES = 8 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def source_files(state: Path) -> list[Path]:
    """Require an exact, digest-matching flat inventory of synthetic sources."""
    try:
        raw = read_regular_file(state / "manifest.csv", 1024 * 1024)
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""),
                                strict=True)
        if reader.fieldnames != list(FIELDS):
            raise ValueError("invalid synthetic source manifest header")
        rows = list(reader)
        if not 1 <= len(rows) <= MAX_SOURCES:
            raise ValueError("invalid synthetic source count")
        names: set[str] = set()
        identifiers: set[str] = set()
        for row in rows:
            if (set(row) != set(FIELDS) or any(not isinstance(row[key], str) or
                    not row[key] for key in FIELDS)):
                raise ValueError("invalid synthetic source manifest row")
            relative = row["relative_path"]
            name = relative.removeprefix("sources/")
            if (not relative.startswith("sources/") or not _NAME.fullmatch(name)
                    or not _DIGEST.fullmatch(row["sha256"])
                    or name in names or row["document_id"] in identifiers):
                raise ValueError("unsafe or duplicate synthetic source")
            names.add(name)
            identifiers.add(row["document_id"])
            payload = read_source_bytes(state, relative, MAX_SOURCE_BYTES)
            if hashlib.sha256(payload).hexdigest() != row["sha256"]:
                raise ValueError("synthetic source digest mismatch")
        source_dir = state / "sources"
        if source_dir.is_symlink() or not source_dir.is_dir():
            raise ValueError("synthetic source directory is unsafe")
        present = {path.name for path in source_dir.iterdir()}
        if present != names:
            raise ValueError("synthetic source inventory mismatch")
        return [source_dir / name for name in sorted(names)]
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError("invalid synthetic source inventory") from exc


def stage_source_inventory(state: Path, destination: Path) -> list[Path]:
    """Freeze a digest-checked manifest and sources in a private directory."""
    original = source_files(state)
    destination.mkdir(mode=0o700)
    (destination / "sources").mkdir(mode=0o700)
    manifest = read_regular_file(state / "manifest.csv", 1024 * 1024)
    staged_manifest = destination / "manifest.csv"
    staged_manifest.write_bytes(manifest)
    staged_manifest.chmod(0o600)
    for source in original:
        payload = read_source_bytes(state, f"sources/{source.name}", MAX_SOURCE_BYTES)
        staged = destination / "sources" / source.name
        staged.write_bytes(payload)
        staged.chmod(0o600)
    return source_files(destination)
