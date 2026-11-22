"""Check and freeze the synthetic Phase 3 index beside its approved sources."""

from __future__ import annotations

import csv
from contextlib import closing
import io
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote

from infrastructure.backup import MAX_FILE
from infrastructure.deploy.core_state_inventory import FIELDS, source_files
from services.knowledge.ingestion import (
    _parse_verified_bytes, _valid_source, chunks, parse_local,
)
from services.knowledge.manifest_io import load_manifest, read_manifest_bytes
from services.policy.regular_file import read_regular_file


_METADATA = ("relative_path", "collection", "classification", "owner",
             "version", "sha256", "source_type")


def _pair(root: Path) -> tuple[Path, Path] | None:
    manifest, database = root / "knowledge-manifest.json", root / "knowledge.db"
    present = (manifest.exists() or manifest.is_symlink(),
               database.exists() or database.is_symlink())
    if present == (False, False):
        return None
    if present != (True, True):
        raise ValueError("incomplete synthetic knowledge pair")
    return manifest, database


def verify_knowledge_pair(root: Path) -> int:
    """Require indexed rows to agree with the manifest and source bytes."""
    pair = _pair(root)
    if pair is None:
        raise ValueError("synthetic knowledge pair is missing")
    manifest, database = pair
    source_files(root)
    payload = load_manifest(manifest)
    if (not isinstance(payload, dict) or set(payload) != {"schema", "sources"}
            or type(payload["schema"]) is not int or payload["schema"] != 1
            or not isinstance(payload["sources"], list)):
        raise ValueError("invalid synthetic knowledge manifest")
    source_manifest = read_regular_file(root / "manifest.csv", 1024 * 1024)
    approved = {row["document_id"]: row for row in csv.DictReader(
        io.StringIO(source_manifest.decode("utf-8"), newline=""))}
    listed: dict[str, dict[str, object]] = {}
    for item in payload["sources"]:
        if (not isinstance(item, dict) or not set(FIELDS) <= set(item)
                or not isinstance(item.get("document_id"), str)
                or item["document_id"] in listed
                or item["document_id"] not in approved
                or any(str(item.get(key)) != approved[item["document_id"]][key]
                       for key in FIELDS)):
            raise ValueError("knowledge manifest differs from source inventory")
        listed[item["document_id"]] = item
    details = database.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE:
        raise ValueError("unsafe synthetic knowledge database")
    try:
        uri = f"file:{quote(str(database.resolve()), safe='/')}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            if connection.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                raise ValueError("synthetic knowledge database failed integrity check")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValueError("synthetic knowledge database has orphaned passages")
            rows = connection.execute(
                "SELECT document_id,relative_path,collection,classification,owner,"
                "version,sha256,source_type,state FROM sources").fetchall()
            quarantine = {row[0] for row in connection.execute(
                "SELECT document_id FROM quarantine")}
            passages: dict[str, list[tuple[int, str]]] = {}
            for document_id, ordinal, content in connection.execute(
                    "SELECT document_id,ordinal,text FROM passages "
                    "ORDER BY document_id,ordinal"):
                passages.setdefault(document_id, []).append((ordinal, content))
    except sqlite3.DatabaseError as exc:
        raise ValueError("invalid synthetic knowledge database") from exc
    ready: set[str] = set()
    for row in rows:
        document_id = row[0]
        item = listed.get(document_id)
        if (item is None or document_id in ready or row[-1] != "ready"
                or any(str(item[key]) != row[index + 1]
                       for index, key in enumerate(_METADATA))):
            raise ValueError("knowledge index differs from approved manifest")
        try:
            suffix, _, payload = _valid_source(root, item)
            expected = list(enumerate(chunks(
                _parse_verified_bytes(payload, suffix, parse_local))))
        except (OSError, ValueError, UnicodeError, RuntimeError, ImportError) as exc:
            raise ValueError("approved source cannot be re-parsed for recovery") from exc
        if passages.get(document_id) != expected:
            raise ValueError("knowledge passages differ from approved source")
        ready.add(document_id)
    if (ready & quarantine or ready | quarantine != set(listed)
            or set(passages) != ready):
        raise ValueError("knowledge index has incomplete source state")
    return len(ready)


def stage_knowledge_pair(state: Path, frozen: Path) -> tuple[Path, Path] | None:
    """Copy the approved JSON and a consistent SQLite backup into private staging."""
    pair = _pair(state)
    if pair is None:
        return None
    manifest, database = pair
    verify_knowledge_pair(state)
    staged_manifest, staged_database = frozen / manifest.name, frozen / database.name
    staged_manifest.write_bytes(read_manifest_bytes(manifest))
    staged_manifest.chmod(0o600)
    try:
        uri = f"file:{quote(str(database.resolve()), safe='/')}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as original:
            with closing(sqlite3.connect(staged_database)) as snapshot:
                original.backup(snapshot)
    except sqlite3.DatabaseError as exc:
        raise ValueError("cannot freeze synthetic knowledge database") from exc
    staged_database.chmod(0o600)
    verify_knowledge_pair(frozen)
    return staged_manifest, staged_database
