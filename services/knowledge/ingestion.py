"""Allowlisted, local-only document ingestion for the synthetic Phase 3 lab.

The source manifest is authoritative. A failed read, parse or ACL check never
leaves an old searchable version behind. Only metadata and parsed passages are
stored; source files remain in the read-only fixture tree.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Callable
from zipfile import BadZipFile, ZipFile

SUPPORTED = {".pdf", ".docx", ".xlsx", ".txt"}
MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT = 2 * 1024 * 1024
_ID = re.compile(r"[A-Z0-9][A-Z0-9_-]{2,79}\Z")
_PARSER_LOCK = RLock()
_PARSER_PROCESS = None
_PARSER_PIPE = None


def _serve_parser(pipe) -> None:
    import os
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    from services.knowledge.parse_worker import convert
    while True:
        try:
            path = pipe.recv()
        except EOFError:
            return
        try:
            pipe.send((True, convert(Path(path))))
        except Exception as exc:
            pipe.send((False, type(exc).__name__))


def _parser() -> object:
    global _PARSER_PROCESS, _PARSER_PIPE
    if _PARSER_PROCESS is None or not _PARSER_PROCESS.is_alive():
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        _PARSER_PROCESS = context.Process(target=_serve_parser, args=(child,), daemon=True)
        _PARSER_PROCESS.start()
        child.close()
        _PARSER_PIPE = parent
    return _PARSER_PIPE


def parse_local(path: Path) -> str:
    """Parse locally in a time-bounded subprocess for untrusted formats."""
    if path.suffix == ".txt":
        return path.read_text(encoding="utf-8")
    with _PARSER_LOCK:
        pipe = _parser()
        pipe.send(str(path.resolve()))
        if not pipe.poll(45):
            _PARSER_PROCESS.terminate()
            _PARSER_PROCESS.join(timeout=2)
            raise ValueError("parser timeout")
        try:
            success, value = pipe.recv()
        except EOFError as exc:
            raise ValueError("parser worker stopped") from exc
        if not success or len(value) > MAX_TEXT:
            raise ValueError("parser failed or exceeded output limit")
        return value


def chunks(text: str, size: int = 1200, overlap: int = 150) -> list[str]:
    clean = " ".join(text.split())
    if not clean or len(clean) > MAX_TEXT:
        raise ValueError("empty or excessive parsed text")
    if size <= overlap or overlap < 0:
        raise ValueError("invalid chunk bounds")
    return [clean[start:start + size] for start in range(0, len(clean), size - overlap)]


def _connect(database: Path) -> sqlite3.Connection:
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS sources (
            document_id TEXT PRIMARY KEY, relative_path TEXT NOT NULL,
            collection TEXT NOT NULL, classification TEXT NOT NULL,
            owner TEXT NOT NULL, version TEXT NOT NULL, sha256 TEXT NOT NULL,
            source_type TEXT NOT NULL, state TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passages (
            document_id TEXT NOT NULL REFERENCES sources(document_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL, text TEXT NOT NULL,
            PRIMARY KEY (document_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS quarantine (
            document_id TEXT PRIMARY KEY, reason TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS passages_source ON passages(document_id);
    """)
    return connection


def _valid_source(root: Path, item: dict[str, object]) -> tuple[Path, str]:
    document_id = item.get("document_id")
    relative = item.get("relative_path")
    digest = item.get("sha256")
    if not isinstance(document_id, str) or not _ID.fullmatch(document_id):
        raise ValueError("invalid source id")
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("invalid source path")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
        raise ValueError("source escapes approved root")
    if path.suffix.casefold() not in SUPPORTED:
        raise ValueError("unsupported format")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("source exceeds size limit")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("missing source hash")
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("source hash mismatch")
    if path.suffix.casefold() in {".docx", ".xlsx"}:
        try:
            with ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > 512 or sum(member.file_size for member in members) > 16 * 1024 * 1024:
                    raise ValueError("archive resource limit")
                for member in members:
                    if (Path(member.filename).is_absolute() or ".." in Path(member.filename).parts or
                            member.file_size > 100 * max(member.compress_size, 1)):
                        raise ValueError("unsafe archive member")
        except BadZipFile as exc:
            raise ValueError("malformed office archive") from exc
    for key in ("owner", "collection", "classification", "version", "source_type"):
        if not isinstance(item.get(key), str) or not item[key]:
            raise ValueError(f"missing {key}")
    return path, digest


def sync_manifest(
    root: Path, manifest: Path, database: Path,
    parser: Callable[[Path], str] = parse_local,
) -> dict[str, object]:
    """Replace index contents from an approved manifest, failing closed per source.

    The caller must mount the source root read-only. Only manifest-listed paths
    are opened. Deletions are reconciled in the same transaction as additions.
    """
    base = root.resolve(strict=True)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != 1 or not isinstance(payload.get("sources"), list):
        raise ValueError("invalid ingestion manifest")
    sources = payload["sources"]
    if len(sources) > 10000:
        raise ValueError("manifest too large")
    ids = [item.get("document_id") for item in sources if isinstance(item, dict)]
    if len(ids) != len(sources) or len(set(ids)) != len(ids):
        raise ValueError("duplicate or invalid source entries")
    result: dict[str, object] = {"indexed": [], "unchanged": [], "quarantined": [], "deleted": []}
    with _connect(database) as db:
        existing = {row["document_id"]: row for row in db.execute("SELECT * FROM sources")}
        active_ids = set(ids)
        seen_hashes: set[str] = set()
        for old in existing.keys() - active_ids:
            db.execute("DELETE FROM sources WHERE document_id=?", (old,))
            db.execute("DELETE FROM quarantine WHERE document_id=?", (old,))
            result["deleted"].append(old)
        for item in sources:
            document_id = item["document_id"]
            try:
                path, digest = _valid_source(base, item)
                if digest in seen_hashes:
                    raise ValueError("duplicate source payload")
                seen_hashes.add(digest)
                previous = existing.get(document_id)
                metadata = (item["relative_path"], item["collection"], item["classification"],
                            item["owner"], str(item["version"]), digest, item["source_type"])
                if previous and previous["state"] == "ready" and tuple(previous[key] for key in
                        ("relative_path", "collection", "classification", "owner", "version", "sha256", "source_type")) == metadata:
                    result["unchanged"].append(document_id)
                    continue
                passage_text = chunks(parser(path))
                db.execute("DELETE FROM sources WHERE document_id=?", (document_id,))
                db.execute("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?)",
                           (document_id, *metadata, "ready"))
                db.executemany("INSERT INTO passages VALUES (?,?,?)",
                               [(document_id, ordinal, passage) for ordinal, passage in enumerate(passage_text)])
                db.execute("DELETE FROM quarantine WHERE document_id=?", (document_id,))
                result["indexed"].append(document_id)
            except (OSError, ValueError, UnicodeError, RuntimeError, ImportError) as exc:
                db.execute("DELETE FROM sources WHERE document_id=?", (document_id,))
                db.execute("INSERT OR REPLACE INTO quarantine VALUES (?,?)", (document_id, type(exc).__name__))
                result["quarantined"].append(document_id)
    return result
