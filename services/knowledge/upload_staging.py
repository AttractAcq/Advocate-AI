"""Bounded, private upload quarantine; never an approved knowledge source."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
from uuid import uuid4

from services.knowledge.ingestion import MAX_BYTES, SUPPORTED

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,119}\Z")
_LOCK = Lock()
MAX_PENDING = 100


def _directory(root: Path) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("invalid upload area")
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    mode = root.stat().st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o077:
        raise ValueError("upload area must be private")


@contextmanager
def quarantine_directory_lock(root: Path, *, exclusive: bool):
    """Coordinate upload writers and a backup reader across Core processes."""
    _directory(root)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError("upload area changed during lock acquisition")
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _metadata(root: Path, name: str) -> dict[str, object]:
    path = root / name
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > 2048 or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError("invalid upload record")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = json.loads(stream.read(2049))
        if not isinstance(value, dict) or value.get("status") not in {"pending", "approved"}:
            raise ValueError("invalid upload record")
        return value
    finally:
        os.close(fd)


def list_uploads(root: Path, actor: str) -> list[dict[str, object]]:
    with quarantine_directory_lock(root, exclusive=False):
        records = [_metadata(root, name) for name in os.listdir(root) if re.fullmatch(r"[0-9a-f]{32}\.json", name)]
    return sorted((item for item in records if item.get("uploader") == actor),
                  key=lambda item: str(item["created_at"]), reverse=True)


def stage_upload(root: Path, actor: str, filename: str, payload: bytes) -> dict[str, object]:
    if not _NAME.fullmatch(filename) or filename in {".", ".."} or Path(filename).suffix.lower() not in SUPPORTED:
        raise ValueError("unsupported or invalid filename")
    if not payload or len(payload) > MAX_BYTES:
        raise ValueError("invalid upload size")
    _directory(root)
    with _LOCK, quarantine_directory_lock(root, exclusive=True):
        if sum(_metadata(root, name).get("status") == "pending" for name in os.listdir(root)
               if re.fullmatch(r"[0-9a-f]{32}\.json", name)) >= MAX_PENDING:
            raise ValueError("upload area is full")
        identifier = uuid4().hex
        record: dict[str, object] = {
            "id": identifier, "filename": filename, "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(), "uploader": actor,
            "created_at": datetime.now(timezone.utc).isoformat(), "status": "pending",
        }
        blob = root / f"{identifier}.blob"
        metadata = root / f"{identifier}.json"
        blob_fd = os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(blob_fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            meta_fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(meta_fd, "w", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            blob.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)
            raise
        return record


def discard_upload(root: Path, identifier: str) -> None:
    """Remove an uncommitted submission if its audit decision cannot be saved."""
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("invalid upload id")
    with quarantine_directory_lock(root, exclusive=True):
        for suffix in (".json", ".blob"):
            (root / f"{identifier}{suffix}").unlink(missing_ok=True)
