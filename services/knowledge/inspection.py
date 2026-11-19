"""Pinned, offline ClamAV gate for exact staged document bytes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from services.knowledge.ingestion import MAX_BYTES, SUPPORTED

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(?:cvd|cld|hdb|ndb|ldb)\Z")
MAX_DATABASE_FILE = 256 * 1024 * 1024
MAX_DATABASE_TOTAL = 512 * 1024 * 1024


class InspectionError(ValueError):
    pass


def _hash_file(path: Path, maximum: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_size > maximum:
            raise InspectionError("invalid scanner file")
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise InspectionError("scanner file too large")
            digest.update(chunk)
    return digest.hexdigest()


def _profile(path: Path) -> tuple[dict[str, object], str]:
    if not path.is_absolute():
        raise InspectionError("invalid inspection profile")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) & 0o077):
            raise InspectionError("inspection profile must be owner-only")
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise InspectionError("inspection profile too large")
    try:
        profile = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise InspectionError("invalid inspection profile") from exc
    if (not isinstance(profile, dict) or set(profile) != {
            "schema", "scanner", "scanner_sha256", "database", "database_files", "database_as_of"} or
            profile["schema"] != 1):
        raise InspectionError("invalid inspection profile")
    scanner = Path(profile["scanner"]) if isinstance(profile["scanner"], str) else Path(".")
    database = Path(profile["database"]) if isinstance(profile["database"], str) else Path(".")
    if (not scanner.is_absolute() or scanner.is_symlink() or not scanner.is_file() or
            not os.access(scanner, os.X_OK) or not database.is_absolute() or database.is_symlink() or
            not database.is_dir() or database.stat().st_mode & 0o022):
        raise InspectionError("scanner or database unavailable")
    if not isinstance(profile["scanner_sha256"], str) or not _DIGEST.fullmatch(profile["scanner_sha256"]):
        raise InspectionError("invalid scanner digest")
    if _hash_file(scanner, 128 * 1024 * 1024) != profile["scanner_sha256"]:
        raise InspectionError("scanner binary changed")
    files = profile["database_files"]
    if (not isinstance(files, dict) or not 1 <= len(files) <= 16 or
            any(not isinstance(name, str) or not _DB_NAME.fullmatch(name) or
                not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
                for name, digest in files.items()) or set(os.listdir(database)) != set(files)):
        raise InspectionError("scanner database inventory changed")
    total = 0
    for name, digest in files.items():
        total += (database / name).stat().st_size
        if total > MAX_DATABASE_TOTAL:
            raise InspectionError("scanner database too large")
        if _hash_file(database / name, MAX_DATABASE_FILE) != digest:
            raise InspectionError("scanner database changed")
    try:
        as_of = datetime.fromisoformat(profile["database_as_of"])
    except (ValueError, TypeError) as exc:
        raise InspectionError("invalid scanner database date") from exc
    now = datetime.now(timezone.utc)
    if (as_of.tzinfo is None or as_of > now + timedelta(minutes=5) or
            now - as_of > timedelta(days=30)):
        raise InspectionError("scanner database is stale")
    return profile, hashlib.sha256(raw).hexdigest()


def create_profile(scanner: Path, database: Path, database_as_of: str) -> bytes:
    """Prepare an owner-reviewed, exact binary/database inventory for signing."""
    scanner = scanner.resolve(strict=True)
    database = database.resolve(strict=True)
    if not scanner.is_file() or not database.is_dir():
        raise InspectionError("scanner or database unavailable")
    names = sorted(os.listdir(database))
    if not 1 <= len(names) <= 16 or any(not _DB_NAME.fullmatch(name) for name in names):
        raise InspectionError("unsupported scanner database inventory")
    if sum((database / name).stat().st_size for name in names) > MAX_DATABASE_TOTAL:
        raise InspectionError("scanner database too large")
    profile = {
        "schema": 1, "scanner": str(scanner),
        "scanner_sha256": _hash_file(scanner, 128 * 1024 * 1024),
        "database": str(database),
        "database_files": {name: _hash_file(database / name, MAX_DATABASE_FILE)
                           for name in names},
        "database_as_of": database_as_of,
    }
    # Reuse the same freshness rules as the scanner before a profile is saved.
    try:
        as_of = datetime.fromisoformat(database_as_of)
    except (ValueError, TypeError) as exc:
        raise InspectionError("invalid scanner database date") from exc
    now = datetime.now(timezone.utc)
    if (as_of.tzinfo is None or as_of > now + timedelta(minutes=5) or
            now - as_of > timedelta(days=30)):
        raise InspectionError("scanner database is stale")
    return json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _copy_verified_database(profile: dict[str, object], destination: Path) -> None:
    destination.mkdir(mode=0o700)
    source = Path(str(profile["database"]))
    for name, expected in profile["database_files"].items():
        source_fd = os.open(source / name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            target_fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except Exception:
            os.close(source_fd)
            raise
        try:
            details = os.fstat(source_fd)
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_DATABASE_FILE:
                raise InspectionError("scanner database changed")
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(source_fd, "rb", closefd=False) as input_stream, \
                    os.fdopen(target_fd, "wb", closefd=False) as output_stream:
                while chunk := input_stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_DATABASE_FILE:
                        raise InspectionError("scanner database changed")
                    digest.update(chunk)
                    output_stream.write(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            if digest.hexdigest() != expected:
                raise InspectionError("scanner database changed")
        finally:
            os.close(source_fd)
            os.close(target_fd)


def inspect_document(payload: bytes, suffix: str, profile_path: Path) -> str:
    """Return profile digest only after a clean, exact-byte offline scan."""
    if not payload or len(payload) > MAX_BYTES or suffix not in SUPPORTED:
        raise InspectionError("invalid document for inspection")
    profile, profile_digest = _profile(profile_path)
    with tempfile.TemporaryDirectory(prefix="sovereign-inspection-") as temporary:
        database_snapshot = Path(temporary) / "database"
        _copy_verified_database(profile, database_snapshot)
        snapshot = Path(temporary) / f"verified{suffix}"
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        command = [str(profile["scanner"]), f"--database={database_snapshot}",
                   "--no-summary", "--alert-exceeds-max=yes", "--alert-encrypted=yes",
                   "--max-filesize=16M", "--max-scansize=64M", "--max-files=512",
                   "--max-recursion=12", "--max-scantime=60000",
                   "--follow-file-symlinks=0", f"--tempdir={temporary}", str(snapshot)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=90, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InspectionError("document scanner unavailable") from exc
    if result.returncode == 1:
        raise InspectionError("document inspection rejected")
    if result.returncode != 0:
        raise InspectionError("document scanner unavailable")
    return profile_digest
