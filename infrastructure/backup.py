"""Authenticated, synthetic-only backup and clean-directory restore.

The backup key is supplied separately and is never included in the archive.
Plaintext SQLite snapshots use a private temporary directory; production use
requires an approved encrypted staging filesystem and key-custody procedure.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import struct
import tempfile
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SVBK1\x00"
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK = 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_FILES = 32
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


class BackupError(ValueError):
    """Invalid backup input, authentication or payload."""


def _key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BackupError("backup key file is missing or linked")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise BackupError("backup key must contain 32 raw bytes")
    return raw


def generate_key(path: Path) -> None:
    """Generate a synthetic test key in a new, owner-only file."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _name(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BackupError("invalid archive name")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise BackupError("unsafe archive name")
    if path.suffix.lower() in (".key", ".pem", ".p12", ".pfx"):
        raise BackupError("key material must use separate custody")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BackupError("duplicate JSON key")
        result[key] = value
    return result


def _snapshot(spec: dict[str, object], base: Path, stage: Path, key_path: Path,
              output: Path, *, max_file: int = MAX_FILE) -> list[dict[str, object]]:
    if type(max_file) is not int or not 1 <= max_file <= MAX_TOTAL:
        raise BackupError("invalid snapshot file limit")
    if not isinstance(spec, dict) or set(spec) != {"schema", "files"} or spec["schema"] != 1:
        raise BackupError("invalid backup specification")
    files = spec["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise BackupError("invalid backup file count")
    names: set[str] = set()
    rows = []
    total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"name", "kind", "source"}:
            raise BackupError("invalid backup file entry")
        name = _name(entry["name"])
        if name in names or entry["kind"] not in ("file", "sqlite") or not isinstance(entry["source"], str):
            raise BackupError("duplicate name or invalid source")
        names.add(name)
        source = (base / entry["source"]).absolute()
        if (source.is_symlink() or not source.is_file() or source.resolve() in
                (key_path.resolve(), output.resolve())):
            raise BackupError("source is missing, linked or prohibited")
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if entry["kind"] == "sqlite":
            try:
                uri = f"file:{quote(str(source.resolve()), safe='/')}?mode=ro"
                with closing(sqlite3.connect(uri, uri=True, timeout=5)) as original:
                    with closing(sqlite3.connect(destination)) as snapshot:
                        original.backup(snapshot)
                with closing(sqlite3.connect(destination)) as check:
                    if check.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                        raise BackupError("SQLite snapshot failed integrity check")
            except sqlite3.Error as exc:
                raise BackupError("SQLite snapshot failed") from exc
        else:
            shutil.copyfile(source, destination)
        size = destination.stat().st_size
        total += size
        if size > max_file or total > MAX_TOTAL:
            raise BackupError("backup exceeds synthetic size limit")
        rows.append({"name": name, "kind": entry["kind"], "size": size,
                     "sha256": _sha256(destination)})
    return rows


def create_backup(spec_path: Path, output: Path, key_path: Path) -> dict[str, object]:
    """Snapshot allowlisted files, then encrypt a bounded stream with AES-256-GCM."""
    key = _key(key_path)
    output = output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise BackupError("output must be a new file in an existing directory")
    spec = json.loads(spec_path.read_text(), object_pairs_hook=_unique_object)
    with tempfile.TemporaryDirectory(prefix=".svbk-snapshot-", dir=output.parent) as temporary:
        stage = Path(temporary)
        rows = _snapshot(spec, spec_path.parent, stage, key_path, output)
        manifest: dict[str, object] = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                                       "files": rows}
        metadata = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        if len(metadata) > MAX_MANIFEST:
            raise BackupError("manifest too large")
        nonce = os.urandom(NONCE_SIZE)
        header = MAGIC + nonce
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as archive:
                archive.write(header)
                archive.write(encryptor.update(struct.pack(">I", len(metadata)) + metadata))
                for row in rows:
                    with (stage / str(row["name"])).open("rb") as source:
                        for block in iter(lambda: source.read(CHUNK), b""):
                            archive.write(encryptor.update(block))
                archive.write(encryptor.finalize())
                archive.write(encryptor.tag)
                archive.flush()
                os.fsync(archive.fileno())
            return manifest
        except Exception:
            output.unlink(missing_ok=True)
            raise


def _decrypt(backup: Path, key: bytes, plaintext: Path) -> None:
    if backup.is_symlink() or not backup.is_file():
        raise BackupError("backup is missing or linked")
    size = backup.stat().st_size
    minimum = len(MAGIC) + NONCE_SIZE + TAG_SIZE + 4
    if size < minimum or size > MAX_TOTAL + MAX_MANIFEST + minimum:
        raise BackupError("invalid backup size")
    with backup.open("rb") as archive:
        header = archive.read(len(MAGIC) + NONCE_SIZE)
        if not header.startswith(MAGIC):
            raise BackupError("invalid backup header")
        archive.seek(-TAG_SIZE, os.SEEK_END)
        tag = archive.read(TAG_SIZE)
        archive.seek(len(header))
        remaining = size - len(header) - TAG_SIZE
        decryptor = Cipher(algorithms.AES(key), modes.GCM(header[len(MAGIC):], tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        with plaintext.open("xb") as destination:
            while remaining:
                chunk = archive.read(min(CHUNK, remaining))
                if not chunk:
                    raise BackupError("truncated ciphertext")
                destination.write(decryptor.update(chunk))
                remaining -= len(chunk)
            try:
                destination.write(decryptor.finalize())
            except InvalidTag as exc:
                raise BackupError("backup authentication failed") from exc


def _read_payload(plaintext: Path, stage: Path | None) -> dict[str, object]:
    with plaintext.open("rb") as stream:
        prefix = stream.read(4)
        if len(prefix) != 4:
            raise BackupError("missing manifest")
        length = struct.unpack(">I", prefix)[0]
        if not 0 < length <= MAX_MANIFEST:
            raise BackupError("invalid manifest size")
        try:
            manifest = json.loads(stream.read(length), object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError) as exc:
            raise BackupError("invalid manifest") from exc
        if (not isinstance(manifest, dict) or set(manifest) != {"schema", "created_utc", "files"}
                or manifest["schema"] != 1 or not isinstance(manifest["created_utc"], str)):
            raise BackupError("invalid manifest fields")
        files = manifest["files"]
        if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
            raise BackupError("invalid file inventory")
        names: set[str] = set()
        total = 0
        for row in files:
            if not isinstance(row, dict) or set(row) != {"name", "kind", "size", "sha256"}:
                raise BackupError("invalid file record")
            name = _name(row["name"])
            if name in names or row["kind"] not in ("file", "sqlite"):
                raise BackupError("duplicate or invalid file record")
            names.add(name)
            size, digest = row["size"], row["sha256"]
            if (not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAX_FILE
                    or not isinstance(digest, str) or len(digest) != 64):
                raise BackupError("invalid file metadata")
            total += size
            if total > MAX_TOTAL:
                raise BackupError("backup payload too large")
            target = stage / name if stage is not None else None
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            checksum = hashlib.sha256()
            with (target.open("xb") if target is not None else open(os.devnull, "wb")) as output:
                remaining = size
                while remaining:
                    block = stream.read(min(CHUNK, remaining))
                    if not block:
                        raise BackupError("truncated payload")
                    checksum.update(block)
                    if target is not None:
                        output.write(block)
                    remaining -= len(block)
            if checksum.hexdigest() != digest:
                raise BackupError("payload checksum mismatch")
            if target is not None:
                target.chmod(0o600)
        if stream.read(1):
            raise BackupError("unlisted payload bytes")
    return manifest


def inspect_backup(backup: Path, key_path: Path, destination: Path | None = None) -> dict[str, object]:
    """Authenticate first; optionally restore into a nonexistent directory."""
    key = _key(key_path)
    if destination is not None and (destination.exists() or destination.is_symlink()):
        raise BackupError("restore destination must not exist")
    parent = destination.parent if destination is not None else None
    if parent is not None and not parent.is_dir():
        raise BackupError("restore parent must exist")
    with tempfile.TemporaryDirectory(prefix=".svbk-restore-", dir=parent) as temporary:
        workspace = Path(temporary)
        plaintext = workspace / "payload.bin"
        _decrypt(backup, key, plaintext)
        stage = workspace / "restored" if destination is not None else None
        if stage is not None:
            stage.mkdir(mode=0o700)
        manifest = _read_payload(plaintext, stage)
        if stage is not None:
            if destination.exists() or destination.is_symlink():
                raise BackupError("restore destination appeared during verification")
            os.rename(stage, destination)
        return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic encrypted backup and restore")
    actions = parser.add_subparsers(dest="action", required=True)
    keygen = actions.add_parser("keygen")
    keygen.add_argument("path", type=Path)
    create = actions.add_parser("create")
    create.add_argument("--spec", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--key", required=True, type=Path)
    for action in ("verify", "restore"):
        sub = actions.add_parser(action)
        sub.add_argument("--backup", required=True, type=Path)
        sub.add_argument("--key", required=True, type=Path)
        if action == "restore":
            sub.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "keygen":
            generate_key(args.path)
            print("Created synthetic backup key")
            return
        result = (create_backup(args.spec, args.output, args.key) if args.action == "create"
                  else inspect_backup(args.backup, args.key,
                                      args.destination if args.action == "restore" else None))
    except (BackupError, OSError, ValueError) as exc:
        parser.exit(1, f"backup: {exc}\n")
    label = {"create": "Created", "verify": "Verified", "restore": "Restored"}[args.action]
    print(f"{label} authenticated backup with {len(result['files'])} files")


if __name__ == "__main__":
    main()
