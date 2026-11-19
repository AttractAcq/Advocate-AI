"""Encrypted synthetic Fleet catalog snapshot and clean audited restore."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from infrastructure.backup import (
    BackupError, MAX_FILE, MAX_MANIFEST, create_backup, inspect_backup,
)
from services.fleet.catalog import FleetCatalog, FleetError


class FleetBackupError(ValueError):
    """Fleet catalog backup or restore failed policy validation."""


_FREE_SPACE_RESERVE = 128 * 1024 * 1024


def _check_backup_space(db: Path, directory: Path) -> None:
    """Reserve room for a SQLite snapshot and ciphertext on the archive volume."""
    wal = db.with_name(db.name + "-wal")
    if wal.is_symlink() or (wal.exists() and not wal.is_file()):
        raise FleetBackupError("Fleet database WAL must be a regular file")
    size = db.stat().st_size + (wal.stat().st_size if wal.exists() else 0)
    if size > MAX_FILE:
        raise FleetBackupError("Fleet database exceeds synthetic backup limit")
    # Both the private SQLite snapshot and encrypted archive are written here.
    required = 2 * (max(size, 4096) + MAX_MANIFEST + 64) + _FREE_SPACE_RESERVE
    volume = os.statvfs(directory)
    if volume.f_bavail * volume.f_frsize < required:
        raise FleetBackupError("insufficient Fleet backup staging and archive space")


def _check_restore_space(archive: Path, directory: Path) -> None:
    """Reserve room for decrypted payload and its clean restored SQLite copy."""
    size = archive.stat().st_size
    required = 2 * size + _FREE_SPACE_RESERVE
    volume = os.statvfs(directory)
    if volume.f_bavail * volume.f_frsize < required:
        raise FleetBackupError("insufficient Fleet restore staging space")


def _owner_file(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise FleetBackupError("Fleet backup input must be owner-only")


def _owner_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise FleetBackupError("Fleet backup directory must be owner-only")


def backup_fleet(db: Path, output: Path, key: Path) -> dict[str, object]:
    """Verify the catalog, snapshot SQLite, and encrypt only its database."""
    _owner_file(db)
    _owner_file(key)
    _owner_directory(output.parent)
    FleetCatalog(db)
    _check_backup_space(db, output.parent)
    descriptor, filename = tempfile.mkstemp(prefix=".fleet-backup-spec-", dir=output.parent)
    spec = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"schema": 1, "files": [{"name": "fleet.db", "kind": "sqlite",
                                                "source": str(db)}]}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        manifest = create_backup(spec, output, key)
        if [(item["name"], item["kind"]) for item in manifest["files"]] != \
                [("fleet.db", "sqlite")]:
            raise FleetBackupError("Fleet backup contains unexpected files")
        return {"created_utc": manifest["created_utc"], "files": 1,
                "archive": str(output)}
    finally:
        spec.unlink(missing_ok=True)


def restore_fleet(archive: Path, key: Path, destination: Path) -> dict[str, object]:
    """Authenticate into a new directory, then verify the Fleet audit chain."""
    _owner_file(archive)
    _owner_file(key)
    _owner_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FleetBackupError("Fleet restore requires a new directory")
    _check_restore_space(archive, destination.parent)
    try:
        manifest = inspect_backup(archive, key, destination)
        if [(item["name"], item["kind"]) for item in manifest["files"]] != \
                [("fleet.db", "sqlite")]:
            raise FleetBackupError("Fleet restore contains unexpected files")
        _owner_directory(destination)
        _owner_file(destination / "fleet.db")
        FleetCatalog(destination / "fleet.db")
        return {"created_utc": manifest["created_utc"], "files": 1,
                "database": str(destination / "fleet.db")}
    except Exception:
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic encrypted Fleet catalog recovery")
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--db", required=True, type=Path)
    backup.add_argument("--output", required=True, type=Path)
    backup.add_argument("--key", required=True, type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("--archive", required=True, type=Path)
    restore.add_argument("--key", required=True, type=Path)
    restore.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (backup_fleet(args.db, args.output, args.key) if args.command == "backup"
                  else restore_fleet(args.archive, args.key, args.destination))
    except (BackupError, FleetBackupError, FleetError, OSError, ValueError) as exc:
        parser.exit(1, f"Fleet backup: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
