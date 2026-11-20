"""Explicit synthetic Core history migration with a verified encrypted backup."""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from apps.api.auth import _history_shape, migrate_legacy_history
from infrastructure.restic_repository import create_snapshot, restore_snapshot


class HistoryMigrationError(ValueError):
    """The legacy history or its recovery evidence is not safe to migrate."""


def _private_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise HistoryMigrationError("migration directory must be owner-only")


def _fingerprint(path: Path, expected_version: int) -> tuple[str, int]:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise HistoryMigrationError("unsafe migration history database")
    digest = hashlib.sha256()
    count = 0
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA user_version").fetchone() != (expected_version,):
                raise HistoryMigrationError("unexpected history schema version")
            _history_shape(db)
            for identifier, owner, raw in db.execute(
                    "SELECT id,owner,turns_json FROM conversations ORDER BY id"):
                if (not isinstance(identifier, str) or not 1 <= len(identifier) <= 80
                        or not isinstance(owner, str) or not 1 <= len(owner) <= 200):
                    raise HistoryMigrationError("invalid history identity")
                turns = json.loads(raw)
                if (not isinstance(turns, list) or len(turns) > 20 or
                        any(not isinstance(turn, dict) for turn in turns)):
                    raise HistoryMigrationError("invalid history turns")
                encoded = json.dumps([identifier, owner, turns], sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode()
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
                count += 1
    except (sqlite3.DatabaseError, UnicodeError, TypeError, OverflowError) as exc:
        raise HistoryMigrationError("history database cannot be verified") from exc
    return digest.hexdigest(), count


def _write_evidence(path: Path, payload: dict[str, object], *, replace: bool) -> None:
    if path.is_symlink() or (not replace and path.exists()):
        raise HistoryMigrationError("migration evidence already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".history-migration-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        if replace and not path.is_file():
            raise HistoryMigrationError("migration evidence disappeared")
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            Path(temporary).unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def migrate_history_with_backup(history: Path, repository: Path,
                                password_file: Path, restic: Path,
                                restic_sha256: str, staging_parent: Path,
                                evidence: Path) -> dict[str, object]:
    """Verify a clean encrypted restore before explicitly ledgering legacy history.

    The caller must stop Core and retain the repository and evidence off vessel.
    This isolated synthetic helper does not change installation active state.
    """
    _private_directory(history.parent)
    _private_directory(staging_parent)
    _private_directory(evidence.parent)
    if (history.name != "history.db" or not repository.is_absolute() or
            not evidence.is_absolute() or
            evidence.exists() or evidence.is_symlink() or
            repository.resolve().is_relative_to(history.parent.resolve()) or
            staging_parent.resolve().is_relative_to(history.parent.resolve()) or
            evidence.parent.resolve().is_relative_to(history.parent.resolve()) or
            history.parent.resolve().is_relative_to(repository.resolve()) or
            history.parent.resolve().is_relative_to(staging_parent.resolve()) or
            history.parent.resolve().is_relative_to(evidence.parent.resolve()) or
            evidence.parent.resolve().is_relative_to(repository.resolve()) or
            repository.resolve().is_relative_to(evidence.parent.resolve())):
        raise HistoryMigrationError("migration paths overlap Core state")
    before, count = _fingerprint(history, 0)
    descriptor, spec_name = tempfile.mkstemp(prefix=".history-migration-spec-",
                                             suffix=".json", dir=history.parent)
    spec = Path(spec_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b'{"schema":1,"files":[{"name":"history.db",'
                         b'"kind":"sqlite","source":"history.db"}]}')
            stream.flush()
            os.fsync(stream.fileno())
        snapshot = create_snapshot(spec, repository, password_file, restic,
                                   restic_sha256, staging_parent)
        if snapshot.get("status") != "snapshot-verified" or snapshot.get("files") != 1:
            raise HistoryMigrationError("encrypted history snapshot did not verify")
        snapshot_id = snapshot["snapshot_id"]
        with tempfile.TemporaryDirectory(prefix=".history-migration-verify-",
                                         dir=staging_parent) as temporary:
            restored = Path(temporary) / "restored"
            result = restore_snapshot(snapshot_id, repository, password_file,
                                      restic, restic_sha256, restored)
            if result.get("files") != 1 or result.get("snapshot_id") != snapshot_id:
                raise HistoryMigrationError("clean history restore did not verify")
            if _fingerprint(restored / "history.db", 0) != (before, count):
                raise HistoryMigrationError("restored history differs from live state")
        if _fingerprint(history, 0) != (before, count):
            raise HistoryMigrationError("live history changed during backup")
        record: dict[str, object] = {"schema": 1, "status": "backup-verified",
                                     "snapshot_id": snapshot_id,
                                     "repository": str(repository.resolve()),
                                     "history_sha256": before, "conversations": count}
        _write_evidence(evidence, record, replace=False)
        migrated = migrate_legacy_history(history)
        if migrated != count or _fingerprint(history, 1) != (before, count):
            raise HistoryMigrationError("migrated history changed; retain backup")
        record["status"] = "migration-complete"
        _write_evidence(evidence, record, replace=True)
        return record
    finally:
        spec.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate stopped synthetic Core history after verified encrypted backup")
    parser.add_argument("--synthetic-lab", action="store_true", required=True)
    parser.add_argument("--history-db", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--restic", type=Path, required=True)
    parser.add_argument("--restic-sha256", required=True)
    parser.add_argument("--staging-parent", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    result = migrate_history_with_backup(args.history_db, args.repository,
                                         args.password_file, args.restic,
                                         args.restic_sha256, args.staging_parent,
                                         args.evidence)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
