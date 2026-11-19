"""Local restic repository adapter for allowlisted application snapshots."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from infrastructure.backup import BackupError, MAX_FILE, _name, _snapshot, _unique_object

RESTIC_VERSION = "0.19.1"
MANIFEST = "sovereign-snapshot-manifest.json"
SNAPSHOT_TAG = "sovereign-ai"
SNAPSHOT_HOST = "sovereign-ai"
_SNAPSHOT_ID = re.compile(r"[0-9a-f]{64}\Z")


class ResticError(ValueError):
    """The restic tool, local repository or snapshot failed validation."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool(restic: Path, expected_sha256: str) -> None:
    if (restic.is_symlink() or not restic.is_file() or len(expected_sha256) != 64 or
            any(char not in "0123456789abcdef" for char in expected_sha256) or
            _sha256(restic) != expected_sha256):
        raise ResticError("restic binary has no approved SHA-256")


def _credentials(password_file: Path) -> None:
    if password_file.is_symlink() or not password_file.is_file():
        raise ResticError("restic password file is missing or linked")
    if stat.S_IMODE(password_file.stat().st_mode) & 0o077:
        raise ResticError("restic password file must be owner-only")
    if len(password_file.read_bytes()) < 32:
        raise ResticError("restic password is too short")


def _run(restic: Path, repository: Path, password_file: Path, *arguments: str) -> str:
    argv = [str(restic), "--no-cache", "-r", str(repository),
            "--password-file", str(password_file), *arguments]
    try:
        completed = subprocess.run(argv, check=True, capture_output=True, text=True,
                                   timeout=300)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ResticError(f"restic {arguments[0]} failed") from exc
    return completed.stdout


def _preflight(restic: Path, restic_sha256: str, repository: Path,
               password_file: Path) -> None:
    _tool(restic, restic_sha256)
    _credentials(password_file)
    if (not repository.is_absolute() or ":" in str(repository) or
            repository.is_symlink() or (repository.exists() and not repository.is_dir())):
        raise ResticError("repository must be a local, unlinked absolute directory")
    result = subprocess.run([str(restic), "version"], check=True,
                            capture_output=True, text=True, timeout=10)
    if not result.stdout.startswith(f"restic {RESTIC_VERSION} "):
        raise ResticError("unapproved restic version")


def create_snapshot(spec_path: Path, repository: Path, password_file: Path,
                    restic: Path, restic_sha256: str, staging_parent: Path,
                    *, max_file: int = MAX_FILE) -> dict[str, object]:
    """Snapshot SQLite and allowlisted files, then store them in local restic."""
    _preflight(restic, restic_sha256, repository, password_file)
    if not staging_parent.is_dir() or staging_parent.is_symlink():
        raise ResticError("private staging parent is missing or linked")
    spec = json.loads(spec_path.read_text(), object_pairs_hook=_unique_object)
    with tempfile.TemporaryDirectory(prefix=".sovereign-restic-", dir=staging_parent) as temporary:
        stage = Path(temporary) / "snapshot"
        stage.mkdir(mode=0o700)
        rows = _snapshot(spec, spec_path.parent, stage, password_file, repository,
                         max_file=max_file)
        if any(row["name"] == MANIFEST for row in rows):
            raise ResticError("reserved snapshot manifest name")
        manifest = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                    "files": rows}
        (stage / MANIFEST).write_text(json.dumps(manifest, sort_keys=True))
        if not repository.exists():
            _run(restic, repository, password_file, "init")
        output = _run(restic, repository, password_file, "backup", str(stage), "--json",
                      "--tag", SNAPSHOT_TAG, "--host", SNAPSHOT_HOST)
        try:
            summaries = [json.loads(line) for line in output.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise ResticError("invalid restic backup report") from exc
        ids = [row.get("snapshot_id") for row in summaries
               if isinstance(row, dict) and row.get("message_type") == "summary"]
        if len(ids) != 1 or not isinstance(ids[0], str) or len(ids[0]) != 64:
            raise ResticError("restic did not return one snapshot ID")
        _run(restic, repository, password_file, "check", "--read-data")
        return {"status": "snapshot-verified", "snapshot_id": ids[0],
                "files": len(rows), "restic_version": RESTIC_VERSION}


def restore_snapshot(snapshot_id: str, repository: Path, password_file: Path,
                     restic: Path, restic_sha256: str, destination: Path) -> dict[str, object]:
    """Check the encrypted repository and restore one snapshot into a new dir."""
    _preflight(restic, restic_sha256, repository, password_file)
    if (len(snapshot_id) != 64 or any(char not in "0123456789abcdef" for char in snapshot_id)
            or destination.exists() or destination.is_symlink() or not destination.parent.is_dir()):
        raise ResticError("invalid snapshot ID or restore destination")
    _run(restic, repository, password_file, "check", "--read-data")
    with tempfile.TemporaryDirectory(prefix=".sovereign-restic-restore-",
                                     dir=destination.parent) as temporary:
        root = Path(temporary)
        _run(restic, repository, password_file, "restore", snapshot_id,
             "--target", str(root))
        manifests = list(root.rglob(MANIFEST))
        if len(manifests) != 1 or manifests[0].is_symlink():
            raise ResticError("snapshot manifest is missing or ambiguous")
        stage = manifests[0].parent
        try:
            manifest = json.loads(manifests[0].read_text(), object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError) as exc:
            raise ResticError("invalid snapshot manifest") from exc
        if (not isinstance(manifest, dict) or set(manifest) != {"schema", "created_utc", "files"}
                or manifest["schema"] != 1 or not isinstance(manifest["files"], list)):
            raise ResticError("invalid snapshot manifest fields")
        names: set[str] = set()
        for row in manifest["files"]:
            if (not isinstance(row, dict) or set(row) != {"name", "kind", "size", "sha256"}
                    or row["kind"] not in ("file", "sqlite") or
                    not isinstance(row["name"], str) or row["name"] in names or
                    not isinstance(row["size"], int) or isinstance(row["size"], bool) or
                    row["size"] < 0 or not isinstance(row["sha256"], str) or
                    len(row["sha256"]) != 64 or
                    any(char not in "0123456789abcdef" for char in row["sha256"])):
                raise ResticError("invalid snapshot file record")
            name = _name(row["name"])
            names.add(name)
            target = stage / name
            if (target.is_symlink() or not target.is_file() or
                    not target.resolve().is_relative_to(stage.resolve()) or
                    target.stat().st_size != row["size"] or _sha256(target) != row["sha256"]):
                raise ResticError("snapshot file changed")
        actual = set()
        for item in stage.rglob("*"):
            if item.is_symlink():
                raise ResticError("linked snapshot path")
            if item.is_file():
                actual.add(item.relative_to(stage).as_posix())
        if actual != names | {MANIFEST}:
            raise ResticError("unlisted snapshot file")
        if destination.exists() or destination.is_symlink():
            raise ResticError("restore destination appeared")
        shutil.move(stage, destination)
        return {"status": "restored", "snapshot_id": snapshot_id,
                "files": len(names), "restic_version": RESTIC_VERSION}


def verify_repository(repository: Path, password_file: Path, restic: Path,
                      restic_sha256: str, max_age_hours: int,
                      verification_staging: Path,
                      now: datetime | None = None) -> dict[str, object]:
    """Require a recent Sovereign snapshot and prove a clean private restore."""
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 168:
        raise ResticError("snapshot maximum age must be 1–168 hours")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ResticError("verification clock must have a timezone")
    current = current.astimezone(timezone.utc)
    if (verification_staging.is_symlink() or not verification_staging.is_dir()
            or stat.S_IMODE(verification_staging.stat().st_mode) & 0o077
            or verification_staging.resolve().is_relative_to(repository.resolve())
            or repository.resolve().is_relative_to(verification_staging.resolve())):
        raise ResticError("verification staging must be a separate owner-only directory")
    _preflight(restic, restic_sha256, repository, password_file)
    try:
        rows = json.loads(_run(restic, repository, password_file, "snapshots", "--json",
                               "--tag", SNAPSHOT_TAG, "--host", SNAPSHOT_HOST),
                          object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as exc:
        raise ResticError("invalid restic snapshot inventory") from exc
    if not isinstance(rows, list) or not rows:
        raise ResticError("no Sovereign snapshot available")
    seen: set[str] = set()
    latest: tuple[datetime, str] | None = None
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                or not _SNAPSHOT_ID.fullmatch(row["id"]) or row["id"] in seen
                or row.get("hostname") != SNAPSHOT_HOST
                or not isinstance(row.get("tags"), list)
                or SNAPSHOT_TAG not in row["tags"]
                or not isinstance(row.get("time"), str)):
            raise ResticError("invalid or out-of-scope snapshot")
        seen.add(row["id"])
        try:
            created = datetime.fromisoformat(row["time"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ResticError("invalid snapshot timestamp") from exc
        if created.tzinfo is None or created > current + timedelta(minutes=5):
            raise ResticError("snapshot timestamp is missing a zone or in the future")
        created = created.astimezone(timezone.utc)
        if latest is None or created > latest[0]:
            latest = (created, row["id"])
    if latest is None:
        raise ResticError("no Sovereign snapshot available")
    age = max(timedelta(), current - latest[0])
    if age > timedelta(hours=max_age_hours):
        raise ResticError("latest Sovereign snapshot is stale")
    with tempfile.TemporaryDirectory(prefix=".sovereign-verify-",
                                     dir=verification_staging) as temporary:
        restored = restore_snapshot(latest[1], repository, password_file, restic,
                                    restic_sha256, Path(temporary) / "restored")
    return {"status": "verified", "snapshot_count": len(rows),
            "latest_snapshot_id": latest[1], "age_seconds": int(age.total_seconds()),
            "max_age_hours": max_age_hours, "restored_files": restored["files"],
            "restic_version": RESTIC_VERSION}


def main() -> None:
    parser = argparse.ArgumentParser(description="Local encrypted restic snapshot adapter")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "restore", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--repository", required=True, type=Path)
        command.add_argument("--password-file", required=True, type=Path)
        command.add_argument("--restic", required=True, type=Path)
        command.add_argument("--restic-sha256", required=True)
        if name == "create":
            command.add_argument("--spec", required=True, type=Path)
            command.add_argument("--staging-parent", required=True, type=Path)
        elif name == "restore":
            command.add_argument("--snapshot-id", required=True)
            command.add_argument("--destination", required=True, type=Path)
        else:
            command.add_argument("--max-age-hours", required=True, type=int)
            command.add_argument("--verification-staging", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_snapshot(args.spec, args.repository, args.password_file,
                                     args.restic, args.restic_sha256, args.staging_parent)
        elif args.command == "restore":
            result = restore_snapshot(args.snapshot_id, args.repository, args.password_file,
                                      args.restic, args.restic_sha256, args.destination)
        else:
            result = verify_repository(args.repository, args.password_file,
                                       args.restic, args.restic_sha256, args.max_age_hours,
                                       args.verification_staging)
    except (ResticError, BackupError, OSError, ValueError) as exc:
        parser.exit(1, f"restic repository: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
