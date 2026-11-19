"""Synthetic encrypted restic backup of the isolated upload quarantine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from infrastructure.restic_repository import MANIFEST, create_snapshot, restore_snapshot
from services.knowledge.ingestion import MAX_BYTES
from services.knowledge.upload_staging import MAX_PENDING, quarantine_directory_lock

_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_RECORDS = 1024
MAX_TOTAL = 900 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 2 * 1024 * 1024
FREE_SPACE_RESERVE = 128 * 1024 * 1024
ARCHIVE = "upload-quarantine.zip"
INVENTORY = "inventory.json"


class UploadBackupError(ValueError):
    """Quarantine backup or restore failed validation."""


def _private_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise UploadBackupError("quarantine must be an owner-only absolute directory")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scan_inventory(root: Path) -> list[dict[str, object]]:
    _private_directory(root)
    names = sorted(os.listdir(root))
    if len(names) > MAX_RECORDS * 2:
        raise UploadBackupError("quarantine file limit exceeded")
    metadata: dict[str, bytes] = {}
    sizes: dict[str, int] = {}
    digests: dict[str, str] = {}
    total = 0
    for name in names:
        match = re.fullmatch(r"([0-9a-f]{32})\.(json|blob)", name)
        if not match:
            raise UploadBackupError("unexpected quarantine entry")
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_size > (2048 if match[2] == "json" else MAX_BYTES)):
                raise UploadBackupError("unsafe quarantine file")
            total += info.st_size
            if total > MAX_TOTAL:
                raise UploadBackupError("quarantine size limit exceeded")
            checksum = hashlib.sha256()
            read_size = 0
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                if match[2] == "json":
                    content = stream.read(info.st_size + 1)
                    checksum.update(content)
                    read_size = len(content)
                    metadata[name] = content
                else:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        checksum.update(block)
                        read_size += len(block)
            if read_size != info.st_size:
                raise UploadBackupError("quarantine file changed during snapshot")
            sizes[name] = info.st_size
            digests[name] = checksum.hexdigest()
        finally:
            os.close(descriptor)
    metadata_names = [name for name in names if name.endswith(".json")]
    if len(metadata_names) > MAX_RECORDS:
        raise UploadBackupError("quarantine record limit exceeded")
    pending = 0
    for name in metadata_names:
        identifier = name[:-5]
        try:
            record = json.loads(metadata[name])
        except (ValueError, UnicodeError) as exc:
            raise UploadBackupError("invalid quarantine metadata") from exc
        if (not isinstance(record, dict) or record.get("id") != identifier
                or record.get("status") not in {"pending", "approved"}
                or not isinstance(record.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                or type(record.get("size")) is not int or record["size"] < 1):
            raise UploadBackupError("invalid quarantine record")
        blob = f"{identifier}.blob"
        if record["status"] == "pending":
            pending += 1
            if (blob not in sizes or sizes[blob] != record["size"]
                    or digests[blob] != record["sha256"]):
                raise UploadBackupError("pending upload bytes do not match metadata")
        elif blob in sizes:
            raise UploadBackupError("approved upload retains quarantine bytes")
    if pending > MAX_PENDING or any(name.endswith(".blob") and f"{name[:-5]}.json" not in sizes
                                    for name in names):
        raise UploadBackupError("orphan or excessive pending upload")
    return [{"name": name, "size": sizes[name], "sha256": digests[name]}
            for name in names]


def _read_inventory(root: Path) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    """Small fixture helper; the backup path uses the streaming scan above."""
    rows = _scan_inventory(root)
    return {row["name"]: (root / row["name"]).read_bytes() for row in rows}, rows


def _write_archive(archive: Path, files: dict[str, bytes], rows: list[dict[str, object]]) -> None:
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_STORED,
                         allowZip64=True) as output:
        output.writestr(INVENTORY, json.dumps({"schema": 1, "files": rows},
                                              sort_keys=True))
        for name, content in files.items():
            output.writestr(name, content)
    archive.chmod(0o600)


def _write_archive_from_root(archive: Path, root: Path,
                             rows: list[dict[str, object]]) -> None:
    """Copy checked files into a ZIP without buffering upload blobs in memory."""
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_STORED,
                         allowZip64=True) as output:
        output.writestr(INVENTORY, json.dumps({"schema": 1, "files": rows},
                                              sort_keys=True))
        for row in rows:
            descriptor = os.open(root / row["name"], os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077
                        or info.st_size != row["size"]):
                    raise UploadBackupError("quarantine file changed during snapshot")
                checksum = hashlib.sha256()
                copied = 0
                with os.fdopen(descriptor, "rb", closefd=False) as source:
                    with output.open(row["name"], "w", force_zip64=True) as target:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            checksum.update(block)
                            copied += len(block)
                            if copied > row["size"]:
                                raise UploadBackupError("quarantine file grew during snapshot")
                            target.write(block)
                if copied != row["size"] or checksum.hexdigest() != row["sha256"]:
                    raise UploadBackupError("quarantine file changed during snapshot")
            finally:
                os.close(descriptor)
    archive.chmod(0o600)
    if archive.stat().st_size > MAX_ARCHIVE:
        raise UploadBackupError("quarantine archive exceeds synthetic size limit")


def _check_backup_space(rows: list[dict[str, object]], staging_parent: Path,
                        repository: Path) -> None:
    """Reserve room for the private archive, restic copy and encrypted pack."""
    if not repository.is_absolute() or repository.is_symlink():
        raise UploadBackupError("repository must be an unlinked absolute path")
    repository_volume = repository if repository.exists() else repository.parent
    if repository_volume.is_symlink() or not repository_volume.is_dir():
        raise UploadBackupError("repository parent is missing or linked")
    estimated_archive = sum(int(row["size"]) for row in rows) + 2 * 1024 * 1024
    if estimated_archive > MAX_ARCHIVE:
        raise UploadBackupError("quarantine archive exceeds synthetic size limit")
    staging_need = estimated_archive * 2 + FREE_SPACE_RESERVE
    repository_need = estimated_archive + FREE_SPACE_RESERVE
    if _device(staging_parent) == _device(repository_volume):
        if shutil.disk_usage(staging_parent).free < staging_need + estimated_archive:
            raise UploadBackupError("insufficient space for encrypted quarantine snapshot")
    elif (shutil.disk_usage(staging_parent).free < staging_need or
          shutil.disk_usage(repository_volume).free < repository_need):
        raise UploadBackupError("insufficient space for encrypted quarantine snapshot")


def _device(path: Path) -> int:
    return path.stat().st_dev


def _extract_archive(archive: Path, destination: Path) -> int:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise UploadBackupError("restore needs a new destination")
    if archive.is_symlink() or archive.stat().st_size > MAX_ARCHIVE:
        raise UploadBackupError("quarantine archive exceeds synthetic size limit")
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or INVENTORY not in names or len(names) > MAX_RECORDS * 2 + 1:
            raise UploadBackupError("invalid quarantine archive inventory")
        if any(entry.compress_type != zipfile.ZIP_STORED or entry.is_dir()
               or stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK
               for entry in entries):
            raise UploadBackupError("unsupported quarantine archive entry")
        try:
            if source.getinfo(INVENTORY).file_size > 256 * 1024:
                raise UploadBackupError("quarantine inventory too large")
            manifest = json.loads(source.read(INVENTORY))
        except (ValueError, UnicodeError) as exc:
            raise UploadBackupError("invalid quarantine inventory") from exc
        if (not isinstance(manifest, dict) or set(manifest) != {"schema", "files"}
                or manifest["schema"] != 1 or not isinstance(manifest["files"], list)):
            raise UploadBackupError("invalid quarantine inventory")
        rows = manifest["files"]
        if names != [INVENTORY] + [row.get("name") for row in rows if isinstance(row, dict)]:
            raise UploadBackupError("archive entries differ from inventory")
        with tempfile.TemporaryDirectory(prefix=".upload-restore-", dir=destination.parent) as temporary:
            stage = Path(temporary) / "quarantine"
            stage.mkdir(mode=0o700)
            total = 0
            for row in rows:
                if (not isinstance(row, dict) or set(row) != {"name", "size", "sha256"}
                        or not isinstance(row["name"], str)
                        or not re.fullmatch(r"[0-9a-f]{32}\.(json|blob)", row["name"])
                        or type(row["size"]) is not int or row["size"] < 0
                        or row["size"] > (2048 if row["name"].endswith(".json") else MAX_BYTES)
                        or not isinstance(row["sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
                    raise UploadBackupError("invalid quarantine file record")
                total += row["size"]
                if total > MAX_TOTAL or source.getinfo(row["name"]).file_size != row["size"]:
                    raise UploadBackupError("quarantine size limit exceeded")
                target = stage / row["name"]
                checksum = hashlib.sha256()
                copied = 0
                with source.open(row["name"]) as input_stream, target.open("xb") as output_stream:
                    for block in iter(lambda: input_stream.read(1024 * 1024), b""):
                        checksum.update(block)
                        copied += len(block)
                        if copied > row["size"]:
                            raise UploadBackupError("quarantine file grew during restore")
                        output_stream.write(block)
                if copied != row["size"] or checksum.hexdigest() != row["sha256"]:
                    raise UploadBackupError("quarantine file changed")
                target.chmod(0o600)
            _scan_inventory(stage)
            shutil.move(stage, destination)
    return len(rows)


def create_upload_snapshot(upload_root: Path, repository: Path, password_file: Path,
                           restic: Path, restic_sha256: str, staging_parent: Path) -> dict[str, object]:
    """Snapshot a stopped synthetic Core's private upload area into restic."""
    _private_directory(staging_parent)
    if upload_root.resolve() == staging_parent.resolve():
        raise UploadBackupError("staging and quarantine must be separate")
    with tempfile.TemporaryDirectory(prefix=".upload-backup-", dir=staging_parent) as temporary:
        stage = Path(temporary)
        archive = stage / ARCHIVE
        with quarantine_directory_lock(upload_root, exclusive=False):
            rows = _scan_inventory(upload_root)
            _check_backup_space(rows, staging_parent, repository)
            _write_archive_from_root(archive, upload_root, rows)
        spec = stage / "spec.json"
        spec.write_text(json.dumps({"schema": 1, "files": [
            {"name": ARCHIVE, "kind": "file", "source": ARCHIVE}]}))
        result = create_snapshot(spec, repository, password_file, restic,
                                 restic_sha256, staging_parent,
                                 max_file=MAX_ARCHIVE)
    return {**result, "quarantine_files": len(rows)}


def restore_upload_snapshot(snapshot_id: str, repository: Path, password_file: Path,
                            restic: Path, restic_sha256: str, destination: Path) -> dict[str, object]:
    """Restore an exact encrypted snapshot to a new private directory."""
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise UploadBackupError("restore needs a new destination")
    _private_directory(destination.parent)
    with tempfile.TemporaryDirectory(prefix=".upload-restic-", dir=destination.parent) as temporary:
        restored = Path(temporary) / "restored"
        result = restore_snapshot(snapshot_id, repository, password_file, restic,
                                  restic_sha256, restored)
        if set(os.listdir(restored)) != {ARCHIVE, MANIFEST} or result["files"] != 1:
            raise UploadBackupError("not an upload quarantine snapshot")
        count = _extract_archive(restored / ARCHIVE, destination)
    return {"status": "restored", "snapshot_id": snapshot_id, "quarantine_files": count}


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic upload quarantine restic backup")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--repository", required=True, type=Path)
        command.add_argument("--password-file", required=True, type=Path)
        command.add_argument("--restic", required=True, type=Path)
        command.add_argument("--restic-sha256", required=True)
        if name == "create":
            command.add_argument("--upload-root", required=True, type=Path)
            command.add_argument("--staging-parent", required=True, type=Path)
        else:
            command.add_argument("--snapshot-id", required=True)
            command.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_upload_snapshot(args.upload_root, args.repository,
                args.password_file, args.restic, args.restic_sha256, args.staging_parent)
        else:
            result = restore_upload_snapshot(args.snapshot_id, args.repository,
                args.password_file, args.restic, args.restic_sha256, args.destination)
    except (UploadBackupError, OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"upload quarantine backup: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
