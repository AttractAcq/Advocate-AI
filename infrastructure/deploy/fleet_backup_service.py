"""Synthetic Fleet daily encrypted backup, clean verification and unit rendering."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from infrastructure.backup import BackupError
from infrastructure.deploy.boot_service import BootServiceError, _path
from infrastructure.deploy.fleet_backup import (
    FleetBackupError, _owner_directory, _owner_file, backup_fleet, restore_fleet,
)
from services.fleet.catalog import FleetError


class FleetScheduleError(ValueError):
    """The scheduled Fleet backup or its verification cannot safely proceed."""


_ARCHIVE = re.compile(r"fleet-[0-9]{8}T[0-9]{6}-[0-9]{6}Z\.svb\Z")


@contextmanager
def _backup_lock(directory: Path, *, exclusive: bool):
    _owner_directory(directory)
    descriptor = os.open(directory / ".fleet-backup.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or
                details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) & 0o077):
            raise FleetScheduleError("Fleet backup lock must be owner-only")
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(descriptor)


def _archives(directory: Path, max_archives: int) -> list[Path]:
    _owner_directory(directory)
    if type(max_archives) is not int or not 1 <= max_archives <= 10000:
        raise FleetScheduleError("invalid archive capacity")
    archives = [path for path in directory.iterdir() if _ARCHIVE.fullmatch(path.name)]
    if len(archives) > max_archives:
        raise FleetScheduleError("archive capacity exceeded; review retention")
    for path in archives:
        _owner_file(path)
    return sorted(archives)


def create_scheduled(db: Path, directory: Path, key: Path,
                     max_archives: int) -> dict[str, object]:
    """Write one unique archive; stop before filling an unapproved retention set."""
    with _backup_lock(directory, exclusive=True):
        archives = _archives(directory, max_archives)
        if len(archives) >= max_archives:
            raise FleetScheduleError("archive capacity reached; review retention")
        name = datetime.now(timezone.utc).strftime("fleet-%Y%m%dT%H%M%S-%fZ.svb")
        return backup_fleet(db, directory / name, key)


def verify_latest(directory: Path, key: Path, max_age_hours: int,
                  max_archives: int) -> dict[str, object]:
    """Authenticate and clean-restore the newest archive, then check age."""
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 720:
        raise FleetScheduleError("invalid maximum backup age")
    with _backup_lock(directory, exclusive=False):
        archives = _archives(directory, max_archives)
        _owner_file(key)
        if not archives:
            raise FleetScheduleError("no Fleet backup archives")
        latest = archives[-1]
        stage = Path(tempfile.mkdtemp(prefix=".fleet-verify-", dir=directory))
        try:
            result = restore_fleet(latest, key, stage / "restored")
            created = datetime.fromisoformat(str(result["created_utc"]))
            if created.tzinfo is None:
                raise FleetScheduleError("backup timestamp has no timezone")
            age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
            if age < -300 or age > max_age_hours * 3600:
                raise FleetScheduleError("latest Fleet backup is outside freshness limit")
            return {"archive": str(latest), "created_utc": result["created_utc"],
                    "archive_count": len(archives), "clean_restore": "verified"}
        finally:
            shutil.rmtree(stage)


def render_fleet_backup_units(db: Path, directory: Path, key: Path,
                              python: Path, workdir: Path, hour_utc: int,
                              max_age_hours: int, max_archives: int) -> tuple[str, str]:
    try:
        database, archive_dir, secret, executable, working = (
            _path(path) for path in (db, directory, key, python, workdir))
    except BootServiceError as exc:
        raise FleetScheduleError(str(exc)) from exc
    if (len({database, archive_dir, secret, executable, working}) != 5 or
            Path(secret).is_relative_to(archive_dir) or
            Path(database).is_relative_to(archive_dir) or
            type(hour_utc) is not int or not 0 <= hour_utc <= 23 or
            type(max_age_hours) is not int or not 1 <= max_age_hours <= 720 or
            type(max_archives) is not int or not 1 <= max_archives <= 10000):
        raise FleetScheduleError("invalid Fleet backup paths or schedule")
    command = "infrastructure.deploy.fleet_backup_service"
    credential = "${CREDENTIALS_DIRECTORY}/fleet-backup-key"
    service = (
        "[Unit]\nDescription=Sovereign synthetic Fleet encrypted backup and verification\n"
        f"RequiresMountsFor={archive_dir}\nAfter=local-fs.target\n\n[Service]\n"
        "Type=oneshot\nUser=sovereign-fleet\nGroup=sovereign-fleet\n"
        f"WorkingDirectory={working}\nUMask=0077\nNoNewPrivileges=yes\n"
        "PrivateNetwork=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
        "ProtectKernelTunables=yes\nProtectControlGroups=yes\n"
        f"ReadWritePaths={archive_dir}\nLoadCredential=fleet-backup-key:{secret}\n"
        "TimeoutStartSec=30min\n"
        f"ExecStart={executable} -m {command} create --db {database} "
        f"--directory {archive_dir} --key {credential} --max-archives {max_archives}\n"
        f"ExecStart={executable} -m {command} verify --directory {archive_dir} "
        f"--key {credential} --max-age-hours {max_age_hours} "
        f"--max-archives {max_archives}\n"
    )
    timer = (
        "[Unit]\nDescription=Schedule Sovereign synthetic Fleet backup\n"
        f"\n[Timer]\nOnCalendar=*-*-* {hour_utc:02d}:00:00 UTC\n"
        "Persistent=true\nAccuracySec=5min\nUnit=sovereign-fleet-backup.service\n"
        "\n[Install]\nWantedBy=timers.target\n"
    )
    return service, timer


def write_fleet_backup_units(service_output: Path, timer_output: Path,
                             *args: object) -> None:
    service, timer = render_fleet_backup_units(*args)
    if (service_output.name != "sovereign-fleet-backup.service" or
            timer_output.name != "sovereign-fleet-backup.timer" or
            service_output == timer_output or
            any(path.exists() or path.is_symlink() or not path.parent.is_dir()
                for path in (service_output, timer_output))):
        raise FleetScheduleError("unit destinations must be distinct new files")
    created: list[Path] = []
    try:
        for path, content in ((service_output, service), (timer_output, timer)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic Fleet backup schedule")
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create")
    create.add_argument("--db", required=True, type=Path)
    create.add_argument("--directory", required=True, type=Path)
    create.add_argument("--key", required=True, type=Path)
    create.add_argument("--max-archives", required=True, type=int)
    verify = actions.add_parser("verify")
    verify.add_argument("--directory", required=True, type=Path)
    verify.add_argument("--key", required=True, type=Path)
    verify.add_argument("--max-age-hours", required=True, type=int)
    verify.add_argument("--max-archives", required=True, type=int)
    render = actions.add_parser("render")
    for field in ("service-output", "timer-output", "db", "directory",
                  "key", "python", "workdir"):
        render.add_argument("--" + field, required=True, type=Path)
    for field in ("hour-utc", "max-age-hours", "max-archives"):
        render.add_argument("--" + field, required=True, type=int)
    args = parser.parse_args()
    try:
        if args.action == "create":
            result = create_scheduled(args.db, args.directory, args.key,
                                      args.max_archives)
        elif args.action == "verify":
            result = verify_latest(args.directory, args.key, args.max_age_hours,
                                   args.max_archives)
        else:
            write_fleet_backup_units(args.service_output, args.timer_output,
                                     args.db, args.directory, args.key, args.python,
                                     args.workdir, args.hour_utc, args.max_age_hours,
                                     args.max_archives)
            result = {"service": str(args.service_output),
                      "timer": str(args.timer_output)}
    except (BackupError, FleetBackupError, FleetError, FleetScheduleError,
            OSError, ValueError) as exc:
        parser.exit(1, f"fleet-backup-service: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
