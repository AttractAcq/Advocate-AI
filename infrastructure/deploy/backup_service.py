"""Render a synthetic daily restic backup and verification systemd pair.

Rendering does not install, enable, or start either unit.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re

from infrastructure.deploy.boot_service import BootServiceError, _path


class BackupServiceError(ValueError):
    """The backup schedule or unit destination is invalid."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def render_backup_units(spec: Path, repository: Path, password_source: Path,
                        restic: Path, restic_sha256: str, python: Path,
                        workdir: Path, staging: Path, hour_utc: int,
                        max_age_hours: int) -> tuple[str, str]:
    """Return a one-shot backup/check service and its daily UTC timer."""
    try:
        paths = [_path(item) for item in (spec, repository, password_source,
                                          restic, python, workdir, staging)]
    except BootServiceError as exc:
        raise BackupServiceError(str(exc)) from exc
    if (len(set(paths)) != len(paths) or not _DIGEST.fullmatch(restic_sha256)
            or type(hour_utc) is not int or not 0 <= hour_utc <= 23
            or type(max_age_hours) is not int or not 1 <= max_age_hours <= 168):
        raise BackupServiceError("invalid backup paths, tool digest or schedule")
    spec_path, repo, secret, tool, executable, working, stage = paths
    if (Path(secret).is_relative_to(repo) or Path(secret).is_relative_to(stage)
            or Path(repo).is_relative_to(stage) or Path(stage).is_relative_to(repo)):
        raise BackupServiceError("secret, repository and staging paths must be separate")
    shared = (f"--repository {repo} --password-file "
              "${CREDENTIALS_DIRECTORY}/restic-password "
              f"--restic {tool} --restic-sha256 {restic_sha256}")
    service = (
        "[Unit]\n"
        "Description=Sovereign synthetic encrypted backup and verification\n"
        "After=local-fs.target\n"
        f"RequiresMountsFor={repo} {stage}\n"
        "\n[Service]\n"
        "Type=oneshot\n"
        "User=sovereign-backup\n"
        "Group=sovereign-backup\n"
        f"WorkingDirectory={working}\n"
        "UMask=0077\n"
        "NoNewPrivileges=yes\n"
        "PrivateNetwork=yes\n"
        "PrivateTmp=yes\n"
        "ProtectSystem=strict\n"
        "ProtectKernelTunables=yes\n"
        "ProtectControlGroups=yes\n"
        f"ReadWritePaths={repo} {stage}\n"
        f"LoadCredential=restic-password:{secret}\n"
        "TimeoutStartSec=30min\n"
        f"ExecStart={executable} -m infrastructure.restic_repository create "
        f"--spec {spec_path} {shared} --staging-parent {stage}\n"
        f"ExecStart={executable} -m infrastructure.restic_repository verify "
        f"{shared} --max-age-hours {max_age_hours} --verification-staging {stage}\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Schedule Sovereign synthetic encrypted backup\n"
        "\n[Timer]\n"
        f"OnCalendar=*-*-* {hour_utc:02d}:00:00 UTC\n"
        "Persistent=true\n"
        "AccuracySec=5min\n"
        "Unit=sovereign-backup.service\n"
        "\n[Install]\n"
        "WantedBy=timers.target\n"
    )
    return service, timer


def write_backup_units(service_output: Path, timer_output: Path, *args: object) -> None:
    """Write both owner-only candidate units, removing partial output on error."""
    service, timer = render_backup_units(*args)
    if (service_output == timer_output or service_output.exists() or service_output.is_symlink()
            or timer_output.exists() or timer_output.is_symlink()
            or not service_output.parent.is_dir() or not timer_output.parent.is_dir()):
        raise BackupServiceError("unit destinations must be distinct new files")
    created: list[Path] = []
    try:
        for output, content in ((service_output, service), (timer_output, timer)):
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            created.append(output)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except Exception:
        for output in created:
            output.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Render synthetic backup timer units")
    for key in ("service-output", "timer-output", "spec", "repository",
                "password-source", "restic", "python", "workdir", "staging"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--restic-sha256", required=True)
    parser.add_argument("--hour-utc", required=True, type=int)
    parser.add_argument("--max-age-hours", required=True, type=int)
    args = parser.parse_args()
    try:
        write_backup_units(args.service_output, args.timer_output, args.spec,
                           args.repository, args.password_source, args.restic,
                           args.restic_sha256, args.python, args.workdir,
                           args.staging, args.hour_utc, args.max_age_hours)
    except (BackupServiceError, OSError) as exc:
        parser.exit(1, f"backup-service: {exc}\n")


if __name__ == "__main__":
    main()
