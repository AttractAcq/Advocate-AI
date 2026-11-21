"""Render a boot-only recovery unit for an installed synthetic vessel release."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re

from infrastructure.deploy.boot_service import BootServiceError, _path


_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


def render_vessel_recovery_unit(root: Path, core_state: Path,
                                trusted_key: Path, crane: Path, python: Path,
                                workdir: Path, user: str, group: str) -> str:
    """Finish a checked stop, recover the signed release, then require health."""
    install, state, trusted, crane_bin, executable, working = (
        _path(path) for path in (root, core_state, trusted_key, crane, python, workdir))
    if (len({install, state, trusted, crane_bin, executable, working}) != 6 or
            Path(state).is_relative_to(install) or
            not _ACCOUNT.fullmatch(user) or not _ACCOUNT.fullmatch(group) or
            user == "root" or group == "root"):
        raise BootServiceError("vessel boot paths and service account must be distinct")
    command = (f"{executable} -m scripts.vesselctl {{action}} "
               f"--root {install} --trusted-key {trusted} --crane {crane_bin}")
    return (
        "[Unit]\n"
        "Description=Sovereign synthetic vessel boot recovery\n"
        "Requires=docker.service\nAfter=docker.service\n"
        f"ConditionPathExists={install}/vessel-state.json\n"
        "\n[Service]\nType=oneshot\n"
        f"User={user}\nGroup={group}\n"
        f"WorkingDirectory={working}\n"
        "UMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
        "ProtectSystem=strict\nProtectKernelTunables=yes\n"
        "ProtectControlGroups=yes\n"
        f"ReadWritePaths={install} {state}\n"
        "TimeoutStartSec=30min\n"
        f"ExecStartPre={command.format(action='finish-stop')}\n"
        f"ExecStart={command.format(action='recover')}\n"
        f"ExecStartPost={command.format(action='status')}\n"
        "\n[Install]\nWantedBy=multi-user.target\n"
    )


def write_vessel_recovery_unit(output: Path, root: Path, core_state: Path,
                               trusted_key: Path, crane: Path, python: Path,
                               workdir: Path, user: str, group: str) -> None:
    unit = render_vessel_recovery_unit(root, core_state, trusted_key, crane,
                                       python, workdir, user, group)
    if (output.name != "sovereign-vessel-recover.service" or output.is_symlink() or
            output.exists() or not output.parent.is_dir()):
        raise BootServiceError("vessel recovery unit must be a new named file")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(unit)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        output.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Render synthetic vessel boot recovery")
    for field in ("output", "root", "core-state", "trusted-key", "crane", "python", "workdir"):
        parser.add_argument("--" + field, required=True, type=Path)
    for field in ("user", "group"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    try:
        write_vessel_recovery_unit(args.output, args.root, args.core_state,
                                   args.trusted_key, args.crane, args.python,
                                   args.workdir, args.user, args.group)
    except (BootServiceError, OSError) as exc:
        parser.exit(1, f"vessel-boot-service: {exc}\n")


if __name__ == "__main__":
    main()
