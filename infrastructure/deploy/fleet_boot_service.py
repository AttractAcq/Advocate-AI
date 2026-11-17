"""Render a synthetic Fleet boot recovery unit for an installed signed release."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from infrastructure.deploy.boot_service import BootServiceError, _path


def render_fleet_recovery_unit(root: Path, trusted_key: Path, crane: Path,
                               python: Path, workdir: Path) -> str:
    """Recover the signed Fleet runtime, then require its health probe to pass."""
    install, trusted, crane_bin, executable, working = (
        _path(path) for path in (root, trusted_key, crane, python, workdir))
    if len({install, trusted, crane_bin, executable, working}) != 5:
        raise BootServiceError("Fleet recovery paths must be distinct")
    return (
        "[Unit]\n"
        "Description=Sovereign synthetic Fleet boot recovery\n"
        "Requires=docker.service\nAfter=docker.service\n"
        f"ConditionPathExists={install}/fleet-state.json\n"
        "\n[Service]\nType=oneshot\n"
        "User=sovereign-fleet\nGroup=sovereign-fleet\n"
        f"WorkingDirectory={working}\n"
        "UMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
        "ProtectSystem=strict\nProtectKernelTunables=yes\n"
        "ProtectControlGroups=yes\n"
        f"ReadWritePaths={install}\n"
        "TimeoutStartSec=15min\n"
        f"ExecStart={executable} -m infrastructure.deploy.fleet_installer recover "
        f"--root {install} --trusted-key {trusted} --crane {crane_bin}\n"
        f"ExecStart={executable} -m infrastructure.deploy.fleet_installer status "
        f"--root {install} --trusted-key {trusted}\n"
        "\n[Install]\nWantedBy=multi-user.target\n"
    )


def write_fleet_recovery_unit(output: Path, root: Path, trusted_key: Path,
                              crane: Path, python: Path, workdir: Path) -> None:
    unit = render_fleet_recovery_unit(root, trusted_key, crane, python, workdir)
    if (output.name != "sovereign-fleet-recover.service" or output.is_symlink() or
            output.exists() or not output.parent.is_dir()):
        raise BootServiceError("Fleet recovery unit must be a new named file")
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
    parser = argparse.ArgumentParser(description="Render synthetic Fleet boot recovery")
    for field in ("output", "root", "trusted-key", "crane", "python", "workdir"):
        parser.add_argument("--" + field, required=True, type=Path)
    args = parser.parse_args()
    try:
        write_fleet_recovery_unit(args.output, args.root, args.trusted_key,
                                  args.crane, args.python, args.workdir)
    except (BootServiceError, OSError) as exc:
        parser.exit(1, f"fleet-boot-service: {exc}\n")


if __name__ == "__main__":
    main()
