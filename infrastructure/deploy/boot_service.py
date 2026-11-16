"""Render a site-specific systemd boot recovery unit for the synthetic product.

Rendering does not install, enable or start the unit.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re


class BootServiceError(ValueError):
    """A service path or destination is unsafe or ambiguous."""


_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


def _path(value: Path) -> str:
    name = str(value)
    if (not _PATH.fullmatch(name) or ".." in value.parts or "." in value.parts
            or "//" in name or name.endswith("/")):
        raise BootServiceError("service paths must be unambiguous absolute paths")
    return name


def render_recovery_unit(root: Path, trusted_key: Path, crane: Path,
                         python: Path, workdir: Path) -> str:
    """Return a boot-only recovery unit bound to an installed lab release."""
    install = _path(root)
    trusted = _path(trusted_key)
    crane_bin = _path(crane)
    python_bin = _path(python)
    working = _path(workdir)
    if len({install, trusted, crane_bin, python_bin, working}) != 5:
        raise BootServiceError("service paths must be distinct")
    return (
        "[Unit]\n"
        "Description=Sovereign synthetic product boot recovery\n"
        "Requires=docker.service\n"
        "After=docker.service\n"
        f"ConditionPathExists={install}/product-state.json\n"
        "\n[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={working}\n"
        "UMask=0077\n"
        "NoNewPrivileges=yes\n"
        "ProtectSystem=strict\n"
        f"ReadWritePaths={install}\n"
        "TimeoutStartSec=15min\n"
        f"ExecStart={python_bin} -m infrastructure.deploy.product_installer recover "
        f"--root {install} --trusted-key {trusted} --crane {crane_bin}\n"
        "\n[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def write_recovery_unit(output: Path, root: Path, trusted_key: Path,
                        crane: Path, python: Path, workdir: Path) -> None:
    unit = render_recovery_unit(root, trusted_key, crane, python, workdir)
    if output.is_symlink() or output.exists():
        raise BootServiceError("unit destination must be new")
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
    parser = argparse.ArgumentParser(description="Render a synthetic boot recovery unit")
    for key in ("output", "root", "trusted-key", "crane", "python", "workdir"):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    try:
        write_recovery_unit(args.output, args.root, args.trusted_key,
                            args.crane, args.python, args.workdir)
    except (BootServiceError, OSError) as exc:
        parser.exit(1, f"boot-service: {exc}\n")


if __name__ == "__main__":
    main()
