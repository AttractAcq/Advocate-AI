"""Operator entry point for signed synthetic vessel installation and recovery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from infrastructure.deploy.vessel_installer import (
    finish_vessel_stop, install_vessel, reconcile_first_install,
    reconcile_vessel, recover_vessel, reset_first_install,
    resume_first_install, status_vessel, stop_vessel,
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--root", type=Path, required=True)
    shared.add_argument("--trusted-key", type=Path, required=True)
    shared.add_argument("--crane", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install", parents=[shared])
    install.add_argument("--bundle", type=Path, required=True)
    install.add_argument("--console-config", type=Path, required=True)
    install.add_argument("--core-state", type=Path, required=True)
    install.add_argument("--lab-password-file", type=Path, required=True)
    for command in ("status", "stop", "finish-stop", "reconcile", "recover",
                    "reconcile-install", "resume-install"):
        commands.add_parser(command, parents=[shared])
    reset = commands.add_parser("reset-bootstrap", parents=[shared])
    reset.add_argument("--discard-data", action="store_true", required=True)
    args = parser.parse_args(argv)
    if args.command == "install":
        result = install_vessel(args.bundle, args.trusted_key, args.crane,
                                args.console_config, args.root, args.core_state,
                                args.lab_password_file)
    elif args.command == "status":
        result = status_vessel(args.root, args.trusted_key, args.crane)
    elif args.command == "stop":
        result = stop_vessel(args.root, args.trusted_key, args.crane)
    elif args.command == "finish-stop":
        result = finish_vessel_stop(args.root, args.trusted_key, args.crane)
    elif args.command == "reconcile":
        result = reconcile_vessel(args.root, args.trusted_key, args.crane)
    elif args.command == "reconcile-install":
        result = reconcile_first_install(args.root, args.trusted_key, args.crane)
    elif args.command == "resume-install":
        result = resume_first_install(args.root, args.trusted_key, args.crane)
    elif args.command == "reset-bootstrap":
        result = reset_first_install(args.root, args.trusted_key, args.crane)
    else:
        result = recover_vessel(args.root, args.trusted_key, args.crane)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
