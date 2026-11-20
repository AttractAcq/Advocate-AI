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
from infrastructure.deploy.vessel_recovery_set import (
    abandon_incomplete_vessel_restore, activate_vessel_recovery_set,
    create_vessel_recovery_set, restore_vessel_recovery_files,
    retry_abandoned_vessel_restore,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_release_switch import (
    discard_stopped_vessel_stage, rollback_stopped_vessel_release,
    switch_stopped_vessel_release,
)
from infrastructure.deploy.vessel_history_migration import (
    migrate_stopped_vessel_history, verify_vessel_history_migration_receipt,
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
    switch = commands.add_parser("switch-stopped", parents=[shared])
    switch.add_argument("--bundle", type=Path, required=True)
    switch.add_argument("--console-config", type=Path, required=True)
    commands.add_parser("rollback-stopped", parents=[shared])
    discard_stage = commands.add_parser("discard-staged-candidate")
    discard_stage.add_argument("--root", type=Path, required=True)
    discard_stage.add_argument("--trusted-key", type=Path, required=True)
    discard_stage.add_argument("--bundle", type=Path, required=True)
    discard_stage.add_argument("--console-config", type=Path, required=True)
    discard_stage.add_argument("--discard-stage", action="store_true", required=True)
    reset = commands.add_parser("reset-bootstrap", parents=[shared])
    reset.add_argument("--discard-data", action="store_true", required=True)
    capture = commands.add_parser("capture-recovery-set", parents=[shared])
    capture.add_argument("--repository", type=Path, required=True)
    capture.add_argument("--password-file", type=Path, required=True)
    capture.add_argument("--restic", type=Path, required=True)
    capture.add_argument("--restic-sha256", required=True)
    capture.add_argument("--staging-parent", type=Path, required=True)
    capture.add_argument("--receipt-signing-key", type=Path, required=True)
    capture.add_argument("--receipt", type=Path, required=True)
    migrate_history = commands.add_parser("migrate-history-stopped", parents=[shared])
    migrate_history.add_argument("--repository", type=Path, required=True)
    migrate_history.add_argument("--password-file", type=Path, required=True)
    migrate_history.add_argument("--restic", type=Path, required=True)
    migrate_history.add_argument("--restic-sha256", required=True)
    migrate_history.add_argument("--staging-parent", type=Path, required=True)
    migrate_history.add_argument("--evidence", type=Path, required=True)
    migrate_history.add_argument("--receipt-signing-key", type=Path, required=True)
    migrate_history.add_argument("--receipt", type=Path, required=True)
    verify_history = commands.add_parser("verify-history-migration-receipt")
    verify_history.add_argument("--receipt", type=Path, required=True)
    verify_history.add_argument("--receipt-key", type=Path, required=True)
    verify = commands.add_parser("verify-recovery-receipt")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--receipt-key", type=Path, required=True)
    restore = commands.add_parser("restore-recovery-files")
    restore.add_argument("--receipt", type=Path, required=True)
    restore.add_argument("--receipt-key", type=Path, required=True)
    restore.add_argument("--password-file", type=Path, required=True)
    restore.add_argument("--restic", type=Path, required=True)
    restore.add_argument("--restic-sha256", required=True)
    restore.add_argument("--destination", type=Path, required=True)
    activate = commands.add_parser("activate-recovery-set")
    activate.add_argument("--bundle", type=Path, required=True)
    activate.add_argument("--trusted-key", type=Path, required=True)
    activate.add_argument("--crane", type=Path, required=True)
    activate.add_argument("--console-config", type=Path, required=True)
    activate.add_argument("--receipt", type=Path, required=True)
    activate.add_argument("--receipt-key", type=Path, required=True)
    activate.add_argument("--password-file", type=Path, required=True)
    activate.add_argument("--restic", type=Path, required=True)
    activate.add_argument("--restic-sha256", required=True)
    activate.add_argument("--root", type=Path, required=True)
    activate.add_argument("--core-state", type=Path, required=True)
    activate.add_argument("--lab-password-file", type=Path, required=True)
    activate.add_argument("--staging-parent", type=Path, required=True)
    abandon = commands.add_parser("abandon-incomplete-restore")
    abandon.add_argument("--root", type=Path, required=True)
    abandon.add_argument("--trusted-key", type=Path, required=True)
    abandon.add_argument("--receipt", type=Path, required=True)
    abandon.add_argument("--receipt-key", type=Path, required=True)
    abandon.add_argument("--discard-partial-data", action="store_true", required=True)
    retry = commands.add_parser("retry-abandoned-restore")
    retry.add_argument("--abandoned-root", type=Path, required=True)
    retry.add_argument("--bundle", type=Path, required=True)
    retry.add_argument("--trusted-key", type=Path, required=True)
    retry.add_argument("--crane", type=Path, required=True)
    retry.add_argument("--console-config", type=Path, required=True)
    retry.add_argument("--receipt", type=Path, required=True)
    retry.add_argument("--receipt-key", type=Path, required=True)
    retry.add_argument("--password-file", type=Path, required=True)
    retry.add_argument("--restic", type=Path, required=True)
    retry.add_argument("--restic-sha256", required=True)
    retry.add_argument("--root", type=Path, required=True)
    retry.add_argument("--core-state", type=Path, required=True)
    retry.add_argument("--lab-password-file", type=Path, required=True)
    retry.add_argument("--staging-parent", type=Path, required=True)
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
    elif args.command == "switch-stopped":
        result = switch_stopped_vessel_release(
            args.root, args.trusted_key, args.crane, args.bundle,
            args.console_config)
    elif args.command == "rollback-stopped":
        result = rollback_stopped_vessel_release(
            args.root, args.trusted_key, args.crane)
    elif args.command == "discard-staged-candidate":
        result = discard_stopped_vessel_stage(
            args.root, args.trusted_key, args.bundle, args.console_config,
            discard_stage=args.discard_stage)
    elif args.command == "capture-recovery-set":
        result = create_vessel_recovery_set(
            args.root, args.trusted_key, args.crane, args.repository,
            args.password_file, args.restic, args.restic_sha256,
            args.staging_parent, args.receipt_signing_key, args.receipt)
    elif args.command == "migrate-history-stopped":
        result = migrate_stopped_vessel_history(
            args.root, args.trusted_key, args.crane, args.repository,
            args.password_file, args.restic, args.restic_sha256,
            args.staging_parent, args.evidence, args.receipt_signing_key,
            args.receipt)
    elif args.command == "verify-history-migration-receipt":
        result = verify_vessel_history_migration_receipt(args.receipt,
                                                        args.receipt_key)
    elif args.command == "verify-recovery-receipt":
        result = verify_vessel_recovery_receipt(args.receipt, args.receipt_key)
    elif args.command == "restore-recovery-files":
        result = restore_vessel_recovery_files(
            args.receipt, args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.destination)
    elif args.command == "activate-recovery-set":
        result = activate_vessel_recovery_set(
            args.bundle, args.trusted_key, args.crane, args.console_config,
            args.receipt, args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.root, args.core_state,
            args.lab_password_file, args.staging_parent)
    elif args.command == "abandon-incomplete-restore":
        result = abandon_incomplete_vessel_restore(
            args.root, args.trusted_key, args.receipt, args.receipt_key,
            discard_partial_data=args.discard_partial_data)
    elif args.command == "retry-abandoned-restore":
        result = retry_abandoned_vessel_restore(
            args.abandoned_root, args.bundle, args.trusted_key, args.crane,
            args.console_config, args.receipt, args.receipt_key,
            args.password_file, args.restic, args.restic_sha256, args.root,
            args.core_state, args.lab_password_file, args.staging_parent)
    else:
        result = recover_vessel(args.root, args.trusted_key, args.crane)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
