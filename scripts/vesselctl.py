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
    finish_incomplete_vessel_restore, retry_abandoned_vessel_restore,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_release_switch import (
    discard_stopped_vessel_stage, rollback_stopped_vessel_release,
    switch_stopped_vessel_release,
)
from infrastructure.deploy.vessel_runtime import ThreatFeedMount
from infrastructure.deploy.vessel_history_migration import (
    migrate_stopped_vessel_history, verify_vessel_history_migration_backup,
    verify_vessel_history_migration_receipt,
)
from infrastructure.deploy.vessel_identity_recovery import (
    create_identity_recovery_pair, restore_paired_realm,
)


def _identity_pair_arguments(parser: argparse.ArgumentParser) -> None:
    for name in ("identity-pair", "identity-pair-key", "identity-archive",
                 "identity-archive-key"):
        parser.add_argument("--" + name, type=Path)


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
    install_identity = install.add_mutually_exclusive_group(required=True)
    install_identity.add_argument("--lab-password-file", type=Path)
    install_identity.add_argument("--identity-network")
    install.add_argument("--threat-feed-store", type=Path)
    install.add_argument("--threat-feed-key", type=Path)
    for command in ("status", "stop", "finish-stop", "reconcile", "recover",
                    "reconcile-install", "resume-install"):
        commands.add_parser(command, parents=[shared])
    switch = commands.add_parser("switch-stopped", parents=[shared])
    switch.add_argument("--bundle", type=Path, required=True)
    switch.add_argument("--console-config", type=Path, required=True)
    switch.add_argument("--recovery-receipt", type=Path, required=True)
    switch.add_argument("--receipt-key", type=Path, required=True)
    switch.add_argument("--password-file", type=Path, required=True)
    switch.add_argument("--restic", type=Path, required=True)
    switch.add_argument("--restic-sha256", required=True)
    switch.add_argument("--staging-parent", type=Path, required=True)
    rollback = commands.add_parser("rollback-stopped", parents=[shared])
    rollback.add_argument("--recovery-receipt", type=Path, required=True)
    rollback.add_argument("--receipt-key", type=Path, required=True)
    rollback.add_argument("--password-file", type=Path, required=True)
    rollback.add_argument("--restic", type=Path, required=True)
    rollback.add_argument("--restic-sha256", required=True)
    rollback.add_argument("--staging-parent", type=Path, required=True)
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
    verify_history_backup = commands.add_parser("verify-history-migration-backup")
    verify_history_backup.add_argument("--receipt", type=Path, required=True)
    verify_history_backup.add_argument("--receipt-key", type=Path, required=True)
    verify_history_backup.add_argument("--password-file", type=Path, required=True)
    verify_history_backup.add_argument("--restic", type=Path, required=True)
    verify_history_backup.add_argument("--restic-sha256", required=True)
    verify_history_backup.add_argument("--staging-parent", type=Path, required=True)
    verify = commands.add_parser("verify-recovery-receipt")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--receipt-key", type=Path, required=True)
    identity_pair = commands.add_parser("pair-identity-recovery")
    identity_pair.add_argument("--core-receipt", type=Path, required=True)
    identity_pair.add_argument("--core-receipt-key", type=Path, required=True)
    identity_pair.add_argument("--archive", type=Path, required=True)
    identity_pair.add_argument("--archive-key", type=Path, required=True)
    identity_pair.add_argument("--archive-checkpoint", required=True)
    identity_pair.add_argument("--signing-key", type=Path, required=True)
    identity_pair.add_argument("--output", type=Path, required=True)
    identity_restore = commands.add_parser("restore-paired-identity")
    identity_restore.add_argument("--pair", type=Path, required=True)
    identity_restore.add_argument("--pair-key", type=Path, required=True)
    identity_restore.add_argument("--core-receipt", type=Path, required=True)
    identity_restore.add_argument("--core-receipt-key", type=Path, required=True)
    identity_restore.add_argument("--archive", type=Path, required=True)
    identity_restore.add_argument("--archive-key", type=Path, required=True)
    identity_restore.add_argument("--destination", type=Path, required=True)
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
    activate_identity = activate.add_mutually_exclusive_group(required=True)
    activate_identity.add_argument("--lab-password-file", type=Path)
    activate_identity.add_argument("--identity-network")
    activate.add_argument("--staging-parent", type=Path, required=True)
    activate.add_argument("--threat-feed-store", type=Path)
    activate.add_argument("--threat-feed-key", type=Path)
    _identity_pair_arguments(activate)
    finish_restore = commands.add_parser("finish-incomplete-restore")
    finish_restore.add_argument("--root", type=Path, required=True)
    finish_restore.add_argument("--trusted-key", type=Path, required=True)
    finish_restore.add_argument("--crane", type=Path, required=True)
    finish_restore.add_argument("--receipt", type=Path, required=True)
    finish_restore.add_argument("--receipt-key", type=Path, required=True)
    finish_restore.add_argument("--password-file", type=Path, required=True)
    finish_restore.add_argument("--restic", type=Path, required=True)
    finish_restore.add_argument("--restic-sha256", required=True)
    finish_restore.add_argument("--staging-parent", type=Path, required=True)
    _identity_pair_arguments(finish_restore)
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
    retry_identity = retry.add_mutually_exclusive_group(required=True)
    retry_identity.add_argument("--lab-password-file", type=Path)
    retry_identity.add_argument("--identity-network")
    retry.add_argument("--staging-parent", type=Path, required=True)
    retry.add_argument("--threat-feed-store", type=Path)
    retry.add_argument("--threat-feed-key", type=Path)
    _identity_pair_arguments(retry)
    args = parser.parse_args(argv)
    feed_store = getattr(args, "threat_feed_store", None)
    feed_key = getattr(args, "threat_feed_key", None)
    if bool(feed_store) != bool(feed_key):
        parser.error("--threat-feed-store and --threat-feed-key must be supplied together")
    feed_options = ({"threat_feed": ThreatFeedMount(feed_store, feed_key)}
                    if feed_store is not None else {})
    identity_pair_options = {
        name: value for name in ("identity_pair", "identity_pair_key",
                                 "identity_archive", "identity_archive_key")
        if (value := getattr(args, name, None)) is not None
    }
    if args.command == "install":
        result = install_vessel(args.bundle, args.trusted_key, args.crane,
                                args.console_config, args.root, args.core_state,
                                args.lab_password_file,
                                **feed_options,
                                **({"identity_network": args.identity_network}
                                   if args.identity_network is not None else {}))
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
            args.console_config, args.recovery_receipt, args.receipt_key,
            args.password_file, args.restic, args.restic_sha256,
            args.staging_parent)
    elif args.command == "rollback-stopped":
        result = rollback_stopped_vessel_release(
            args.root, args.trusted_key, args.crane, args.recovery_receipt,
            args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.staging_parent)
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
    elif args.command == "verify-history-migration-backup":
        result = verify_vessel_history_migration_backup(
            args.receipt, args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.staging_parent)
    elif args.command == "verify-recovery-receipt":
        result = verify_vessel_recovery_receipt(args.receipt, args.receipt_key)
    elif args.command == "pair-identity-recovery":
        result = create_identity_recovery_pair(
            args.core_receipt, args.core_receipt_key, args.archive,
            args.archive_key, args.archive_checkpoint, args.signing_key,
            args.output)
    elif args.command == "restore-paired-identity":
        result = restore_paired_realm(
            args.pair, args.pair_key, args.core_receipt,
            args.core_receipt_key, args.archive, args.archive_key,
            args.destination)
    elif args.command == "restore-recovery-files":
        result = restore_vessel_recovery_files(
            args.receipt, args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.destination)
    elif args.command == "activate-recovery-set":
        result = activate_vessel_recovery_set(
            args.bundle, args.trusted_key, args.crane, args.console_config,
            args.receipt, args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.root, args.core_state,
            args.lab_password_file, args.staging_parent,
            **({"identity_network": args.identity_network}
               if args.identity_network is not None else {}),
            **feed_options,
            **identity_pair_options)
    elif args.command == "finish-incomplete-restore":
        result = finish_incomplete_vessel_restore(
            args.root, args.trusted_key, args.crane, args.receipt,
            args.receipt_key, args.password_file, args.restic,
            args.restic_sha256, args.staging_parent,
            **identity_pair_options)
    elif args.command == "abandon-incomplete-restore":
        result = abandon_incomplete_vessel_restore(
            args.root, args.trusted_key, args.receipt, args.receipt_key,
            discard_partial_data=args.discard_partial_data)
    elif args.command == "retry-abandoned-restore":
        result = retry_abandoned_vessel_restore(
            args.abandoned_root, args.bundle, args.trusted_key, args.crane,
            args.console_config, args.receipt, args.receipt_key,
            args.password_file, args.restic, args.restic_sha256, args.root,
            args.core_state, args.lab_password_file, args.staging_parent,
            **({"identity_network": args.identity_network}
               if args.identity_network is not None else {}),
            **feed_options,
            **identity_pair_options)
    else:
        result = recover_vessel(args.root, args.trusted_key, args.crane)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
