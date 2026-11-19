"""Capture a signed synthetic Core and upload recovery point while stopped."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from infrastructure.deploy.product_installer import (
    _identifier, _installation_id, _lock, _mount_config, _owner_directory,
    _state, restore_install_product,
)
from infrastructure.restic_repository import create_snapshot
from infrastructure.release.bundle import verify_bundle
from infrastructure.upload_quarantine_backup import create_upload_snapshot
from services.knowledge.upload_staging import quarantine_directory_lock
from services.policy.policy_file import policy_directory_lock


class RecoverySetError(ValueError):
    """The synthetic product cannot produce or verify a recovery set."""


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoverySetError("duplicate recovery receipt key")
        result[key] = value
    return result


def _private_file(path: Path, *, maximum: int) -> bytes:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077 or path.stat().st_size > maximum):
        raise RecoverySetError("private recovery file is missing or unsafe")
    return path.read_bytes()


def _require_stopped(runtime: dict[str, str]) -> None:
    """Require a reachable Docker daemon and absent or stopped product containers."""
    try:
        daemon = subprocess.run(["docker", "info", "--format", "{{.ID}}"],
                                capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoverySetError("Docker runtime state unavailable") from exc
    if daemon.returncode or not daemon.stdout.strip():
        raise RecoverySetError("Docker runtime state unavailable")
    for name in ("core_id", "console_id"):
        identifier = runtime[name]
        try:
            checked = subprocess.run(["docker", "inspect", "--format",
                                      "{{.State.Running}}", identifier],
                                     capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RecoverySetError("product runtime state unavailable") from exc
        if checked.returncode:
            try:
                present = subprocess.run(
                    ["docker", "ps", "-a", "--no-trunc", "--filter", f"id={identifier}",
                     "--format", "{{.ID}}"], capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RecoverySetError("product runtime state unavailable") from exc
            if present.returncode or present.stdout.strip():
                raise RecoverySetError("product runtime state unavailable")
        elif checked.stdout.strip() != "false":
            raise RecoverySetError("product runtime must be stopped before backup")


def _source_file(state: Path) -> Path:
    source_dir = state / "sources"
    files = list(source_dir.iterdir())
    if (len(files) != 1 or files[0].is_symlink() or not files[0].is_file()
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", files[0].name)):
        raise RecoverySetError("synthetic Core snapshot requires one regular source")
    return files[0]


def _payload(value: object) -> dict[str, object]:
    expected = {"schema", "installation_id", "active_release", "runtime_ids",
                "started_utc", "finished_utc", "core_snapshot_id",
                "upload_snapshot_id", "core_repository", "upload_repository"}
    if (not isinstance(value, dict) or set(value) != expected
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["installation_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["installation_id"])
            or not isinstance(value["active_release"], str)
            or not re.fullmatch(r"[0-9a-f]{24}", value["active_release"])
            or not isinstance(value["runtime_ids"], dict)
            or set(value["runtime_ids"]) != {"network_id", "core_id", "console_id"}
            or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
                   for item in value["runtime_ids"].values())
            or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key])
                   for key in ("core_snapshot_id", "upload_snapshot_id"))
            or any(not isinstance(value[key], str) or not Path(value[key]).is_absolute()
                   for key in ("core_repository", "upload_repository"))
            or value["core_repository"] == value["upload_repository"]):
        raise RecoverySetError("invalid recovery receipt payload")
    try:
        started = datetime.fromisoformat(value["started_utc"])
        finished = datetime.fromisoformat(value["finished_utc"])
    except (ValueError, TypeError) as exc:
        raise RecoverySetError("invalid recovery capture time") from exc
    if (started.tzinfo is None or finished.tzinfo is None or
            not started <= finished or
            (finished - started).total_seconds() > 3600):
        raise RecoverySetError("invalid recovery capture window")
    return value


def create_product_recovery_set(install_root: Path, core_repository: Path,
                                upload_repository: Path, core_password_file: Path,
                                upload_password_file: Path, restic: Path,
                                restic_sha256: str, staging_parent: Path,
                                signing_key: Path, output: Path) -> dict[str, object]:
    """Capture two encrypted snapshots under one stopped, locked window."""
    _owner_directory(install_root, create=False)
    _owner_directory(staging_parent, create=False)
    _owner_directory(output.parent, create=False)
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not core_repository.is_absolute() or not upload_repository.is_absolute()
            or core_repository.resolve() == upload_repository.resolve()):
        raise RecoverySetError("invalid recovery set paths")
    try:
        key = serialization.load_pem_private_key(_private_file(signing_key, maximum=4096),
                                                  password=None)
    except (ValueError, TypeError) as exc:
        raise RecoverySetError("invalid recovery signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RecoverySetError("recovery signing key must be Ed25519")
    with _lock(install_root):
        state_record = _state(install_root)
        state, _, _, uploads = _mount_config(install_root)
        if state_record is None or state is None or uploads is None:
            raise RecoverySetError("installed synthetic Core and uploads are required")
        runtime = state_record["runtime"]
        _require_stopped(runtime)
        source = _source_file(state)
        started = datetime.now(timezone.utc)
        with policy_directory_lock(state / "roles.json", exclusive=True), \
                quarantine_directory_lock(uploads, exclusive=False):
            _require_stopped(runtime)
            with tempfile.TemporaryDirectory(prefix=".product-recovery-set-",
                                             dir=staging_parent) as temporary:
                spec = Path(temporary) / "core-spec.json"
                spec.write_text(json.dumps({"schema": 1, "files": [
                    {"name": "roles.json", "kind": "file", "source": str(state / "roles.json")},
                    {"name": "manifest.csv", "kind": "file", "source": str(state / "manifest.csv")},
                    {"name": "history.db", "kind": "sqlite", "source": str(state / "history.db")},
                    {"name": f"sources/{source.name}", "kind": "file", "source": str(source)},
                ]}))
                core = create_snapshot(spec, core_repository, core_password_file,
                                       restic, restic_sha256, staging_parent)
                upload = create_upload_snapshot(uploads, upload_repository,
                                                upload_password_file, restic,
                                                restic_sha256, staging_parent)
            _require_stopped(runtime)
            value = _payload({
                "schema": 1, "installation_id": _installation_id(install_root),
                "active_release": state_record["active"], "runtime_ids": runtime,
                "started_utc": started.isoformat(),
                "finished_utc": datetime.now(timezone.utc).isoformat(),
                "core_snapshot_id": core["snapshot_id"],
                "upload_snapshot_id": upload["snapshot_id"],
                "core_repository": str(core_repository.resolve()),
                "upload_repository": str(upload_repository.resolve()),
            })
            raw = _canonical(value)
            signed = {"schema": 1, "payload": base64.b64encode(raw).decode("ascii"),
                      "signature": base64.b64encode(key.sign(raw)).decode("ascii")}
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(_canonical(signed))
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                output.unlink(missing_ok=True)
                raise
    return value


def verify_product_recovery_set(receipt: Path, trusted_key: Path) -> dict[str, object]:
    """Verify the exact signed snapshot pair before operator-selected restore."""
    try:
        signed = json.loads(_private_file(receipt, maximum=8192), object_pairs_hook=_unique)
        if (not isinstance(signed, dict) or set(signed) != {"schema", "payload", "signature"}
                or type(signed["schema"]) is not int or signed["schema"] != 1
                or not isinstance(signed["payload"], str)
                or not isinstance(signed["signature"], str)):
            raise RecoverySetError("invalid recovery receipt")
        raw = base64.b64decode(signed["payload"], validate=True)
        signature = base64.b64decode(signed["signature"], validate=True)
        if len(raw) > 4096 or len(signature) != 64:
            raise RecoverySetError("invalid recovery receipt size")
        key = serialization.load_pem_public_key(trusted_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise RecoverySetError("recovery trust key must be Ed25519")
        key.verify(signature, raw)
        value = json.loads(raw, object_pairs_hook=_unique)
        if raw != _canonical(value):
            raise RecoverySetError("noncanonical recovery receipt")
        return _payload(value)
    except (OSError, ValueError, UnicodeError, InvalidSignature) as exc:
        raise RecoverySetError("recovery receipt verification failed") from exc


def restore_product_recovery_set(receipt: Path, receipt_trusted_key: Path,
                                 bundle: Path, bundle_trusted_key: Path,
                                 crane: Path, console_config: Path,
                                 install_root: Path, core_password_file: Path,
                                 upload_password_file: Path, restic: Path,
                                 restic_sha256: str, lab_password_file: Path,
                                 emergency_password_file: Path | None = None
                                 ) -> dict[str, object]:
    """Restore only the signed pair to a new installation of its captured release."""
    recovery_set = verify_product_recovery_set(receipt, receipt_trusted_key)
    manifest = verify_bundle(bundle, bundle_trusted_key)
    if manifest["schema"] != 4 or _identifier(bundle, console_config) != recovery_set["active_release"]:
        raise RecoverySetError("recovery receipt release does not match product bundle")
    restored = restore_install_product(
        bundle, bundle_trusted_key, crane, console_config, install_root,
        str(recovery_set["core_snapshot_id"]), Path(str(recovery_set["core_repository"])),
        core_password_file, restic, restic_sha256, lab_password_file,
        emergency_password_file, enable_uploads=True,
        upload_snapshot_id=str(recovery_set["upload_snapshot_id"]),
        upload_repository=Path(str(recovery_set["upload_repository"])),
        upload_password_file=upload_password_file)
    return {**restored, "recovery_set": "signed-pair-verified"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic signed product recovery set")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in ("install-root", "core-repository", "upload-repository",
                 "core-password-file", "upload-password-file", "restic",
                 "staging-parent", "signing-key", "output"):
        create.add_argument("--" + name, required=True, type=Path)
    create.add_argument("--restic-sha256", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--trusted-key", required=True, type=Path)
    restore = commands.add_parser("restore")
    for name in ("receipt", "receipt-trusted-key", "bundle", "bundle-trusted-key",
                 "crane", "console-config", "install-root", "core-password-file",
                 "upload-password-file", "restic", "lab-password-file"):
        restore.add_argument("--" + name, required=True, type=Path)
    restore.add_argument("--restic-sha256", required=True)
    restore.add_argument("--emergency-password-file", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_product_recovery_set(
                args.install_root, args.core_repository, args.upload_repository,
                args.core_password_file, args.upload_password_file, args.restic,
                args.restic_sha256, args.staging_parent, args.signing_key, args.output)
        elif args.command == "verify":
            result = verify_product_recovery_set(args.receipt, args.trusted_key)
        else:
            result = restore_product_recovery_set(
                args.receipt, args.receipt_trusted_key, args.bundle,
                args.bundle_trusted_key, args.crane, args.console_config,
                args.install_root, args.core_password_file,
                args.upload_password_file, args.restic, args.restic_sha256,
                args.lab_password_file, args.emergency_password_file)
    except (RecoverySetError, OSError, ValueError) as exc:
        parser.exit(1, f"product recovery set: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
