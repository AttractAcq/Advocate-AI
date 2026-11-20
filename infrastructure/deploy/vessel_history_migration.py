"""Stopped synthetic vessel history migration bound to signed release state."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from infrastructure.deploy.container_runtime import _image_id
from infrastructure.deploy.history_migration import migrate_history_with_backup
from infrastructure.deploy.vessel_installer import (
    _operation_lock, _owner_directory, _read_state, _recovery_inventory,
    _verify_stage,
)
from infrastructure.deploy.vessel_recovery_set import (
    _canonical, _private_bytes, _sign_receipt, _unique,
)
from infrastructure.deploy.vessel_runtime import _state_options
from infrastructure.release.bundle import verify_bundle
from services.policy.policy_file import policy_directory_lock


class VesselHistoryMigrationError(ValueError):
    """The stopped migration or its signed evidence cannot be trusted."""


_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_RELEASE = re.compile(r"[0-9a-f]{24}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _receipt_payload(value: object) -> dict[str, object]:
    keys = {"schema", "installation_id", "release", "manifest_sha256",
            "snapshot_id", "repository", "history_sha256", "conversations",
            "migrated_utc"}
    if (not isinstance(value, dict) or set(value) != keys or
            type(value["schema"]) is not int or value["schema"] != 1 or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["release"], str) or
            not _RELEASE.fullmatch(value["release"]) or
            any(not isinstance(value[name], str) or not _SHA.fullmatch(value[name])
                for name in ("manifest_sha256", "snapshot_id", "history_sha256")) or
            not isinstance(value["repository"], str) or
            not Path(value["repository"]).is_absolute() or
            type(value["conversations"]) is not int or value["conversations"] < 0 or
            not isinstance(value["migrated_utc"], str)):
        raise VesselHistoryMigrationError("invalid vessel history migration receipt")
    try:
        timestamp = datetime.fromisoformat(value["migrated_utc"])
    except ValueError as exc:
        raise VesselHistoryMigrationError("invalid history migration timestamp") from exc
    if timestamp.tzinfo is None:
        raise VesselHistoryMigrationError("history migration timestamp lacks timezone")
    return value


def migrate_stopped_vessel_history(root: Path, trusted_key: Path, crane: Path,
                                   repository: Path, password_file: Path,
                                   restic: Path, restic_sha256: str,
                                   staging_parent: Path, evidence: Path,
                                   receipt_signing_key: Path,
                                   receipt: Path) -> dict[str, object]:
    """Require a signed, stopped vessel and verified encrypted history backup."""
    _owner_directory(root)
    _owner_directory(receipt.parent)
    locations = (repository, staging_parent, evidence.parent, receipt.parent)
    if (not receipt.is_absolute() or receipt.exists() or receipt.is_symlink()
            or receipt == evidence or
            any(not path.is_absolute() or path.resolve().is_relative_to(root.resolve())
                or root.resolve().is_relative_to(path.resolve()) for path in locations)
            or receipt.parent.resolve().is_relative_to(repository.resolve())
            or receipt.parent.resolve().is_relative_to(staging_parent.resolve())):
        raise VesselHistoryMigrationError("history migration output paths are unsafe")
    key = serialization.load_pem_private_key(
        _private_bytes(receipt_signing_key, 4096), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VesselHistoryMigrationError("history migration signing key is not Ed25519")
    with _operation_lock(root):
        record = _read_state(root)
        active = record["active"]
        stage = root / "vessel-releases" / active
        _verify_stage(stage, trusted_key, active)
        bundle = stage / "bundle"
        signed = verify_bundle(bundle, trusted_key)
        _image_id(bundle, "core", signed["images"]["core"], crane)
        state = Path(record["core_state"])
        password = Path(record["lab_password_file"])
        if (state.resolve().is_relative_to(root.resolve()) or
                root.resolve().is_relative_to(state.resolve()) or
                receipt.parent.resolve().is_relative_to(state.resolve()) or
                state.resolve().is_relative_to(receipt.parent.resolve())):
            raise VesselHistoryMigrationError("migration output overlaps Core state")
        _recovery_inventory(record["installation_id"], record["runtime"])
        with policy_directory_lock(state / "roles.json", exclusive=True):
            _state_options(state, password, root, allow_legacy_history=True)
            result = migrate_history_with_backup(
                state / "history.db", repository, password_file, restic,
                restic_sha256, staging_parent, evidence)
            _state_options(state, password, root)
            _recovery_inventory(record["installation_id"], record["runtime"])
            manifest = bundle / "release-manifest.json"
            payload = _receipt_payload({
                "schema": 1, "installation_id": record["installation_id"],
                "release": active,
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "snapshot_id": result["snapshot_id"],
                "repository": result["repository"],
                "history_sha256": result["history_sha256"],
                "conversations": result["conversations"],
                "migrated_utc": datetime.now(timezone.utc).isoformat(),
            })
            _sign_receipt(receipt, payload, receipt_signing_key)
            return payload


def verify_vessel_history_migration_receipt(receipt: Path,
                                            trusted_key: Path) -> dict[str, object]:
    """Verify the release-bound, canonical signed history migration record."""
    try:
        envelope = json.loads(_private_bytes(receipt, 8192), object_pairs_hook=_unique)
        if (not isinstance(envelope, dict) or set(envelope) !=
                {"schema", "payload", "signature"} or
                type(envelope["schema"]) is not int or envelope["schema"] != 1):
            raise VesselHistoryMigrationError("invalid history migration envelope")
        raw = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(raw) > 4096 or len(signature) != 64:
            raise VesselHistoryMigrationError("invalid history migration signature size")
        key = serialization.load_pem_public_key(trusted_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise VesselHistoryMigrationError("history migration trust key is not Ed25519")
        key.verify(signature, raw)
        value = json.loads(raw, object_pairs_hook=_unique)
        if raw != _canonical(value):
            raise VesselHistoryMigrationError("noncanonical history migration receipt")
        return _receipt_payload(value)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            InvalidSignature) as exc:
        raise VesselHistoryMigrationError(
            "vessel history migration receipt verification failed") from exc
