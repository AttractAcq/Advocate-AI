"""Bind a synthetic Keycloak export to one signed vessel recovery receipt.

This checks artifact identity only. It does not attest a common capture point
or that a running Keycloak has imported the checked export.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from infrastructure.backup import BackupError, inspect_backup
from infrastructure.deploy.vessel_recovery_set import (
    VesselRecoveryError, _private_bytes, _sign_receipt,
    verify_vessel_recovery_receipt,
)


class IdentityRecoveryError(BackupError):
    """The paired identity recovery artifacts are unsafe or do not match."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IdentityRecoveryError("duplicate identity recovery field")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _safe_parent(path: Path) -> None:
    if not path.is_absolute():
        raise IdentityRecoveryError("identity recovery path must be absolute")
    details = path.parent.lstat()
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or
            stat.S_IMODE(details.st_mode) & 0o022):
        raise IdentityRecoveryError("unsafe identity recovery parent")


def _private_digest(path: Path, *, maximum: int) -> str:
    details = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
            details.st_nlink != 1 or stat.S_IMODE(details.st_mode) & 0o077 or
            not 1 <= details.st_size <= maximum):
        raise IdentityRecoveryError("unsafe identity recovery artifact")
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                details.st_dev, details.st_ino, details.st_size):
            raise IdentityRecoveryError("identity recovery artifact changed before read")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
         after.st_ctime_ns) !=
        (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns,
         details.st_ctime_ns) or
        (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino)):
        raise IdentityRecoveryError("identity recovery artifact changed during read")
    return digest.hexdigest()


def checked_realm_restore(archive: Path, key: Path, destination: Path,
                          trusted_digest: str, realm_name: str) -> str:
    """Restore one authenticated realm export after an exact checkpoint match."""
    _safe_parent(destination)
    if os.path.lexists(destination):
        raise IdentityRecoveryError("identity restore requires a new directory")
    if (len(trusted_digest) != 64 or any(c not in "0123456789abcdef"
                                        for c in trusted_digest)):
        raise IdentityRecoveryError("invalid identity archive checkpoint")
    if not hmac.compare_digest(_private_digest(archive, maximum=1024**3),
                               trusted_digest):
        raise IdentityRecoveryError("identity archive differs from checkpoint")
    if not realm_name or not realm_name.replace("-", "").replace("_", "").isalnum():
        raise IdentityRecoveryError("invalid identity realm")
    name = realm_name + "-realm.json"
    try:
        manifest = inspect_backup(archive, key, destination)
        if [row["name"] for row in manifest["files"]] != [name]:
            raise IdentityRecoveryError("unexpected identity archive inventory")
        realm_file = destination / name
        realm = json.loads(realm_file.read_bytes(), object_pairs_hook=_unique)
        if (not isinstance(realm, dict) or realm.get("realm") != realm_name or
                not isinstance(realm.get("users"), list) or not realm["users"]):
            raise IdentityRecoveryError("restored identity realm or users are missing")
        digest = hashlib.sha256(realm_file.read_bytes()).hexdigest()
        if not hmac.compare_digest(_private_digest(archive, maximum=1024**3),
                                   trusted_digest):
            raise IdentityRecoveryError("identity archive changed during restore")
        return digest
    except Exception:
        if destination.exists():
            shutil.rmtree(destination)
        raise


def _pair_payload(value: object) -> dict[str, object]:
    if (not isinstance(value, dict) or set(value) != {
            "schema", "installation_id", "issuer", "core_receipt_sha256",
            "core_snapshot_id", "keycloak_archive_sha256", "realm_sha256",
            "created_utc"} or type(value["schema"]) is not int or
            value["schema"] != 1 or
            any(not isinstance(value[key], str) for key in value if key != "schema") or
            any(len(value[key]) != 64 or any(c not in "0123456789abcdef" for c in value[key])
                for key in ("core_receipt_sha256", "core_snapshot_id",
                            "keycloak_archive_sha256", "realm_sha256"))):
        raise IdentityRecoveryError("invalid identity recovery pair")
    try:
        created = datetime.fromisoformat(value["created_utc"])
    except ValueError as exc:
        raise IdentityRecoveryError("invalid identity recovery timestamp") from exc
    if created.tzinfo is None:
        raise IdentityRecoveryError("identity recovery timestamp lacks timezone")
    return value


def create_identity_recovery_pair(core_receipt: Path, core_receipt_key: Path,
                                  archive: Path, archive_key: Path,
                                  archive_checkpoint: str, signing_key: Path,
                                  output: Path) -> dict[str, object]:
    """Sign exact identities of a verified Core receipt and realm export."""
    _safe_parent(output)
    core = verify_vessel_recovery_receipt(core_receipt, core_receipt_key)
    if core["schema"] != 3:
        raise IdentityRecoveryError("identity pair requires an OIDC recovery set")
    core_hash = _private_digest(core_receipt, maximum=8192)
    realm_name = urlsplit(core["identity"]["issuer"]).path.rsplit("/", 1)[-1]
    with tempfile.TemporaryDirectory(prefix=".identity-pair-", dir=output.parent) as scratch:
        realm_hash = checked_realm_restore(
            archive, archive_key, Path(scratch) / "realm", archive_checkpoint,
            realm_name)
    payload = _pair_payload({
        "schema": 1, "installation_id": core["installation_id"],
        "issuer": core["identity"]["issuer"],
        "core_receipt_sha256": core_hash,
        "core_snapshot_id": core["snapshot_id"],
        "keycloak_archive_sha256": archive_checkpoint,
        "realm_sha256": realm_hash,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    })
    _sign_receipt(output, payload, signing_key)
    return payload


def restore_paired_realm(pair: Path, pair_key: Path,
                         core_receipt: Path, core_receipt_key: Path,
                         archive: Path, archive_key: Path,
                         destination: Path) -> dict[str, object]:
    """Check both signatures and archive bytes before clean realm import."""
    _safe_parent(destination)
    if os.path.lexists(destination):
        raise IdentityRecoveryError("identity restore requires a new directory")
    try:
        envelope = json.loads(_private_bytes(pair, 8192), object_pairs_hook=_unique)
        if (not isinstance(envelope, dict) or set(envelope) !=
                {"schema", "payload", "signature"} or envelope["schema"] != 1):
            raise IdentityRecoveryError("invalid identity recovery pair envelope")
        raw = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(raw) > 4096 or len(signature) != 64:
            raise IdentityRecoveryError("invalid identity recovery pair signature")
        key = serialization.load_pem_public_key(pair_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise IdentityRecoveryError("invalid identity recovery trust key")
        key.verify(signature, raw)
        payload = _pair_payload(json.loads(raw, object_pairs_hook=_unique))
        if raw != _canonical(payload):
            raise IdentityRecoveryError("noncanonical identity recovery pair")
        core = verify_vessel_recovery_receipt(core_receipt, core_receipt_key)
        if (core["schema"] != 3 or
                payload["installation_id"] != core["installation_id"] or
                payload["issuer"] != core["identity"]["issuer"] or
                payload["core_snapshot_id"] != core["snapshot_id"] or
                not hmac.compare_digest(_private_digest(core_receipt, maximum=8192),
                                        payload["core_receipt_sha256"])):
            raise IdentityRecoveryError("Core receipt differs from identity pair")
        realm_name = urlsplit(payload["issuer"]).path.rsplit("/", 1)[-1]
        realm_hash = checked_realm_restore(
            archive, archive_key, destination,
            payload["keycloak_archive_sha256"], realm_name)
        if not hmac.compare_digest(realm_hash, payload["realm_sha256"]):
            raise IdentityRecoveryError("restored realm differs from identity pair")
        return {"result": "paired-realm-restored", "issuer": payload["issuer"],
                "installation_id": payload["installation_id"]}
    except (BackupError, VesselRecoveryError, OSError, ValueError, TypeError,
            KeyError, InvalidSignature) as exc:
        if destination.exists():
            shutil.rmtree(destination)
        raise IdentityRecoveryError("identity recovery pair verification failed") from exc
