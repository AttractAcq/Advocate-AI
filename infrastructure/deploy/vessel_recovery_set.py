"""Coordinated encrypted capture of a stopped synthetic vessel installation."""

from __future__ import annotations

import base64
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from apps.api.auth import verify_history_format
from apps.api.oidc import validate_keycloak_issuer
from infrastructure.deploy.container_runtime import (
    RuntimeHandle, _docker, _image_id, _validate_console_config, stop_runtime,
)
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, _credentials, _volume, start_signed_knowledge,
    stop_knowledge, probe_knowledge,
)
from infrastructure.deploy.vessel_installer import (
    _assert_missing, _cleanup_failed_install, _operation_lock, _owner_directory,
    _remove_scoped_orphans,
    _read_intent, _read_state, _record_inputs, _recovery_inventory, _release_id, _scoped_list,
    _stage, _state_payload, _verify_knowledge_schema, _verify_stage,
    _write_intent, _write_private_record, _write_state,
)
from infrastructure.deploy.vessel_identity import (
    preflight_vessel_identity, validated_identity_material,
)
from infrastructure.deploy.postgres_socket import sql as postgres_sql, verify_security
from infrastructure.deploy.vessel_runtime import _state_options, start_signed_vessel_services
from infrastructure.release.bundle import require_supported_vessel_compatibility, verify_bundle
from infrastructure.restic_repository import create_snapshot, restore_snapshot
from scripts.phase5_postgres_rehearsal import _dump, _restore
from services.knowledge.ingestion import _valid_source
from services.knowledge.manifest_io import load_manifest, read_manifest_bytes
from services.policy.audit import verify as verify_audit
from services.policy.policy_file import policy_directory_lock, read_policy_bytes


class VesselRecoveryError(ValueError):
    """The stopped vessel cannot produce or accept a complete recovery set."""


_ID = re.compile(r"[0-9a-f]{64}\Z")
_RELEASE = re.compile(r"[0-9a-f]{24}\Z")
_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_MAX_SOURCES = 120
_MAX_AUDIT = 16 * 1024 * 1024
_MAX_HISTORY = 256 * 1024 * 1024


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VesselRecoveryError("duplicate vessel recovery key")
        result[key] = value
    return result


def _private_bytes(path: Path, maximum: int) -> bytes:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or path.stat().st_nlink != 1
            or not 0 < path.stat().st_size <= maximum):
        raise VesselRecoveryError("unsafe private recovery file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o077
                or details.st_nlink != 1
                or not 0 < details.st_size <= maximum):
            raise VesselRecoveryError("unsafe private recovery file")
        payload = stream.read(maximum + 1)
        if len(payload) > maximum:
            raise VesselRecoveryError("oversized private recovery file")
        return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_inventory(state: Path, listed: set[str]) -> None:
    root = state / "sources"
    if root.is_symlink() or not root.is_dir():
        raise VesselRecoveryError("unsafe vessel source directory")
    actual: set[str] = set()
    for item in root.rglob("*"):
        if item.is_symlink() or not (item.is_dir() or item.is_file()):
            raise VesselRecoveryError("unsafe vessel source inventory")
        if item.is_file():
            if item.stat().st_nlink != 1:
                raise VesselRecoveryError("hard-linked vessel source")
            actual.add(item.relative_to(state).as_posix())
    if actual != listed:
        raise VesselRecoveryError("vessel source inventory differs from approved manifest")


def _history_copy(source: Path, target: Path) -> None:
    if (source.is_symlink() or not source.is_file() or
            source.stat().st_uid != os.getuid() or
            stat.S_IMODE(source.stat().st_mode) & 0o077 or
            source.stat().st_nlink != 1 or
            not 0 < source.stat().st_size <= _MAX_HISTORY):
        raise VesselRecoveryError("invalid vessel conversation database")
    try:
        with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as original:
            verify_history_format(original)
            with closing(sqlite3.connect(target)) as copy:
                original.backup(copy)
                verify_history_format(copy)
    except (sqlite3.DatabaseError, ValueError) as exc:
        raise VesselRecoveryError("conversation database snapshot failed") from exc
    target.chmod(0o600)


def _stage_core(state: Path, frozen: Path, *, oidc: bool = False
                ) -> tuple[int, tuple[int, str], str]:
    for name in ("approved.json", "roles.json"):
        path = state / name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise VesselRecoveryError("unsafe linked vessel configuration")
    manifest = load_manifest(state / "approved.json")
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "sources"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or not isinstance(manifest["sources"], list)
            or not 1 <= len(manifest["sources"]) <= _MAX_SOURCES):
        raise VesselRecoveryError("invalid vessel recovery source manifest")
    approved = read_manifest_bytes(state / "approved.json")
    roles = read_policy_bytes(state / "roles.json")
    audit_path = state / "audit.jsonl"
    audit = _private_bytes(audit_path, _MAX_AUDIT)
    identity_material = (validated_identity_material(
        state / "oidc-ca.pem", state / "oidc-revocations.jsonl") if oidc else None)
    checkpoint = verify_audit(audit_path, require_current_clock=True)
    if checkpoint[0] < 1:
        raise VesselRecoveryError("vessel audit trail has no checkpoint")
    sources: set[str] = set()
    for item in manifest["sources"]:
        if not isinstance(item, dict):
            raise VesselRecoveryError("invalid vessel recovery source")
        relative = item.get("relative_path")
        if not isinstance(relative, str) or not relative.startswith("sources/") or \
                relative in sources:
            raise VesselRecoveryError("invalid vessel recovery source path")
        sources.add(relative)
    _source_inventory(state, sources)
    frozen.mkdir(mode=0o700)
    for item in manifest["sources"]:
        _, _, payload = _valid_source(state, item)
        relative = item["relative_path"]
        destination = frozen / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    for name, payload in (("approved.json", approved), ("roles.json", roles),
                          ("audit.jsonl", audit)):
        path = frozen / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    if identity_material is not None:
        for name, payload in zip(("oidc-ca.pem", "oidc-revocations.jsonl"),
                                 identity_material):
            path = frozen / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
    _history_copy(state / "history.db", frozen / "history.db")
    if (verify_audit(frozen / "audit.jsonl", require_current_clock=True) != checkpoint or
            read_manifest_bytes(frozen / "approved.json") != approved or
            read_policy_bytes(frozen / "roles.json") != roles):
        raise VesselRecoveryError("frozen vessel Core state changed")
    for item in manifest["sources"]:
        _valid_source(frozen, item)
    if identity_material is not None and validated_identity_material(
            frozen / "oidc-ca.pem", frozen / "oidc-revocations.jsonl") != identity_material:
        raise VesselRecoveryError("frozen OIDC identity material changed")
    return len(sources), checkpoint, hashlib.sha256(approved).hexdigest()


def _verify_database(bundle: Path, trusted_key: Path, crane: Path,
                     knowledge: KnowledgeVolumeHandle, frozen: Path,
                     secrets_root: Path) -> dict[str, int | str]:
    manifest = verify_bundle(bundle, trusted_key)
    image = _image_id(bundle, "core", manifest["images"]["core"], crane)
    _, _, reader, _, _ = _credentials(secrets_root, initialize=False)
    program = """\
import json
from pathlib import Path
from services.knowledge.postgres_index import verify_knowledge_snapshot
root=Path('/var/lib/sovereign')
result=verify_knowledge_snapshot(root,root/'approved.json',
 'postgresql://sovereign_read@/postgres?host=/run/postgresql',
 include_digest=True)
print(json.dumps(result))
"""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--pull", "never", "--network", "none",
             "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--user", f"{os.getuid()}:{os.getgid()}",
             "--mount", (f"type=volume,source={knowledge.socket_volume},"
                         "target=/run/postgresql,readonly"),
             "--mount", f"type=bind,source={frozen.resolve()},target=/var/lib/sovereign,readonly",
             "--mount", (f"type=bind,source={reader.resolve()},"
                         "target=/run/secrets/pgpass,readonly"),
             "-e", "PGPASSFILE=/run/secrets/pgpass", image, "python", "-c", program],
            capture_output=True, text=True, check=True, timeout=180)
        value = json.loads(result.stdout, object_pairs_hook=_unique)
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise VesselRecoveryError("signed Knowledge snapshot verification failed") from exc
    if (not isinstance(value, dict) or set(value) !=
            {"sources", "passages", "knowledge_sha256"} or
            any(type(value[name]) is not int or value[name] < 1
                for name in ("sources", "passages")) or
            not isinstance(value["knowledge_sha256"], str) or
            not _ID.fullmatch(value["knowledge_sha256"])):
        raise VesselRecoveryError("invalid signed Knowledge snapshot result")
    return value


def _receipt_payload(value: object) -> dict[str, object]:
    common = {"schema", "installation_id", "release", "data_volume",
                "snapshot_id", "repository", "created_utc", "schema_version",
                "audit_count", "audit_tail_hash", "manifest_sha256",
                "dump_sha256", "sources", "passages", "files"}
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or
            value["schema"] not in (1, 2, 3) or
            set(value) != (common if value["schema"] == 1 else
                           common | {"knowledge_sha256"} if value["schema"] == 2 else
                           common | {"knowledge_sha256", "identity"}) or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["release"], str) or
            not _RELEASE.fullmatch(value["release"]) or
            value["data_volume"] !=
            f"sovereign-{value['installation_id']}-knowledge-data" or
            any(not isinstance(value[key], str) or not _ID.fullmatch(value[key])
                for key in ("snapshot_id", "audit_tail_hash", "manifest_sha256",
                            "dump_sha256")) or
            (value["schema"] in (2, 3) and
             (not isinstance(value["knowledge_sha256"], str) or
              not _ID.fullmatch(value["knowledge_sha256"]))) or
            not isinstance(value["repository"], str) or
            not Path(value["repository"]).is_absolute() or
            type(value["schema_version"]) is not int or value["schema_version"] != 1 or
            any(type(value[key]) is not int or value[key] < 1
                for key in ("audit_count", "sources", "passages", "files")) or
            value["files"] != value["sources"] +
            (7 if value["schema"] == 3 else 5)):
        raise VesselRecoveryError("invalid vessel recovery receipt fields")
    if value["schema"] == 3:
        identity = value["identity"]
        if (not isinstance(identity, dict) or
                set(identity) != {"issuer", "ca_sha256", "revocations_sha256"} or
                any(not isinstance(item, str) for item in identity.values()) or
                not _ID.fullmatch(identity["ca_sha256"]) or
                not _ID.fullmatch(identity["revocations_sha256"])):
            raise VesselRecoveryError("invalid vessel recovery identity receipt")
        try:
            validate_keycloak_issuer(identity["issuer"], allow_https=True)
        except ValueError as exc:
            raise VesselRecoveryError("invalid vessel recovery issuer") from exc
        if not identity["issuer"].startswith("https://"):
            raise VesselRecoveryError("vessel recovery issuer must use HTTPS")
    try:
        timestamp = datetime.fromisoformat(value["created_utc"])
    except (TypeError, ValueError) as exc:
        raise VesselRecoveryError("invalid vessel recovery timestamp") from exc
    if timestamp.tzinfo is None:
        raise VesselRecoveryError("vessel recovery timestamp lacks timezone")
    return value


def _sign_receipt(path: Path, payload: dict[str, object], signing_key: Path) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise VesselRecoveryError("recovery receipt destination is not new")
    key = serialization.load_pem_private_key(_private_bytes(signing_key, 4096),
                                              password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VesselRecoveryError("vessel receipt key is not Ed25519")
    raw = _canonical(payload)
    envelope = {"schema": 1, "payload": base64.b64encode(raw).decode(),
                "signature": base64.b64encode(key.sign(raw)).decode()}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(envelope))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def create_vessel_recovery_set(root: Path, trusted_key: Path, crane: Path,
                               repository: Path, password_file: Path,
                               restic: Path, restic_sha256: str,
                               staging_parent: Path, signing_key: Path,
                               receipt: Path) -> dict[str, object]:
    """Capture Core and PostgreSQL at one stopped, locked synthetic point."""
    _owner_directory(root)
    _owner_directory(staging_parent)
    _owner_directory(receipt.parent)
    if (not receipt.is_absolute() or receipt.exists() or receipt.is_symlink()
            or not repository.is_absolute() or repository.is_symlink()
            or repository.resolve().is_relative_to(root.resolve())
            or staging_parent.resolve().is_relative_to(root.resolve())
            or receipt.parent.resolve().is_relative_to(root.resolve())
            or repository.resolve().is_relative_to(staging_parent.resolve())
            or staging_parent.resolve().is_relative_to(repository.resolve())):
        raise VesselRecoveryError("vessel recovery paths must be separate")
    with _operation_lock(root):
        record = _read_state(root)
        release = record["active"]
        stage = root / "vessel-releases" / release
        _verify_stage(stage, trusted_key, release)
        state, lab_password, identity = _record_inputs(
            record, root, stage / "console-config.json")
        _state_options(state, lab_password, root, identity=identity)
        for candidate in (repository, staging_parent, receipt.parent):
            if (candidate.resolve().is_relative_to(state.resolve()) or
                    state.resolve().is_relative_to(candidate.resolve())):
                raise VesselRecoveryError("recovery path overlaps Core state")
        runtime = record["runtime"]
        installation_id = record["installation_id"]
        _recovery_inventory(installation_id, runtime)
        with policy_directory_lock(state / "roles.json", exclusive=True):
            with tempfile.TemporaryDirectory(prefix=".vessel-recovery-",
                                             dir=staging_parent) as temporary:
                frozen = Path(temporary) / "frozen"
                sources, checkpoint, manifest_digest = _stage_core(
                    state, frozen, oidc=identity is not None)
                knowledge = None
                try:
                    knowledge = start_signed_knowledge(
                        stage / "bundle", trusted_key, crane, root,
                        installation_id, initialize=False)
                    _verify_knowledge_schema(knowledge)
                    database = _verify_database(stage / "bundle", trusted_key,
                                                crane, knowledge, frozen, root)
                    _dump(knowledge.container_id, frozen / "postgres.dump")
                    if _verify_database(stage / "bundle", trusted_key,
                                        crane, knowledge, frozen, root) != database:
                        raise VesselRecoveryError("Knowledge changed during capture")
                finally:
                    if knowledge is not None:
                        stop_knowledge(knowledge)
                _recovery_inventory(installation_id, runtime)
                entries = ["roles.json", "approved.json", "audit.jsonl",
                           "history.db", "postgres.dump"]
                if identity is not None:
                    # The encrypted snapshot excludes .pem names as a
                    # key-custody guard. This file is a public CA certificate,
                    # mapped back to the Core path only after verified restore.
                    entries.extend(("oidc-ca.crt", "oidc-revocations.jsonl"))
                entries.extend(item.relative_to(frozen).as_posix()
                               for item in (frozen / "sources").rglob("*")
                               if item.is_file())
                spec = frozen / "snapshot-spec.json"
                spec.write_text(json.dumps({"schema": 1, "files": [
                    {"name": name, "kind": "file",
                     "source": "oidc-ca.pem" if name == "oidc-ca.crt" else name}
                    for name in entries]}))
                snapshot = create_snapshot(spec, repository, password_file,
                                           restic, restic_sha256, staging_parent)
                if (read_manifest_bytes(state / "approved.json") !=
                        (frozen / "approved.json").read_bytes() or
                        read_policy_bytes(state / "roles.json") !=
                        (frozen / "roles.json").read_bytes() or
                        verify_audit(state / "audit.jsonl", require_current_clock=True)
                        != checkpoint):
                    raise VesselRecoveryError("Core state changed during recovery capture")
                if identity is not None and validated_identity_material(
                        identity.ca_file, identity.revocations_file) != (
                            (frozen / "oidc-ca.pem").read_bytes(),
                            (frozen / "oidc-revocations.jsonl").read_bytes()):
                    raise VesselRecoveryError("OIDC material changed during recovery capture")
                _recovery_inventory(installation_id, runtime)
                receipt_fields = {
                    "schema": 3 if identity is not None else 2,
                    "installation_id": installation_id,
                    "release": release, "data_volume": runtime["data_volume"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "repository": str(repository.resolve()),
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "schema_version": 1, "audit_count": checkpoint[0],
                    "audit_tail_hash": checkpoint[1],
                    "manifest_sha256": manifest_digest,
                    "dump_sha256": _sha256(frozen / "postgres.dump"),
                    "knowledge_sha256": database["knowledge_sha256"],
                    "sources": sources, "passages": database["passages"],
                    "files": snapshot["files"],
                }
                if identity is not None:
                    receipt_fields["identity"] = {
                        "issuer": identity.issuer,
                        "ca_sha256": _sha256(frozen / "oidc-ca.pem"),
                        "revocations_sha256": _sha256(frozen / "oidc-revocations.jsonl"),
                    }
                payload = _receipt_payload(receipt_fields)
                _sign_receipt(receipt, payload, signing_key)
                return payload


def verify_vessel_recovery_receipt(receipt: Path, trusted_key: Path) -> dict[str, object]:
    """Verify the exact signed restic snapshot identity and capture checkpoint."""
    try:
        envelope = json.loads(_private_bytes(receipt, 8192), object_pairs_hook=_unique)
        if (not isinstance(envelope, dict) or set(envelope) !=
                {"schema", "payload", "signature"} or
                type(envelope["schema"]) is not int or envelope["schema"] != 1):
            raise VesselRecoveryError("invalid vessel recovery envelope")
        raw = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(raw) > 4096 or len(signature) != 64:
            raise VesselRecoveryError("invalid vessel recovery signature size")
        key = serialization.load_pem_public_key(trusted_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise VesselRecoveryError("vessel recovery trust key is not Ed25519")
        key.verify(signature, raw)
        value = json.loads(raw, object_pairs_hook=_unique)
        if raw != _canonical(value):
            raise VesselRecoveryError("noncanonical vessel recovery receipt")
        return _receipt_payload(value)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            InvalidSignature) as exc:
        raise VesselRecoveryError("vessel recovery receipt verification failed") from exc


def restore_vessel_recovery_files(receipt: Path, receipt_key: Path,
                                  password_file: Path, restic: Path,
                                  restic_sha256: str, destination: Path) -> dict[str, object]:
    """Clean-restore and validate the signed Core files and PostgreSQL dump."""
    value = verify_vessel_recovery_receipt(receipt, receipt_key)
    restored = restore_snapshot(value["snapshot_id"], Path(value["repository"]),
                                password_file, restic, restic_sha256, destination)
    try:
        if value["schema"] == 3:
            certificate = destination / "oidc-ca.crt"
            core_certificate = destination / "oidc-ca.pem"
            if os.path.lexists(core_certificate):
                raise VesselRecoveryError("unexpected vessel identity trust file")
            certificate.rename(core_certificate)
        with tempfile.TemporaryDirectory(prefix=".verify-vessel-recovery-",
                                         dir=destination.parent) as temporary:
            sources, checkpoint, manifest_digest = _stage_core(
                destination, Path(temporary) / "frozen",
                oidc=value["schema"] == 3)
        with (destination / "postgres.dump").open("rb") as archive:
            header = archive.read(5)
        if (restored["files"] != value["files"] or sources != value["sources"] or
                checkpoint != (value["audit_count"], value["audit_tail_hash"]) or
                manifest_digest != value["manifest_sha256"] or
                _sha256(destination / "postgres.dump") != value["dump_sha256"] or
                header != b"PGDMP"):
            raise VesselRecoveryError("restored vessel recovery set differs from receipt")
        if value["schema"] == 3 and (
                _sha256(destination / "oidc-ca.pem") != value["identity"]["ca_sha256"] or
                _sha256(destination / "oidc-revocations.jsonl") !=
                value["identity"]["revocations_sha256"]):
            raise VesselRecoveryError("restored vessel identity differs from receipt")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return {"result": "files-restored-and-verified",
            "snapshot_id": value["snapshot_id"], "sources": sources,
            "audit_count": checkpoint[0]}


def _grant_restored_knowledge(container_id: str) -> None:
    """Recreate the table boundary after pg_restore omits owners and ACLs."""
    tables = ("knowledge_sources", "knowledge_passages", "knowledge_quarantine",
              "knowledge_vectors", "knowledge_schema_version")
    actual = postgres_sql(container_id,
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
    if actual.splitlines() != sorted(tables):
        raise VesselRecoveryError("restored Knowledge table inventory changed")
    for table in tables:
        postgres_sql(container_id,
                     f"ALTER TABLE public.{table} OWNER TO sovereign_migrate")
    postgres_sql(container_id,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON "
        "public.knowledge_sources, public.knowledge_passages, "
        "public.knowledge_quarantine, public.knowledge_vectors TO sovereign_ingest")
    postgres_sql(container_id,
        "GRANT SELECT ON public.knowledge_sources, public.knowledge_passages, "
        "public.knowledge_quarantine, public.knowledge_vectors, "
        "public.knowledge_schema_version TO sovereign_read")
    verify_security(container_id)
    rights = postgres_sql(container_id,
        "SELECT has_table_privilege('sovereign_read','public.knowledge_sources','SELECT')::int"
        " || ':' || has_table_privilege('sovereign_read','public.knowledge_sources','INSERT')::int"
        " || ':' || has_table_privilege('sovereign_ingest','public.knowledge_sources','INSERT')::int"
        " || ':' || has_table_privilege('sovereign_ingest','public.knowledge_schema_version','UPDATE')::int")
    if rights != "1:0:1:0":
        raise VesselRecoveryError("restored Knowledge role boundary changed")


def _verify_activation_identity_pair(
        oidc: bool, receipt: Path, receipt_key: Path, staging_parent: Path,
        pair: Path | None, pair_key: Path | None,
        archive: Path | None, archive_key: Path | None) -> str | None:
    """Require a matching signed realm export before starting an OIDC restore."""
    artifacts = (pair, pair_key, archive, archive_key)
    if not oidc:
        if any(item is not None for item in artifacts):
            raise VesselRecoveryError("lab restore cannot accept identity pair")
        return None
    if any(item is None for item in artifacts):
        raise VesselRecoveryError("OIDC restore requires signed identity pair and archive")
    pair_digest = hashlib.sha256(_private_bytes(pair, 8192)).hexdigest()
    # Import here to avoid a module cycle with the receipt verifier.
    from infrastructure.deploy.vessel_identity_recovery import restore_paired_realm
    with tempfile.TemporaryDirectory(prefix=".verify-identity-pair-",
                                     dir=staging_parent) as temporary:
        restore_paired_realm(pair, pair_key, receipt, receipt_key,
                             archive, archive_key, Path(temporary) / "realm")
    if hashlib.sha256(_private_bytes(pair, 8192)).hexdigest() != pair_digest:
        raise VesselRecoveryError("identity pair changed during verification")
    return pair_digest


def activate_vessel_recovery_set(bundle: Path, trusted_key: Path, crane: Path,
                                 console_config: Path, receipt: Path,
                                 receipt_key: Path, password_file: Path,
                                 restic: Path, restic_sha256: str,
                                 root: Path, core_state: Path,
                                 lab_password: Path | None,
                                 staging_parent: Path,
                                 *, identity_network: str | None = None,
                                 identity_pair: Path | None = None,
                                 identity_pair_key: Path | None = None,
                                 identity_archive: Path | None = None,
                                 identity_archive_key: Path | None = None
                                 ) -> dict[str, object]:
    """Activate a clean synthetic host only after signed, restricted restore."""
    _owner_directory(root.parent)
    _owner_directory(core_state.parent)
    _owner_directory(staging_parent)
    value = verify_vessel_recovery_receipt(receipt, receipt_key)
    manifest = verify_bundle(bundle, trusted_key)
    require_supported_vessel_compatibility(manifest)
    if _release_id(bundle, console_config) != value["release"]:
        raise VesselRecoveryError("recovery release differs from signed receipt")
    oidc = value["schema"] == 3
    if (oidc and (lab_password is not None or identity_network is None)) or \
            (not oidc and (lab_password is None or identity_network is not None)):
        raise VesselRecoveryError("clean restore identity mode differs from receipt")
    issuer = _validate_console_config(console_config, allow_oidc=True)
    if issuer != (value["identity"]["issuer"] if oidc else None):
        raise VesselRecoveryError("clean restore Console issuer differs from receipt")
    if (not root.is_absolute() or root.exists() or root.is_symlink()
            or not core_state.is_absolute() or core_state.exists()
            or core_state.is_symlink() or
            root.resolve().is_relative_to(core_state.resolve()) or
            core_state.resolve().is_relative_to(root.resolve()) or
            staging_parent.resolve().is_relative_to(root.resolve()) or
            staging_parent.resolve().is_relative_to(core_state.resolve())):
        raise VesselRecoveryError("clean recovery requires separate new directories")
    repository = Path(value["repository"])
    if any(candidate.resolve().is_relative_to(repository.resolve()) or
           repository.resolve().is_relative_to(candidate.resolve())
           for candidate in (root, core_state, staging_parent)):
        raise VesselRecoveryError("clean recovery paths overlap encrypted repository")
    if lab_password is not None:
        lab_secret = _private_bytes(lab_password, 4096).decode("utf-8")
        if (not 16 <= len(lab_secret.rstrip("\n")) <= 200 or
                "\r" in lab_secret or "\n" in lab_secret.rstrip("\n")):
            raise VesselRecoveryError("invalid clean recovery lab credential")
    pair_digest = _verify_activation_identity_pair(
        oidc, receipt, receipt_key, staging_parent, identity_pair,
        identity_pair_key, identity_archive, identity_archive_key)
    services: RuntimeHandle | None = None
    knowledge: KnowledgeVolumeHandle | None = None
    installation_id = value["installation_id"]
    data_volume = value["data_volume"]
    restore_attempt = secrets.token_hex(16)
    _assert_missing("volume", data_volume)
    scope = f"label=sovereign.synthetic.install={installation_id}"
    if (_docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("network", "ls", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("volume", "ls", "--filter", scope, "--quiet")):
        raise VesselRecoveryError("installation identity already has Docker resources")
    with tempfile.TemporaryDirectory(prefix=".vessel-activate-",
                                     dir=staging_parent) as temporary:
        restored = Path(temporary) / "restored"
        restore_vessel_recovery_files(receipt, receipt_key, password_file,
                                      restic, restic_sha256, restored)
        root.mkdir(mode=0o700)
        try:
            release, stage = _stage(root, bundle, trusted_key, console_config)
            if release != value["release"]:
                raise VesselRecoveryError("staged recovery release changed")
            core_state.mkdir(mode=0o700)
            shutil.copytree(restored / "sources", core_state / "sources")
            for name in ("roles.json", "approved.json", "audit.jsonl", "history.db"):
                shutil.copy2(restored / name, core_state / name, follow_symlinks=False)
            identity = None
            if oidc:
                for name in ("oidc-ca.pem", "oidc-revocations.jsonl"):
                    shutil.copy2(restored / name, core_state / name,
                                 follow_symlinks=False)
                identity = preflight_vessel_identity(
                    stage / "console-config.json", core_state, identity_network)
                if (_sha256(identity.ca_file) != value["identity"]["ca_sha256"] or
                        _sha256(identity.revocations_file) !=
                        value["identity"]["revocations_sha256"]):
                    raise VesselRecoveryError("restored identity differs from signed receipt")
            marker = {
                "schema": 2, "snapshot_id": value["snapshot_id"],
                "release": release, "installation_id": installation_id,
                "restore_attempt": restore_attempt}
            if pair_digest is not None:
                marker["identity_pair_sha256"] = pair_digest
            _write_private_record(root, "vessel-restore-intent.json", marker)
            _write_intent(root, release, installation_id, core_state, lab_password,
                          identity=identity)
            knowledge = start_signed_knowledge(stage / "bundle", trusted_key,
                                               crane, root, installation_id,
                                               initialize=True,
                                               restore_attempt=restore_attempt)
            _state_options(core_state, lab_password, root, identity=identity)
            _restore(knowledge.container_id, restored / "postgres.dump")
            _grant_restored_knowledge(knowledge.container_id)
            _verify_knowledge_schema(knowledge)
            database = _verify_database(stage / "bundle", trusted_key, crane,
                                        knowledge, core_state, root)
            if (database["sources"] != value["sources"] or
                    database["passages"] != value["passages"] or
                    (value["schema"] in (2, 3) and
                     database["knowledge_sha256"] != value["knowledge_sha256"])):
                raise VesselRecoveryError("restored Knowledge differs from receipt")
            services = start_signed_vessel_services(
                stage / "bundle", trusted_key, crane, stage / "console-config.json",
                core_state, lab_password, root, knowledge, installation_id,
                restore_attempt=restore_attempt, identity=identity)
            _write_state(root, _state_payload(release, installation_id,
                                               core_state, lab_password,
                                               services, knowledge,
                                               identity=identity))
            (root / "vessel-restore-intent.json").unlink()
            (root / "vessel-intent.json").unlink(missing_ok=True)
            return {"result": "restored-and-activated", "active": release,
                    "installation_id": installation_id,
                    "sources": database["sources"],
                    "passages": database["passages"],
                    "audit_count": value["audit_count"]}
        except Exception as exc:
            (root / "vessel-state.json").unlink(missing_ok=True)
            if knowledge is None:
                if (_docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
                        _docker("network", "ls", "--no-trunc", "--filter", scope, "--quiet") or
                        _docker("volume", "ls", "--filter", scope, "--quiet")):
                    raise VesselRecoveryError(
                        "recovery activation failed before ownership; private state retained"
                    ) from exc
                shutil.rmtree(root)
                shutil.rmtree(core_state, ignore_errors=True)
                raise
            if not _cleanup_failed_install(installation_id, services, knowledge,
                                           data_volume):
                raise VesselRecoveryError(
                    "recovery activation failed; cleanup incomplete; private state retained"
                ) from exc
            shutil.rmtree(root)
            shutil.rmtree(core_state, ignore_errors=True)
            raise


def _read_restore_intent(root: Path) -> dict[str, object]:
    path = root / "vessel-restore-intent.json"
    try:
        value = json.loads(_private_bytes(path, 4096), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise VesselRecoveryError("invalid vessel restore intent") from exc
    if (not isinstance(value, dict) or
            set(value) not in ({"schema", "snapshot_id", "release", "installation_id",
                                "restore_attempt"},
                               {"schema", "snapshot_id", "release", "installation_id",
                                "restore_attempt", "identity_pair_sha256"}) or
            type(value["schema"]) is not int or value["schema"] != 2 or
            not isinstance(value["snapshot_id"], str) or
            not _ID.fullmatch(value["snapshot_id"]) or
            not isinstance(value["release"], str) or
            not _RELEASE.fullmatch(value["release"]) or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["restore_attempt"], str) or
            not _INSTALL.fullmatch(value["restore_attempt"]) or
            ("identity_pair_sha256" in value and
             (not isinstance(value["identity_pair_sha256"], str) or
              not _ID.fullmatch(value["identity_pair_sha256"])))):
        raise VesselRecoveryError("invalid vessel restore intent fields")
    return value


def _partial_knowledge_resources(installation_id: str, data_volume: str,
                                 restore_attempt: str,
                                 containers: list[str], networks: list[str],
                                 volumes: list[str]) -> str | None:
    """Identify one interrupted Knowledge run before discarding its resources."""
    if networks or len(containers) > 1:
        raise VesselRecoveryError("partial restore has unexpected Docker resources")
    sockets = [name for name in volumes if name != data_volume]
    if (len(sockets) > 1 or any(not re.fullmatch(
            r"sovereign-knowledge-[0-9a-f]{12}-socket", name)
            for name in sockets)):
        raise VesselRecoveryError("partial restore has unexpected Docker resources")
    if data_volume in volumes:
        _volume(data_volume, installation_id, "knowledge-data", create=False,
                restore_attempt=restore_attempt)
    run_name = sockets[0].removesuffix("-socket") if sockets else None
    if run_name is not None:
        _volume(sockets[0], installation_id, "knowledge-socket", create=False,
                run_name=run_name, restore_attempt=restore_attempt)
    if containers:
        if run_name is None or data_volume not in volumes:
            raise VesselRecoveryError("partial Knowledge container lacks its volumes")
        container = containers[0]
        try:
            labels = json.loads(_docker("inspect", container, "--format",
                                        "{{json .Config.Labels}}"))
            mounts = json.loads(_docker("inspect", container, "--format",
                                        "{{json .Mounts}}"))
        except json.JSONDecodeError as exc:
            raise VesselRecoveryError("invalid partial Knowledge metadata") from exc
        if (not isinstance(labels, dict) or
                labels.get("sovereign.synthetic.install") != installation_id or
                labels.get("sovereign.synthetic.role") != "knowledge" or
                labels.get("sovereign.synthetic.run") != run_name or
                labels.get("sovereign.synthetic.restore_attempt") != restore_attempt or
                _docker("inspect", container, "--format", "{{.Name}}") !=
                f"/{run_name}" or
                _docker("inspect", container, "--format",
                        "{{.HostConfig.NetworkMode}}") != "none" or
                _docker("inspect", container, "--format",
                        "{{json .HostConfig.PortBindings}}") not in ("null", "{}") or
                not isinstance(mounts, list) or
                any(sum(isinstance(item, dict) and
                        item.get("Destination") == destination and
                        item.get("Type") == "volume" and
                        item.get("Name") == volume for item in mounts) != 1
                    for destination, volume in
                    (("/var/lib/postgresql/data", data_volume),
                     ("/var/run/postgresql", sockets[0])))):
            raise VesselRecoveryError("partial Knowledge container identity mismatch")
        return container
    return None


def _match_restored_core(state: Path, restored: Path) -> None:
    """Require the interrupted Core copy to equal the authenticated snapshot."""
    _owner_directory(state)
    def inventory(root: Path, *, snapshot: bool) -> dict[str, Path]:
        found: dict[str, Path] = {}
        for item in root.rglob("*"):
            name = item.relative_to(root).as_posix()
            # Restore verifies these receipt-bound artifacts, but the normal
            # activation copies neither into the running Core state.
            if snapshot and name in ("postgres.dump", "sovereign-snapshot-manifest.json"):
                continue
            if len(found) >= 1024:
                raise VesselRecoveryError("partial Core inventory is oversized")
            found[name] = item
        return found

    expected = inventory(restored, snapshot=True)
    actual = inventory(state, snapshot=False)
    if set(actual) != set(expected):
        raise VesselRecoveryError("partial Core inventory differs from recovery snapshot")
    for name, item in actual.items():
        source = expected[name]
        details = item.lstat()
        if (item.is_symlink() or details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) !=
                stat.S_IMODE(source.lstat().st_mode) or
                item.is_dir() != source.is_dir() or
                (item.is_file() and details.st_nlink != 1) or
                not (item.is_dir() or item.is_file())):
            raise VesselRecoveryError("partial Core metadata differs from recovery snapshot")
        if item.is_file() and (details.st_size != source.stat().st_size or
                               _sha256(item) != _sha256(source)):
            raise VesselRecoveryError("partial Core bytes differ from recovery snapshot")


def finish_incomplete_vessel_restore(root: Path, trusted_key: Path, crane: Path,
                                     receipt: Path, receipt_key: Path,
                                     password_file: Path, restic: Path,
                                     restic_sha256: str,
                                     staging_parent: Path,
                                     *, identity_pair: Path | None = None,
                                     identity_pair_key: Path | None = None,
                                     identity_archive: Path | None = None,
                                     identity_archive_key: Path | None = None
                                     ) -> dict[str, object]:
    """Finish only a fully restored, receipt-matched Knowledge candidate."""
    _owner_directory(staging_parent)
    with _operation_lock(root):
        marker = _read_restore_intent(root)
        intent = _read_intent(root)
        value = verify_vessel_recovery_receipt(receipt, receipt_key)
        if value["schema"] not in (2, 3):
            raise VesselRecoveryError("finishing restore requires row-digest receipt")
        if (marker["snapshot_id"] != value["snapshot_id"] or
                marker["release"] != value["release"] or
                marker["installation_id"] != value["installation_id"] or
                intent["release"] != value["release"] or
                intent["installation_id"] != value["installation_id"] or
                intent["data_volume"] != value["data_volume"] or
                intent["schema"] != (2 if value["schema"] == 3 else 1)):
            raise VesselRecoveryError("restore intent differs from signed receipt")
        pair_digest = _verify_activation_identity_pair(
            value["schema"] == 3, receipt, receipt_key, staging_parent,
            identity_pair, identity_pair_key, identity_archive,
            identity_archive_key)
        if marker.get("identity_pair_sha256") != pair_digest:
            raise VesselRecoveryError("restore intent differs from signed identity pair")
        if ((root / "vessel-state.json").exists() or
                (root / "vessel-state.json").is_symlink() or
                (root / "vessel-restore-abandoned.json").exists() or
                (root / "vessel-restore-abandoned.json").is_symlink()):
            raise VesselRecoveryError("restore is active or abandoned")
        state = Path(intent["core_state"])
        if (state.resolve().is_relative_to(root.resolve()) or
                root.resolve().is_relative_to(state.resolve()) or
                staging_parent.resolve().is_relative_to(root.resolve()) or
                staging_parent.resolve().is_relative_to(state.resolve())):
            raise VesselRecoveryError("restore paths overlap")
        repository = Path(value["repository"])
        if any(path.resolve().is_relative_to(repository.resolve()) or
               repository.resolve().is_relative_to(path.resolve())
               for path in (root, state, staging_parent)):
            raise VesselRecoveryError("restore paths overlap encrypted repository")
        stage = root / "vessel-releases" / value["release"]
        _verify_stage(stage, trusted_key, value["release"])
        scope = f"label=sovereign.synthetic.install={value['installation_id']}"
        containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                                  "--quiet")
        networks = _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                                "--quiet")
        volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                               volume=True)
        container = _partial_knowledge_resources(
            value["installation_id"], value["data_volume"],
            marker["restore_attempt"], containers, networks, volumes)
        sockets = [name for name in volumes if name != value["data_volume"]]
        if container is None or len(sockets) != 1:
            raise VesselRecoveryError("completed Knowledge runtime is absent")
        knowledge = KnowledgeVolumeHandle(
            container, sockets[0], value["data_volume"],
            sockets[0].removesuffix("-socket"), value["installation_id"])
        probe_knowledge(knowledge)
        with tempfile.TemporaryDirectory(prefix=".finish-vessel-restore-",
                                         dir=staging_parent) as temporary:
            restored = Path(temporary) / "restored"
            restore_vessel_recovery_files(receipt, receipt_key, password_file,
                                          restic, restic_sha256, restored)
            _match_restored_core(state, restored)
            state, lab_password, identity = _record_inputs(
                intent, root, stage / "console-config.json")
            if identity is not None and (
                    identity.issuer != value["identity"]["issuer"] or
                    _sha256(identity.ca_file) != value["identity"]["ca_sha256"] or
                    _sha256(identity.revocations_file) !=
                    value["identity"]["revocations_sha256"]):
                raise VesselRecoveryError("partial identity differs from signed receipt")
            _state_options(state, lab_password, root, identity=identity)
            _verify_knowledge_schema(knowledge)
            database = _verify_database(stage / "bundle", trusted_key, crane,
                                        knowledge, state, root)
            if (database["sources"] != value["sources"] or
                    database["passages"] != value["passages"] or
                    database["knowledge_sha256"] != value["knowledge_sha256"]):
                raise VesselRecoveryError("restored Knowledge differs from receipt")
        if (_read_restore_intent(root) != marker or _read_intent(root) != intent or
                _scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                             "--quiet") != containers or
                _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                             "--quiet") or
                set(_scoped_list("volume", "ls", "--filter", scope, "--quiet",
                                 volume=True)) != set(volumes)):
            raise VesselRecoveryError("partial restore changed during verification")
        _verify_stage(stage, trusted_key, value["release"])
        probe_knowledge(knowledge)
        services: RuntimeHandle | None = None
        try:
            services = start_signed_vessel_services(
                stage / "bundle", trusted_key, crane, stage / "console-config.json",
                state, lab_password, root, knowledge, value["installation_id"],
                restore_attempt=marker["restore_attempt"], identity=identity)
            _write_state(root, _state_payload(
                value["release"], value["installation_id"], state, lab_password,
                services, knowledge, identity=identity))
        except Exception:
            try:
                (root / "vessel-state.json").unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise VesselRecoveryError(
                    "finish failed; active record could not be cleared; runtime retained"
                ) from cleanup_error
            if services is not None:
                try:
                    stop_runtime(services)
                except Exception as cleanup_error:
                    raise VesselRecoveryError(
                        "finish failed; service cleanup incomplete"
                    ) from cleanup_error
            raise
        for name in ("vessel-restore-intent.json", "vessel-intent.json"):
            try:
                (root / name).unlink(missing_ok=True)
            except OSError:
                pass
        return {"result": "restored-and-activated", "active": value["release"],
                "installation_id": value["installation_id"],
                "sources": database["sources"], "passages": database["passages"],
                "audit_count": value["audit_count"],
                "recovered_attempt": marker["restore_attempt"]}


def abandon_incomplete_vessel_restore(root: Path, trusted_key: Path,
                                      receipt: Path, receipt_key: Path,
                                      *, discard_partial_data: bool) -> dict[str, str]:
    """Discard only a checked partial synthetic volume; retain private evidence."""
    if discard_partial_data is not True:
        raise VesselRecoveryError("partial restore discard requires explicit flag")
    with _operation_lock(root):
        marker = _read_restore_intent(root)
        intent = _read_intent(root)
        value = verify_vessel_recovery_receipt(receipt, receipt_key)
        if (marker["snapshot_id"] != value["snapshot_id"] or
                marker["release"] != value["release"] or
                marker["installation_id"] != value["installation_id"] or
                intent["release"] != value["release"] or
                intent["installation_id"] != value["installation_id"] or
                intent["data_volume"] != value["data_volume"] or
                intent["schema"] != (2 if value["schema"] == 3 else 1)):
            raise VesselRecoveryError("restore intent differs from signed receipt")
        _verify_stage(root / "vessel-releases" / value["release"],
                      trusted_key, value["release"])
        active = root / "vessel-state.json"
        if active.exists() or active.is_symlink():
            raise VesselRecoveryError("active vessel cannot be abandoned")
        abandoned = root / "vessel-restore-abandoned.json"
        if abandoned.exists() or abandoned.is_symlink():
            raise VesselRecoveryError("restore was already abandoned")
        state = Path(intent["core_state"])
        _owner_directory(state)
        if state.resolve().is_relative_to(root.resolve()):
            raise VesselRecoveryError("partial Core state overlaps installation")
        scope = f"label=sovereign.synthetic.install={value['installation_id']}"
        containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                                  "--quiet")
        networks = _scoped_list("network", "ls", "--no-trunc", "--filter",
                                scope, "--quiet")
        volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                               volume=True)
        if networks or len(containers) > 1:
            if value["data_volume"] not in volumes:
                raise VesselRecoveryError("partial runtime lacks Knowledge data volume")
            _volume(value["data_volume"], value["installation_id"],
                    "knowledge-data", create=False,
                    restore_attempt=marker["restore_attempt"])
            _remove_scoped_orphans(
                value["installation_id"], value["data_volume"],
                lambda: _read_restore_intent(root) == marker and
                _read_intent(root) == intent and
                not active.exists() and not active.is_symlink() and
                set(_scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                                 "--quiet")) == set(containers) and
                set(_scoped_list("network", "ls", "--no-trunc", "--filter",
                                 scope, "--quiet")) == set(networks) and
                set(_scoped_list("volume", "ls", "--filter", scope, "--quiet",
                                 volume=True)) == set(volumes),
                restore_attempt=marker["restore_attempt"])
            volumes = [value["data_volume"]]
            container = None
        else:
            container = _partial_knowledge_resources(
                value["installation_id"], value["data_volume"],
                marker["restore_attempt"], containers, networks, volumes)
        if (_read_restore_intent(root) != marker or _read_intent(root) != intent):
            raise VesselRecoveryError("partial restore intent changed")
        if container is not None:
            _docker("rm", "-f", container)
        for name in volumes:
            if name != value["data_volume"]:
                _volume(name, value["installation_id"], "knowledge-socket",
                        create=False, run_name=name.removesuffix("-socket"),
                        restore_attempt=marker["restore_attempt"])
                _docker("volume", "rm", name)
        if volumes:
            if value["data_volume"] in volumes:
                _volume(value["data_volume"], value["installation_id"],
                        "knowledge-data", create=False,
                        restore_attempt=marker["restore_attempt"])
                _docker("volume", "rm", value["data_volume"])
        _assert_missing("volume", value["data_volume"])
        if (_scoped_list("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
                _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                             "--quiet") or
                _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                             volume=True)):
            raise VesselRecoveryError("partial restore cleanup is incomplete")
        _write_private_record(root, "vessel-restore-abandoned.json", {
            "schema": 1, "snapshot_id": value["snapshot_id"],
            "installation_id": value["installation_id"],
            "restore_attempt": marker["restore_attempt"],
            "discarded_utc": datetime.now(timezone.utc).isoformat()})
        return {"result": "abandoned", "data_volume": "removed",
                "snapshot_id": value["snapshot_id"]}


def _read_abandoned_restore(root: Path) -> dict[str, object]:
    try:
        value = json.loads(_private_bytes(root / "vessel-restore-abandoned.json",
                                          4096), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise VesselRecoveryError("invalid abandoned restore record") from exc
    if (not isinstance(value, dict) or
            set(value) != {"schema", "snapshot_id", "installation_id",
                           "restore_attempt", "discarded_utc"} or
            type(value["schema"]) is not int or value["schema"] != 1 or
            any(not isinstance(value[key], str) or not pattern.fullmatch(value[key])
                for key, pattern in (("snapshot_id", _ID),
                                     ("installation_id", _INSTALL),
                                     ("restore_attempt", _INSTALL)))):
        raise VesselRecoveryError("invalid abandoned restore fields")
    try:
        discarded = datetime.fromisoformat(value["discarded_utc"])
    except (TypeError, ValueError) as exc:
        raise VesselRecoveryError("invalid abandoned restore timestamp") from exc
    if discarded.tzinfo is None or discarded > datetime.now(timezone.utc):
        raise VesselRecoveryError("abandoned restore timestamp is ahead of local clock")
    return value


def retry_abandoned_vessel_restore(abandoned_root: Path, bundle: Path,
                                   trusted_key: Path, crane: Path,
                                   console_config: Path, receipt: Path,
                                   receipt_key: Path, password_file: Path,
                                   restic: Path, restic_sha256: str,
                                   root: Path, core_state: Path,
                                   lab_password: Path | None,
                                   staging_parent: Path,
                                   *, identity_network: str | None = None,
                                   identity_pair: Path | None = None,
                                   identity_pair_key: Path | None = None,
                                   identity_archive: Path | None = None,
                                   identity_archive_key: Path | None = None
                                   ) -> dict[str, object]:
    """Retry a terminal abandoned attempt into entirely new private paths."""
    with _operation_lock(abandoned_root):
        marker = _read_restore_intent(abandoned_root)
        abandoned = _read_abandoned_restore(abandoned_root)
        intent = _read_intent(abandoned_root)
        value = verify_vessel_recovery_receipt(receipt, receipt_key)
        if (marker["snapshot_id"] != abandoned["snapshot_id"] or
                marker["snapshot_id"] != value["snapshot_id"] or
                marker["installation_id"] != abandoned["installation_id"] or
                marker["installation_id"] != value["installation_id"] or
                marker["restore_attempt"] != abandoned["restore_attempt"] or
                marker["release"] != value["release"] or
                intent["release"] != value["release"] or
                intent["installation_id"] != value["installation_id"] or
                intent["data_volume"] != value["data_volume"] or
                intent["schema"] != (2 if value["schema"] == 3 else 1)):
            raise VesselRecoveryError("abandoned attempt differs from signed receipt")
        _verify_stage(abandoned_root / "vessel-releases" / value["release"],
                      trusted_key, value["release"])
        active = abandoned_root / "vessel-state.json"
        if active.exists() or active.is_symlink():
            raise VesselRecoveryError("abandoned root became active")
        old_state = Path(intent["core_state"])
        _owner_directory(old_state)
        for candidate in (root, core_state):
            if (candidate.resolve().is_relative_to(abandoned_root.resolve()) or
                    abandoned_root.resolve().is_relative_to(candidate.resolve()) or
                    candidate.resolve().is_relative_to(old_state.resolve()) or
                    old_state.resolve().is_relative_to(candidate.resolve())):
                raise VesselRecoveryError("retry paths overlap abandoned evidence")
        result = activate_vessel_recovery_set(
            bundle, trusted_key, crane, console_config, receipt, receipt_key,
            password_file, restic, restic_sha256, root, core_state,
            lab_password, staging_parent, identity_network=identity_network,
            identity_pair=identity_pair, identity_pair_key=identity_pair_key,
            identity_archive=identity_archive,
            identity_archive_key=identity_archive_key)
        return {**result, "retry_of_attempt": marker["restore_attempt"]}
