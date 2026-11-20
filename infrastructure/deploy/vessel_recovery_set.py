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
import shutil
import sqlite3
import stat
import subprocess
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from infrastructure.deploy.container_runtime import _image_id
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, _credentials, start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.vessel_installer import (
    _assert_missing, _cleanup_failed_install, _operation_lock, _owner_directory, _read_state,
    _recovery_inventory, _release_id, _stage, _state_payload, _verify_knowledge_schema,
    _verify_stage, _write_intent, _write_state,
)
from infrastructure.deploy.postgres_socket import sql as postgres_sql, verify_security
from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.container_runtime import _docker
from infrastructure.deploy.vessel_runtime import start_signed_vessel_services
from infrastructure.deploy.vessel_runtime import _state_options
from infrastructure.release.bundle import verify_bundle
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
            or not 0 < path.stat().st_size <= maximum):
        raise VesselRecoveryError("unsafe private recovery file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o077
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
            actual.add(item.relative_to(state).as_posix())
    if actual != listed:
        raise VesselRecoveryError("vessel source inventory differs from approved manifest")


def _history_copy(source: Path, target: Path) -> None:
    if (source.is_symlink() or not source.is_file() or
            source.stat().st_uid != os.getuid() or
            stat.S_IMODE(source.stat().st_mode) & 0o077 or
            not 0 < source.stat().st_size <= _MAX_HISTORY):
        raise VesselRecoveryError("invalid vessel conversation database")
    try:
        with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as original:
            if original.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                raise VesselRecoveryError("conversation database integrity failed")
            with closing(sqlite3.connect(target)) as copy:
                original.backup(copy)
                if copy.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                    raise VesselRecoveryError("conversation snapshot integrity failed")
    except sqlite3.DatabaseError as exc:
        raise VesselRecoveryError("conversation database snapshot failed") from exc
    target.chmod(0o600)


def _stage_core(state: Path, frozen: Path) -> tuple[int, tuple[int, str], str]:
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
    checkpoint = verify_audit(audit_path, require_current_clock=True)
    if checkpoint[0] < 1:
        raise VesselRecoveryError("vessel audit trail has no checkpoint")
    sources: set[str] = set()
    frozen.mkdir(mode=0o700)
    for item in manifest["sources"]:
        if not isinstance(item, dict):
            raise VesselRecoveryError("invalid vessel recovery source")
        relative = item.get("relative_path")
        if not isinstance(relative, str) or not relative.startswith("sources/") or \
                relative in sources:
            raise VesselRecoveryError("invalid vessel recovery source path")
        _, _, payload = _valid_source(state, item)
        sources.add(relative)
        destination = frozen / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    _source_inventory(state, sources)
    for name, payload in (("approved.json", approved), ("roles.json", roles),
                          ("audit.jsonl", audit)):
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
    return len(sources), checkpoint, hashlib.sha256(approved).hexdigest()


def _verify_database(bundle: Path, trusted_key: Path, crane: Path,
                     knowledge: KnowledgeVolumeHandle, frozen: Path,
                     secrets_root: Path) -> dict[str, int]:
    manifest = verify_bundle(bundle, trusted_key)
    image = _image_id(bundle, "core", manifest["images"]["core"], crane)
    _, _, reader, _, _ = _credentials(secrets_root, initialize=False)
    program = """\
import json
from pathlib import Path
from services.knowledge.postgres_index import verify_knowledge_snapshot
root=Path('/var/lib/sovereign')
result=verify_knowledge_snapshot(root,root/'approved.json',
 'postgresql://sovereign_read@/postgres?host=/run/postgresql')
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
    if (not isinstance(value, dict) or set(value) != {"sources", "passages"}
            or any(type(number) is not int or number < 1 for number in value.values())):
        raise VesselRecoveryError("invalid signed Knowledge snapshot result")
    return value


def _receipt_payload(value: object) -> dict[str, object]:
    expected = {"schema", "installation_id", "release", "data_volume",
                "snapshot_id", "repository", "created_utc", "schema_version",
                "audit_count", "audit_tail_hash", "manifest_sha256",
                "dump_sha256", "sources", "passages", "files"}
    if (not isinstance(value, dict) or set(value) != expected or
            type(value["schema"]) is not int or value["schema"] != 1 or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["release"], str) or
            not _RELEASE.fullmatch(value["release"]) or
            value["data_volume"] !=
            f"sovereign-{value['installation_id']}-knowledge-data" or
            any(not isinstance(value[key], str) or not _ID.fullmatch(value[key])
                for key in ("snapshot_id", "audit_tail_hash", "manifest_sha256",
                            "dump_sha256")) or
            not isinstance(value["repository"], str) or
            not Path(value["repository"]).is_absolute() or
            type(value["schema_version"]) is not int or value["schema_version"] != 1 or
            any(type(value[key]) is not int or value[key] < 1
                for key in ("audit_count", "sources", "passages", "files")) or
            value["files"] != value["sources"] + 5):
        raise VesselRecoveryError("invalid vessel recovery receipt fields")
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
        state, lab_password = Path(record["core_state"]), Path(record["lab_password_file"])
        _state_options(state, lab_password, root)
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
                sources, checkpoint, manifest_digest = _stage_core(state, frozen)
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
                entries.extend(item.relative_to(frozen).as_posix()
                               for item in (frozen / "sources").rglob("*")
                               if item.is_file())
                spec = frozen / "snapshot-spec.json"
                spec.write_text(json.dumps({"schema": 1, "files": [
                    {"name": name, "kind": "file", "source": name} for name in entries]}))
                snapshot = create_snapshot(spec, repository, password_file,
                                           restic, restic_sha256, staging_parent)
                if (read_manifest_bytes(state / "approved.json") !=
                        (frozen / "approved.json").read_bytes() or
                        read_policy_bytes(state / "roles.json") !=
                        (frozen / "roles.json").read_bytes() or
                        verify_audit(state / "audit.jsonl", require_current_clock=True)
                        != checkpoint):
                    raise VesselRecoveryError("Core state changed during recovery capture")
                _recovery_inventory(installation_id, runtime)
                payload = _receipt_payload({
                    "schema": 1, "installation_id": installation_id,
                    "release": release, "data_volume": runtime["data_volume"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "repository": str(repository.resolve()),
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "schema_version": 1, "audit_count": checkpoint[0],
                    "audit_tail_hash": checkpoint[1],
                    "manifest_sha256": manifest_digest,
                    "dump_sha256": _sha256(frozen / "postgres.dump"),
                    "sources": sources, "passages": database["passages"],
                    "files": snapshot["files"],
                })
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
        with tempfile.TemporaryDirectory(prefix=".verify-vessel-recovery-",
                                         dir=destination.parent) as temporary:
            sources, checkpoint, manifest_digest = _stage_core(
                destination, Path(temporary) / "frozen")
        with (destination / "postgres.dump").open("rb") as archive:
            header = archive.read(5)
        if (restored["files"] != value["files"] or sources != value["sources"] or
                checkpoint != (value["audit_count"], value["audit_tail_hash"]) or
                manifest_digest != value["manifest_sha256"] or
                _sha256(destination / "postgres.dump") != value["dump_sha256"] or
                header != b"PGDMP"):
            raise VesselRecoveryError("restored vessel recovery set differs from receipt")
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


def activate_vessel_recovery_set(bundle: Path, trusted_key: Path, crane: Path,
                                 console_config: Path, receipt: Path,
                                 receipt_key: Path, password_file: Path,
                                 restic: Path, restic_sha256: str,
                                 root: Path, core_state: Path,
                                 lab_password: Path,
                                 staging_parent: Path) -> dict[str, object]:
    """Activate a clean synthetic host only after signed, restricted restore."""
    _owner_directory(root.parent)
    _owner_directory(core_state.parent)
    _owner_directory(staging_parent)
    value = verify_vessel_recovery_receipt(receipt, receipt_key)
    manifest = verify_bundle(bundle, trusted_key)
    if (manifest.get("schema") != 6 or manifest.get("target") != "vessel"
            or _release_id(bundle, console_config) != value["release"]):
        raise VesselRecoveryError("recovery release differs from signed receipt")
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
    lab_secret = _private_bytes(lab_password, 4096).decode("utf-8")
    if (not 16 <= len(lab_secret.rstrip("\n")) <= 200 or
            "\r" in lab_secret or "\n" in lab_secret.rstrip("\n")):
        raise VesselRecoveryError("invalid clean recovery lab credential")
    services: RuntimeHandle | None = None
    knowledge: KnowledgeVolumeHandle | None = None
    installation_id = value["installation_id"]
    data_volume = value["data_volume"]
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
            _write_intent(root, release, installation_id, core_state, lab_password)
            knowledge = start_signed_knowledge(stage / "bundle", trusted_key,
                                               crane, root, installation_id,
                                               initialize=True)
            _state_options(core_state, lab_password, root)
            _restore(knowledge.container_id, restored / "postgres.dump")
            _grant_restored_knowledge(knowledge.container_id)
            _verify_knowledge_schema(knowledge)
            database = _verify_database(stage / "bundle", trusted_key, crane,
                                        knowledge, core_state, root)
            if database != {"sources": value["sources"],
                            "passages": value["passages"]}:
                raise VesselRecoveryError("restored Knowledge differs from receipt")
            services = start_signed_vessel_services(
                stage / "bundle", trusted_key, crane, stage / "console-config.json",
                core_state, lab_password, root, knowledge, installation_id)
            _write_state(root, _state_payload(release, installation_id,
                                               core_state, lab_password,
                                               services, knowledge))
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
