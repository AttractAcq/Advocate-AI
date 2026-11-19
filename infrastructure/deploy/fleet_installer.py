"""Stage, activate, roll back and recover signed synthetic Fleet releases."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from cryptography import x509

from infrastructure.deploy.fleet_runtime import (
    FleetRuntime, RuntimeError as FleetRuntimeError, _import_trust, probe_runtime,
    start_verified_bundle, stop_runtime, validate_config, validate_state,
    verify_runtime_identity,
)
from infrastructure.deploy.fleet_backup import restore_fleet
from infrastructure.release.bundle import BundleError, MANIFEST, verify_bundle


class FleetInstallError(ValueError):
    """The Fleet installation or its checked state is invalid."""


_RELEASE = re.compile(r"[0-9a-f]{24}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _owner_directory(path: Path, *, create: bool = False) -> None:
    if not path.is_absolute() or path.is_symlink() or (path.exists() and not path.is_dir()):
        raise FleetInstallError("invalid Fleet installation directory")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (not path.is_dir() or path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise FleetInstallError("Fleet installation directory must be owner-only")


@contextmanager
def _lock(root: Path):
    descriptor = os.open(root / ".fleet-install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                         0o600)
    try:
        if os.fstat(descriptor).st_mode & 0o077:
            raise FleetInstallError("Fleet install lock must be owner-only")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FleetInstallError("duplicate Fleet state key")
        value[key] = item
    return value


def _state(root: Path) -> dict[str, object] | None:
    _owner_directory(root)
    path = root / "fleet-state.json"
    if path.is_symlink():
        raise FleetInstallError("linked Fleet state")
    if not path.exists():
        return None
    if (not path.is_file() or path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077 or path.stat().st_size > 4096):
        raise FleetInstallError("invalid Fleet state")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise FleetInstallError("invalid Fleet state JSON") from exc
    if (not isinstance(value, dict) or set(value) != {"schema", "active", "previous", "runtime"}
            or value["schema"] != 1 or type(value["schema"]) is not int
            or not isinstance(value["active"], str) or not _RELEASE.fullmatch(value["active"])
            or (value["previous"] is not None and
                (not isinstance(value["previous"], str) or
                 not _RELEASE.fullmatch(value["previous"])))
            or not isinstance(value["runtime"], dict)
            or set(value["runtime"]) not in (
                {"network_id", "api_id", "portal_id"},
                {"network_id", "api_id", "portal_id",
                 "identity_network_id", "identity_network_name"})
            or any(not isinstance(value["runtime"].get(key), str) or
                   not _DOCKER_ID.fullmatch(value["runtime"][key])
                   for key in ("network_id", "api_id", "portal_id"))
            or ("identity_network_id" in value["runtime"] and
                ((value["runtime"]["identity_network_id"] is None) !=
                 (value["runtime"]["identity_network_name"] is None) or
                 (value["runtime"]["identity_network_id"] is not None and
                  (not isinstance(value["runtime"]["identity_network_id"], str) or
                   not _DOCKER_ID.fullmatch(value["runtime"]["identity_network_id"]) or
                   not isinstance(value["runtime"]["identity_network_name"], str)))))):
        raise FleetInstallError("invalid Fleet state fields")
    return value


def _handle(value: dict[str, object]) -> FleetRuntime:
    return FleetRuntime(**value["runtime"])


def _write_state(root: Path, active: str, previous: str | None,
                 handle: FleetRuntime) -> None:
    payload = {"schema": 1, "active": active, "previous": previous,
               "runtime": {"network_id": handle.network_id, "api_id": handle.api_id,
                           "portal_id": handle.portal_id,
                           "identity_network_id": handle.identity_network_id,
                           "identity_network_name": handle.identity_network_name}}
    descriptor, filename = tempfile.mkstemp(prefix=".fleet-state-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, root / "fleet-state.json")
    finally:
        Path(filename).unlink(missing_ok=True)


def _identifier(bundle: Path, config: Path) -> str:
    return hashlib.sha256((bundle / MANIFEST).read_bytes() +
                          b"\x00" + config.read_bytes()).hexdigest()[:24]


def _verify_stage(stage: Path, trusted_key: Path, identifier: str) -> None:
    if (stage.is_symlink() or not stage.is_dir() or
            {item.name for item in stage.iterdir()} != {"bundle", "fleet-config.json"}):
        raise FleetInstallError("invalid staged Fleet release")
    manifest = verify_bundle(stage / "bundle", trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise FleetInstallError("staged release is not a Fleet bundle")
    config = stage / "fleet-config.json"
    validate_config(config)
    if _identifier(stage / "bundle", config) != identifier:
        raise FleetInstallError("staged Fleet release identity mismatch")


def _stage(root: Path, bundle: Path, config: Path,
           trusted_key: Path) -> tuple[str, Path]:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise FleetInstallError("Fleet installer requires a signed Fleet bundle")
    validate_config(config)
    releases = root / "fleet-releases"
    _owner_directory(releases, create=True)
    identifier = _identifier(bundle, config)
    target = releases / identifier
    if target.exists() or target.is_symlink():
        _verify_stage(target, trusted_key, identifier)
        return identifier, target
    temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
    try:
        shutil.copytree(bundle, temporary / "bundle", symlinks=True)
        copied_config = temporary / "fleet-config.json"
        copied_config.write_bytes(config.read_bytes())
        copied_config.chmod(0o644)
        _verify_stage(temporary, trusted_key, identifier)
        os.rename(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return identifier, target


def _provision_identity(root: Path, issuer: str | None,
                        token_file: Path | None, roles_file: Path | None,
                        ca_file: Path | None = None) -> None:
    state = root / "state"
    _owner_directory(state, create=True)
    target = state / "token"
    identity = root / "identity"
    if issuer is None:
        if (roles_file is not None or ca_file is not None or
                identity.exists() or identity.is_symlink()):
            raise FleetInstallError("lab Fleet cannot contain OIDC roles")
    elif token_file is not None or target.exists() or target.is_symlink():
        raise FleetInstallError("OIDC Fleet cannot contain a lab token")
    if token_file is not None:
        if target.exists() or target.is_symlink() or token_file.is_symlink() or \
                not token_file.is_absolute() or not token_file.is_file() or \
                token_file.stat().st_uid != os.getuid() or \
                stat.S_IMODE(token_file.stat().st_mode) & 0o077:
            raise FleetInstallError("invalid Fleet token source")
        data = token_file.read_bytes()
        if not 32 <= len(data.strip()) <= 200 or b"\n" in data.strip():
            raise FleetInstallError("invalid Fleet token")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    if ca_file is not None and roles_file is None:
        raise FleetInstallError("Fleet OIDC CA is provisioned with initial roles")
    if issuer is not None and roles_file is not None:
        if (identity.exists() or identity.is_symlink() or
                not roles_file.is_absolute() or roles_file.is_symlink()):
            raise FleetInstallError("invalid Fleet OIDC roles source")
        source_descriptor = os.open(roles_file, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            source_stat = os.fstat(source_descriptor)
            if (not stat.S_ISREG(source_stat.st_mode) or
                    source_stat.st_uid != os.getuid() or
                    stat.S_IMODE(source_stat.st_mode) & 0o077 or
                    source_stat.st_size > 1024 * 1024):
                raise FleetInstallError("invalid Fleet OIDC roles source")
            with os.fdopen(source_descriptor, "rb", closefd=False) as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise FleetInstallError("Fleet OIDC roles source is too large")
        finally:
            os.close(source_descriptor)
        identity.mkdir(mode=0o700)
        try:
            descriptor = os.open(identity / "roles.json",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if ca_file is not None:
                if not ca_file.is_absolute() or ca_file.is_symlink():
                    raise FleetInstallError("invalid Fleet OIDC CA source")
                ca_descriptor = os.open(ca_file, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    ca_stat = os.fstat(ca_descriptor)
                    if (not stat.S_ISREG(ca_stat.st_mode) or
                            ca_stat.st_uid != os.getuid() or
                            stat.S_IMODE(ca_stat.st_mode) & 0o077 or
                            ca_stat.st_size > 64 * 1024):
                        raise FleetInstallError("invalid Fleet OIDC CA source")
                    with os.fdopen(ca_descriptor, "rb", closefd=False) as source:
                        ca_data = source.read(64 * 1024 + 1)
                    if len(ca_data) > 64 * 1024:
                        raise FleetInstallError("Fleet OIDC CA source is too large")
                finally:
                    os.close(ca_descriptor)
                ca_target = identity / "ca.pem"
                ca_output = os.open(ca_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                    os.O_NOFOLLOW, 0o600)
                with os.fdopen(ca_output, "wb") as stream:
                    stream.write(ca_data)
                    stream.flush()
                    os.fsync(stream.fileno())
        except Exception:
            shutil.rmtree(identity)
            raise
    validate_state(state, issuer)


def _provision_receipt_trust(root: Path, source: Path | None) -> None:
    if source is None:
        return
    target = root / "receipt-import"
    if (target.exists() or target.is_symlink() or not source.is_absolute() or
            source.is_symlink() or not source.is_dir() or
            source.stat().st_uid != os.getuid() or
            stat.S_IMODE(source.stat().st_mode) & 0o077):
        raise FleetInstallError("invalid or already provisioned Fleet receipt trust")
    try:
        shutil.copytree(source, target, symlinks=True)
        _import_trust(root / "state")
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def _activate(root: Path, identifier: str, stage: Path,
              trusted_key: Path, crane: Path,
              identity_network: str | None = None) -> dict[str, object]:
    current = _state(root)
    if current is not None:
        if _handle(current).identity_network_name != identity_network:
            raise FleetInstallError("Fleet identity network cannot change during update")
        old_stage = root / "fleet-releases" / str(current["active"])
        _verify_stage(old_stage, trusted_key, str(current["active"]))
        probe_runtime(_handle(current), old_stage / "bundle", trusted_key,
                      root / "state", old_stage / "fleet-config.json")
        if current["active"] == identifier:
            return {"result": "unchanged", "active": identifier,
                    "previous": current["previous"]}
    _verify_stage(stage, trusted_key, identifier)
    candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                      stage / "fleet-config.json", root / "state",
                                      identity_network)
    try:
        _write_state(root, identifier, str(current["active"]) if current else None,
                     candidate)
    except Exception:
        stop_runtime(candidate)
        raise
    if current is not None:
        stop_runtime(_handle(current))
    return {"result": "activated", "active": identifier,
            "previous": current["active"] if current else None}


def install_fleet(bundle: Path, trusted_key: Path, crane: Path,
                  config: Path, root: Path,
                  token_file: Path | None = None,
                  roles_file: Path | None = None,
                  identity_network: str | None = None,
                  ca_file: Path | None = None,
                  receipt_trust_dir: Path | None = None) -> dict[str, object]:
    _owner_directory(root, create=True)
    with _lock(root):
        if _read_ca_journal(root) is not None:
            raise FleetInstallError("recover interrupted Fleet CA rotation first")
        issuer = validate_config(config)
        current = _state(root)
        if issuer is not None and identity_network is None and current is not None:
            identity_network = _handle(current).identity_network_name
        if (issuer is None) != (identity_network is None):
            raise FleetInstallError("Fleet identity mode requires matching network")
        _provision_receipt_trust(root, receipt_trust_dir)
        _provision_identity(root, issuer, token_file, roles_file, ca_file)
        identifier, stage = _stage(root, bundle, config, trusted_key)
        return _activate(root, identifier, stage, trusted_key, crane, identity_network)


def restore_install_fleet(bundle: Path, trusted_key: Path, crane: Path,
                          config: Path, root: Path, token_file: Path | None,
                          archive: Path, backup_key: Path,
                          roles_file: Path | None = None,
                          identity_network: str | None = None,
                          ca_file: Path | None = None,
                          receipt_trust_dir: Path | None = None) -> dict[str, object]:
    """Clean-restore the audited Fleet database before signed activation."""
    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise FleetInstallError("Fleet restore-install requires a new absolute root")
    _owner_directory(root.parent)
    root.mkdir(mode=0o700)
    try:
        restored = restore_fleet(archive, backup_key, root / "state")
        installed = install_fleet(bundle, trusted_key, crane, config, root,
                                  token_file, roles_file, identity_network, ca_file,
                                  receipt_trust_dir)
        return {**installed, "restored_files": restored["files"]}
    except Exception:
        if not (root / "fleet-state.json").exists() and not root.is_symlink():
            shutil.rmtree(root)
        raise


def fleet_status(root: Path, trusted_key: Path) -> dict[str, object]:
    if _read_ca_journal(root) is not None:
        raise FleetInstallError("Fleet CA rotation is pending recovery")
    current = _state(root)
    if current is None:
        raise FleetInstallError("no active Fleet release")
    identifier = str(current["active"])
    stage = root / "fleet-releases" / identifier
    _verify_stage(stage, trusted_key, identifier)
    probe_runtime(_handle(current), stage / "bundle", trusted_key,
                  root / "state", stage / "fleet-config.json")
    return {"result": "healthy", "active": identifier,
            "previous": current["previous"]}


def _validate_ca_bundle(data: bytes) -> None:
    try:
        certificates = x509.load_pem_x509_certificates(data)
        now = datetime.now(timezone.utc)
        if not certificates or any(
                not certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints).value.ca or
                certificate.not_valid_before_utc > now or
                certificate.not_valid_after_utc <= now
                for certificate in certificates):
            raise FleetInstallError("Fleet CA bundle must contain valid CA certificates")
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise FleetInstallError("invalid Fleet CA bundle") from exc


def _read_ca_source(source: Path) -> bytes:
    if not source.is_absolute() or source.is_symlink():
        raise FleetInstallError("invalid Fleet CA source")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) & 0o077 or
                not 1 <= details.st_size <= 64 * 1024):
            raise FleetInstallError("Fleet CA source must be an owner-only regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(64 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(data) > 64 * 1024:
        raise FleetInstallError("Fleet CA source is too large")
    _validate_ca_bundle(data)
    return data


def _private_temp(directory: Path, prefix: str, data: bytes) -> Path:
    descriptor, filename = tempfile.mkstemp(prefix=prefix, dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        Path(filename).unlink(missing_ok=True)
        raise
    return Path(filename)


def _ca_journal(root: Path) -> Path:
    return root / "identity" / ".ca-rotation.json"


def _write_ca_journal(root: Path, current: dict[str, object], old_ca: bytes) -> Path:
    journal = _ca_journal(root)
    payload = json.dumps({"schema": 1, "old_state": current,
                          "old_ca": old_ca.decode("ascii")},
                         sort_keys=True, separators=(",", ":")).encode()
    descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        journal.unlink(missing_ok=True)
        raise
    return journal


def _read_ca_journal(root: Path) -> dict[str, object] | None:
    journal = _ca_journal(root)
    if not journal.exists() and not journal.is_symlink():
        return None
    if (journal.is_symlink() or not journal.is_file() or
            journal.stat().st_uid != os.getuid() or
            stat.S_IMODE(journal.stat().st_mode) & 0o077 or
            journal.stat().st_size > 128 * 1024):
        raise FleetInstallError("invalid Fleet CA rotation journal")
    try:
        value = json.loads(journal.read_bytes(), object_pairs_hook=_unique)
        if (not isinstance(value, dict) or set(value) != {"schema", "old_state", "old_ca"}
                or value["schema"] != 1 or not isinstance(value["old_state"], dict)
                or not isinstance(value["old_ca"], str)):
            raise ValueError("invalid rotation journal fields")
        old = value["old_state"]
        runtime = old.get("runtime")
        if (set(old) != {"schema", "active", "previous", "runtime"} or
                old["schema"] != 1 or not isinstance(old["active"], str) or
                not _RELEASE.fullmatch(old["active"]) or
                (old["previous"] is not None and
                 (not isinstance(old["previous"], str) or
                  not _RELEASE.fullmatch(old["previous"]))) or
                not isinstance(runtime, dict) or
                set(runtime) != {"network_id", "api_id", "portal_id",
                                 "identity_network_id", "identity_network_name"} or
                any(not isinstance(runtime.get(key), str) or
                    not _DOCKER_ID.fullmatch(runtime[key])
                    for key in ("network_id", "api_id", "portal_id",
                                "identity_network_id")) or
                not isinstance(runtime.get("identity_network_name"), str)):
            raise ValueError("invalid rotation journal state")
        _validate_ca_bundle(value["old_ca"].encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise FleetInstallError("invalid Fleet CA rotation journal") from exc
    return value


def rotate_fleet_ca(root: Path, trusted_key: Path, crane: Path,
                    ca_file: Path) -> dict[str, object]:
    """Start a signed candidate with staged CA trust; retain the old runtime on failure."""
    _owner_directory(root)
    with _lock(root):
        if _read_ca_journal(root) is not None:
            raise FleetInstallError("recover interrupted Fleet CA rotation first")
        current = _state(root)
        if current is None:
            raise FleetInstallError("no active Fleet release")
        identifier = str(current["active"])
        stage = root / "fleet-releases" / identifier
        _verify_stage(stage, trusted_key, identifier)
        if validate_config(stage / "fleet-config.json") is None:
            raise FleetInstallError("Fleet CA rotation requires OIDC mode")
        identity = root / "identity"
        _owner_directory(identity)
        old_ca = identity / "ca.pem"
        previous = _read_ca_source(old_ca)
        replacement = _read_ca_source(ca_file)
        handle = _handle(current)
        probe_runtime(handle, stage / "bundle", trusted_key,
                      root / "state", stage / "fleet-config.json")
        staged = _private_temp(identity, ".ca-next-", replacement)
        try:
            journal = _write_ca_journal(root, current, previous)
            try:
                os.replace(staged, old_ca)
            except Exception:
                journal.unlink()
                raise
            try:
                candidate = start_verified_bundle(
                    stage / "bundle", trusted_key, crane,
                    stage / "fleet-config.json", root / "state",
                    handle.identity_network_name)
                try:
                    _write_state(root, identifier, current["previous"], candidate)
                except Exception:
                    stop_runtime(candidate)
                    raise
            except Exception:
                fallback = _private_temp(identity, ".ca-restore-", previous)
                os.replace(fallback, old_ca)
                journal.unlink()
                raise
        finally:
            staged.unlink(missing_ok=True)
        journal.unlink()
        stop_runtime(handle)
        return {"result": "identity_rotated", "active": identifier,
                "previous": current["previous"]}


def _reconcile_ca_rotation(root: Path, trusted_key: Path) -> None:
    pending = _read_ca_journal(root)
    if pending is None:
        return
    current = _state(root)
    old = pending["old_state"]
    if current is None or not isinstance(old, dict) or current["active"] != old.get("active"):
        raise FleetInstallError("Fleet CA rotation journal does not match active release")
    identity = root / "identity"
    _owner_directory(identity)
    target = identity / "ca.pem"
    old_runtime = _handle(old)
    current_runtime = _handle(current)
    if current_runtime.api_id == old_runtime.api_id:
        restored = _private_temp(identity, ".ca-recovery-",
                                 pending["old_ca"].encode("ascii"))
        os.replace(restored, target)
    else:
        stage = root / "fleet-releases" / str(current["active"])
        _verify_stage(stage, trusted_key, str(current["active"]))
        probe_runtime(current_runtime, stage / "bundle", trusted_key,
                      root / "state", stage / "fleet-config.json")
        stop_runtime(old_runtime)
    _ca_journal(root).unlink()


def rollback_fleet(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    _owner_directory(root)
    with _lock(root):
        if _read_ca_journal(root) is not None:
            raise FleetInstallError("recover interrupted Fleet CA rotation first")
        current = _state(root)
        if current is None or current["previous"] is None:
            raise FleetInstallError("no previous Fleet release")
        identifier = str(current["previous"])
        stage = root / "fleet-releases" / identifier
        return _activate(root, identifier, stage, trusted_key, crane,
                         _handle(current).identity_network_name)


def recover_fleet(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    _owner_directory(root)
    with _lock(root):
        _reconcile_ca_rotation(root, trusted_key)
        current = _state(root)
        if current is None:
            raise FleetInstallError("no active Fleet release")
        identifier = str(current["active"])
        stage = root / "fleet-releases" / identifier
        _verify_stage(stage, trusted_key, identifier)
        try:
            probe_runtime(_handle(current), stage / "bundle", trusted_key,
                          root / "state", stage / "fleet-config.json")
        except FleetRuntimeError:
            pass
        else:
            return {"result": "already_healthy", "active": identifier,
                    "previous": current["previous"]}
        try:
            verify_runtime_identity(_handle(current), stage / "bundle", trusted_key,
                                    root / "state", stage / "fleet-config.json")
        except FleetRuntimeError:
            old_owned = False
        else:
            old_owned = True
        candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                          stage / "fleet-config.json", root / "state",
                                          _handle(current).identity_network_name)
        try:
            _write_state(root, identifier, current["previous"], candidate)
        except Exception:
            stop_runtime(candidate)
            raise
        if old_owned:
            stop_runtime(_handle(current))
        return {"result": "recovered", "active": identifier,
                "previous": current["previous"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic signed Fleet installer")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "restore-install", "status", "rollback", "recover",
                 "rotate-ca"):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True, type=Path)
        command.add_argument("--trusted-key", required=True, type=Path)
        if name != "status":
            command.add_argument("--crane", required=True, type=Path)
        if name in ("install", "restore-install"):
            command.add_argument("--bundle", required=True, type=Path)
            command.add_argument("--config", required=True, type=Path)
            command.add_argument("--token-file", type=Path)
            command.add_argument("--roles-file", type=Path)
            command.add_argument("--identity-network")
            command.add_argument("--ca-file", type=Path)
            command.add_argument("--receipt-trust-dir", type=Path)
        if name == "restore-install":
            command.add_argument("--archive", required=True, type=Path)
            command.add_argument("--backup-key", required=True, type=Path)
        if name == "rotate-ca":
            command.add_argument("--ca-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "install":
            result = install_fleet(args.bundle, args.trusted_key, args.crane,
                                   args.config, args.root, args.token_file,
                                   args.roles_file, args.identity_network, args.ca_file,
                                   args.receipt_trust_dir)
        elif args.command == "restore-install":
            if (args.token_file is None) == (args.roles_file is None):
                raise FleetInstallError("Fleet restore-install requires one identity source")
            result = restore_install_fleet(args.bundle, args.trusted_key, args.crane,
                                           args.config, args.root, args.token_file,
                                           args.archive, args.backup_key,
                                           args.roles_file, args.identity_network, args.ca_file,
                                           args.receipt_trust_dir)
        elif args.command == "status":
            result = fleet_status(args.root, args.trusted_key)
        elif args.command == "rotate-ca":
            result = rotate_fleet_ca(args.root, args.trusted_key,
                                     args.crane, args.ca_file)
        elif args.command == "rollback":
            result = rollback_fleet(args.root, args.trusted_key, args.crane)
        else:
            result = recover_fleet(args.root, args.trusted_key, args.crane)
    except (BundleError, FleetInstallError, FleetRuntimeError, OSError,
            ValueError) as exc:
        parser.exit(1, f"Fleet install: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
