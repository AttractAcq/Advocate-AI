"""Owner-only synthetic product staging with checked runtime activation.

This is a local lab installer. It does not configure host boot, TLS, identity,
model storage, firewall policy, or vessel services.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from infrastructure.deploy.container_runtime import (
    RuntimeError as ContainerRuntimeError, RuntimeHandle, _validate_console_config,
    _core_state_options, cleanup_orphan_runtimes, probe_runtime, start_verified_bundle, stop_runtime,
    verify_runtime_identity,
)
from infrastructure.release.bundle import BundleError, verify_bundle
from infrastructure.restic_repository import restore_snapshot


class ProductInstallError(ValueError):
    """The staged product or installer state is invalid."""


_RELEASE = re.compile(r"[0-9a-f]{24}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
_INSTALL_ID = re.compile(r"[0-9a-f]{32}\Z")


@contextmanager
def _lock(root: Path):
    path = root / ".product-install.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_mode & 0o077:
            raise ProductInstallError("installer lock must be owner-only")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _owner_directory(path: Path, *, create: bool) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ProductInstallError("invalid installation directory")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (not path.is_dir() or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & 0o077):
        raise ProductInstallError("installation directory must be owner-only")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProductInstallError("duplicate state key")
        result[key] = value
    return result


def _state(root: Path) -> dict[str, object] | None:
    _owner_directory(root, create=False)
    path = root / "product-state.json"
    if path.is_symlink():
        raise ProductInstallError("linked installation state")
    if not path.exists():
        return None
    if (not path.is_file() or path.stat().st_uid != os.getuid()
            or path.stat().st_size > 4096 or path.stat().st_mode & 0o077):
        raise ProductInstallError("invalid installation state")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise ProductInstallError("invalid installation state JSON") from exc
    if (not isinstance(value, dict) or set(value) != {"schema", "active", "previous", "runtime"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["active"], str) or not _RELEASE.fullmatch(value["active"])
            or (value["previous"] is not None and
                (not isinstance(value["previous"], str) or
                 not _RELEASE.fullmatch(value["previous"])))
            or not isinstance(value["runtime"], dict)
            or set(value["runtime"]) != {"network_id", "core_id", "console_id"}
            or any(not isinstance(item, str) or not _DOCKER_ID.fullmatch(item)
                   for item in value["runtime"].values())):
        raise ProductInstallError("invalid installation state fields")
    return value


def _handle(state: dict[str, object]) -> RuntimeHandle:
    runtime = state["runtime"]
    return RuntimeHandle(runtime["network_id"], runtime["core_id"], runtime["console_id"])


def _installation_id(root: Path) -> str:
    path = root / "installation-id"
    if path.is_symlink():
        raise ProductInstallError("linked installation identifier")
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_hex(16) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    if (not path.is_file() or path.stat().st_mode & 0o077
            or path.stat().st_size != 33):
        raise ProductInstallError("invalid installation identifier file")
    value = path.read_text(encoding="ascii").strip()
    if not _INSTALL_ID.fullmatch(value):
        raise ProductInstallError("invalid installation identifier")
    return value


def _mount_config(root: Path) -> tuple[Path | None, Path | None, Path | None]:
    """Read the owner-only path record; credentials remain outside this file."""
    path = root / "product-core-mount.json"
    if path.is_symlink():
        raise ProductInstallError("linked Core mount record")
    if not path.exists():
        return None, None, None
    if (not path.is_file() or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 4096):
        raise ProductInstallError("invalid Core mount record")
    try:
        record = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise ProductInstallError("invalid Core mount record JSON") from exc
    if (not isinstance(record, dict) or type(record.get("schema")) is not int
            or record["schema"] not in (1, 2)
            or set(record) != ({"schema", "state", "credential"} if record["schema"] == 1
                               else {"schema", "state", "credential", "emergency_credential"})
            or not isinstance(record["state"], str)
            or not isinstance(record["credential"], str)
            or (record["schema"] == 2 and
                not isinstance(record["emergency_credential"], str))):
        raise ProductInstallError("invalid Core mount record fields")
    state, credential = Path(record["state"]), Path(record["credential"])
    emergency = (Path(record["emergency_credential"])
                 if record["schema"] == 2 else None)
    try:
        _core_state_options(state, credential, emergency)
    except ContainerRuntimeError as exc:
        raise ProductInstallError("Core mount record no longer resolves safely") from exc
    return state, credential, emergency


def _configure_mount(root: Path, state: Path | None,
                     credential: Path | None,
                     emergency: Path | None = None) -> tuple[Path | None, Path | None, Path | None]:
    """Pin external lab state paths for every future release and restart."""
    existing = _mount_config(root)
    if state is None and credential is None and emergency is None:
        return existing
    try:
        _core_state_options(state, credential, emergency)
    except ContainerRuntimeError as exc:
        raise ProductInstallError("invalid Core mount paths") from exc
    canonical = state.resolve(), credential.resolve(), (emergency.resolve() if emergency else None)
    if existing != (None, None, None):
        if existing != canonical:
            raise ProductInstallError("Core mount paths cannot change during install")
        return existing
    if _state(root) is not None:
        raise ProductInstallError("cannot attach Core state to an active installation")
    path = root / "product-core-mount.json"
    descriptor, filename = tempfile.mkstemp(prefix=".product-core-mount-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            record = {"schema": 2 if emergency else 1, "state": str(canonical[0]),
                      "credential": str(canonical[1])}
            if emergency:
                record["emergency_credential"] = str(canonical[2])
            stream.write(json.dumps(record,
                                    sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)
    return canonical


def _identifier(bundle: Path, config: Path) -> str:
    return hashlib.sha256((bundle / "release-manifest.json").read_bytes() +
                          b"\x00" + config.read_bytes()).hexdigest()[:24]


def _stage(root: Path, bundle: Path, config: Path, trusted_key: Path) -> tuple[str, Path]:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest["schema"] != 4:
        raise BundleError("product installer requires a two-image bundle")
    _validate_console_config(config)
    releases = root / "product-releases"
    _owner_directory(releases, create=True)
    identifier = _identifier(bundle, config)
    target = releases / identifier
    if target.exists() or target.is_symlink():
        _verify_stage(target, trusted_key, identifier)
        return identifier, target
    temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
    try:
        shutil.copytree(bundle, temporary / "bundle", symlinks=True)
        (temporary / "console-config.json").write_bytes(config.read_bytes())
        _verify_stage(temporary, trusted_key, identifier)
        os.rename(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return identifier, target


def _verify_stage(stage: Path, trusted_key: Path, identifier: str) -> None:
    if (stage.is_symlink() or not stage.is_dir() or
            {item.name for item in stage.iterdir()} != {"bundle", "console-config.json"}):
        raise ProductInstallError("invalid staged product release")
    manifest = verify_bundle(stage / "bundle", trusted_key)
    if manifest["schema"] != 4:
        raise ProductInstallError("staged release is not a product bundle")
    config = stage / "console-config.json"
    _validate_console_config(config)
    if _identifier(stage / "bundle", config) != identifier:
        raise ProductInstallError("staged release identity mismatch")


def _write_state(root: Path, active: str, previous: str | None,
                 handle: RuntimeHandle) -> None:
    payload = {"schema": 1, "active": active, "previous": previous,
               "runtime": {"network_id": handle.network_id, "core_id": handle.core_id,
                           "console_id": handle.console_id}}
    descriptor, filename = tempfile.mkstemp(prefix=".product-state-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, root / "product-state.json")
    finally:
        Path(filename).unlink(missing_ok=True)


def _activate(root: Path, stage: Path, identifier: str,
              trusted_key: Path, crane: Path) -> dict[str, object]:
    core_state, lab_password_file, emergency_password_file = _mount_config(root)
    current = _state(root)
    if current is not None:
        _verify_stage(root / "product-releases" / str(current["active"]),
                      trusted_key, str(current["active"]))
        probe_runtime(_handle(current), core_state, lab_password_file,
                      emergency_password_file)
        if current["active"] == identifier:
            return {"result": "unchanged", "active": identifier,
                    "previous": current["previous"]}
    _verify_stage(stage, trusted_key, identifier)
    candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                      stage / "console-config.json",
                                      installation_id=_installation_id(root),
                                      core_state=core_state,
                                      lab_password_file=lab_password_file,
                                      emergency_password_file=emergency_password_file)
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


def install_product(bundle: Path, trusted_key: Path, crane: Path,
                    console_config: Path, root: Path,
                    core_state: Path | None = None,
                    lab_password_file: Path | None = None,
                    emergency_password_file: Path | None = None) -> dict[str, object]:
    """Stage a signed product release, then switch only after runtime health."""
    _owner_directory(root, create=True)
    with _lock(root):
        _configure_mount(root, core_state, lab_password_file, emergency_password_file)
        identifier, stage = _stage(root, bundle, console_config, trusted_key)
        return _activate(root, stage, identifier, trusted_key, crane)


def restore_install_product(bundle: Path, trusted_key: Path, crane: Path,
                            console_config: Path, root: Path, snapshot_id: str,
                            repository: Path, restic_password_file: Path,
                            restic: Path, restic_sha256: str,
                            lab_password_file: Path,
                            emergency_password_file: Path | None = None) -> dict[str, object]:
    """Clean-restore fictional Core state before first signed installation."""
    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise ProductInstallError("restore installation requires a new absolute root")
    _owner_directory(root.parent, create=False)
    manifest = verify_bundle(bundle, trusted_key)
    if manifest["schema"] != 4:
        raise ProductInstallError("restore installation requires a two-image bundle")
    _validate_console_config(console_config)
    root.mkdir(mode=0o700)
    try:
        restored = restore_snapshot(snapshot_id, repository, restic_password_file,
                                    restic, restic_sha256, root / "core-state")
        if restored["files"] != 4:
            raise ProductInstallError("unexpected synthetic Core snapshot contents")
        activated = install_product(bundle, trusted_key, crane, console_config,
                                    root, root / "core-state", lab_password_file,
                                    emergency_password_file)
        return {**activated, "snapshot_id": snapshot_id,
                "restored_files": restored["files"]}
    except Exception:
        if not (root / "product-state.json").exists() and not root.is_symlink():
            shutil.rmtree(root)
        raise


def product_status(root: Path, trusted_key: Path) -> dict[str, object]:
    core_state, lab_password_file, emergency_password_file = _mount_config(root)
    current = _state(root)
    if current is None:
        raise ProductInstallError("no active product release")
    identifier = str(current["active"])
    _verify_stage(root / "product-releases" / identifier, trusted_key, identifier)
    probe_runtime(_handle(current), core_state, lab_password_file,
                  emergency_password_file)
    return {"result": "healthy", "active": identifier, "previous": current["previous"]}


def rollback_product(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    _owner_directory(root, create=False)
    with _lock(root):
        current = _state(root)
        if current is None or current["previous"] is None:
            raise ProductInstallError("no previous product release")
        identifier = str(current["previous"])
        stage = root / "product-releases" / identifier
        return _activate(root, stage, identifier, trusted_key, crane)


def recover_product(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    """Recreate the signed active lab release when its runtime is unhealthy."""
    _owner_directory(root, create=False)
    with _lock(root):
        core_state, lab_password_file, emergency_password_file = _mount_config(root)
        current = _state(root)
        if current is None:
            raise ProductInstallError("no active product release")
        identifier = str(current["active"])
        stage = root / "product-releases" / identifier
        _verify_stage(stage, trusted_key, identifier)
        try:
            probe_runtime(_handle(current), core_state, lab_password_file,
                          emergency_password_file)
        except ContainerRuntimeError:
            pass
        else:
            return {"result": "already_healthy", "active": identifier,
                    "previous": current["previous"]}
        try:
            verify_runtime_identity(_handle(current))
        except ContainerRuntimeError:
            old_owned = False
        else:
            old_owned = True
        candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                          stage / "console-config.json",
                                          installation_id=_installation_id(root),
                                          core_state=core_state,
                                          lab_password_file=lab_password_file,
                                          emergency_password_file=emergency_password_file)
        try:
            _write_state(root, identifier, current["previous"], candidate)
        except Exception:
            stop_runtime(candidate)
            raise
        if old_owned:
            stop_runtime(_handle(current))
        return {"result": "recovered", "active": identifier,
                "previous": current["previous"]}


def refresh_emergency_product(root: Path, trusted_key: Path,
                              crane: Path) -> dict[str, object]:
    """Rebind a rotated host emergency file through a new signed lab runtime."""
    _owner_directory(root, create=False)
    with _lock(root):
        core_state, lab_password_file, emergency_password_file = _mount_config(root)
        if emergency_password_file is None:
            raise ProductInstallError("no emergency credential is mounted")
        current = _state(root)
        if current is None:
            raise ProductInstallError("no active product release")
        identifier = str(current["active"])
        stage = root / "product-releases" / identifier
        _verify_stage(stage, trusted_key, identifier)
        probe_runtime(_handle(current), core_state, lab_password_file,
                      emergency_password_file, allow_stale_emergency=True)
        candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                          stage / "console-config.json",
                                          installation_id=_installation_id(root),
                                          core_state=core_state,
                                          lab_password_file=lab_password_file,
                                          emergency_password_file=emergency_password_file)
        try:
            probe_runtime(candidate, core_state, lab_password_file,
                          emergency_password_file)
            _write_state(root, identifier, current["previous"], candidate)
        except Exception:
            stop_runtime(candidate)
            raise
        stop_runtime(_handle(current))
        return {"result": "emergency_credential_refreshed", "active": identifier,
                "previous": current["previous"]}


def cleanup_product_orphans(root: Path, trusted_key: Path) -> dict[str, object]:
    """Retire validated labelled lab runtimes not named by active state."""
    _owner_directory(root, create=False)
    with _lock(root):
        core_state, lab_password_file, emergency_password_file = _mount_config(root)
        current = _state(root)
        if current is None:
            raise ProductInstallError("no active product release")
        identifier = str(current["active"])
        _verify_stage(root / "product-releases" / identifier, trusted_key,
                      identifier)
        probe_runtime(_handle(current), core_state, lab_password_file,
                      emergency_password_file)
        counts = cleanup_orphan_runtimes(_installation_id(root), _handle(current))
        return {"result": "cleaned", "active": identifier, **counts}


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic two-image product installer")
    actions = parser.add_subparsers(dest="action", required=True)
    for action in ("install", "restore-install", "status", "rollback", "recover",
                   "refresh-emergency",
                   "cleanup-orphans"):
        command = actions.add_parser(action)
        command.add_argument("--root", required=True, type=Path)
        command.add_argument("--trusted-key", required=True, type=Path)
        if action in ("install", "restore-install", "rollback", "recover",
                      "refresh-emergency"):
            command.add_argument("--crane", required=True, type=Path)
        if action in ("install", "restore-install"):
            command.add_argument("--bundle", required=True, type=Path)
            command.add_argument("--console-config", required=True, type=Path)
        if action == "restore-install":
            command.add_argument("--snapshot-id", required=True)
            command.add_argument("--repository", required=True, type=Path)
            command.add_argument("--restic-password-file", required=True, type=Path)
            command.add_argument("--restic", required=True, type=Path)
            command.add_argument("--restic-sha256", required=True)
            command.add_argument("--lab-password-file", required=True, type=Path)
            command.add_argument("--emergency-password-file", type=Path)
        if action == "install":
            command.add_argument("--core-state", type=Path)
            command.add_argument("--lab-password-file", type=Path)
            command.add_argument("--emergency-password-file", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "install":
            result = install_product(args.bundle, args.trusted_key, args.crane,
                                     args.console_config, args.root,
                                     args.core_state, args.lab_password_file,
                                     args.emergency_password_file)
        elif args.action == "restore-install":
            result = restore_install_product(
                args.bundle, args.trusted_key, args.crane, args.console_config,
                args.root, args.snapshot_id, args.repository,
                args.restic_password_file, args.restic, args.restic_sha256,
                args.lab_password_file, args.emergency_password_file)
        elif args.action == "rollback":
            result = rollback_product(args.root, args.trusted_key, args.crane)
        elif args.action == "recover":
            result = recover_product(args.root, args.trusted_key, args.crane)
        elif args.action == "refresh-emergency":
            result = refresh_emergency_product(args.root, args.trusted_key, args.crane)
        elif args.action == "cleanup-orphans":
            result = cleanup_product_orphans(args.root, args.trusted_key)
        else:
            result = product_status(args.root, args.trusted_key)
    except (BundleError, ProductInstallError, OSError, ValueError) as exc:
        parser.exit(1, f"product-install: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
