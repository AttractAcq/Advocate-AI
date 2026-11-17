"""Stage, activate, roll back and recover signed synthetic Fleet releases."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from infrastructure.deploy.fleet_runtime import (
    FleetRuntime, RuntimeError as FleetRuntimeError, probe_runtime,
    start_verified_bundle, stop_runtime, validate_config, validate_state,
    verify_runtime_identity,
)
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
            or set(value["runtime"]) != {"network_id", "api_id", "portal_id"}
            or any(not isinstance(item, str) or not _DOCKER_ID.fullmatch(item)
                   for item in value["runtime"].values())):
        raise FleetInstallError("invalid Fleet state fields")
    return value


def _handle(value: dict[str, object]) -> FleetRuntime:
    return FleetRuntime(**value["runtime"])


def _write_state(root: Path, active: str, previous: str | None,
                 handle: FleetRuntime) -> None:
    payload = {"schema": 1, "active": active, "previous": previous,
               "runtime": {"network_id": handle.network_id, "api_id": handle.api_id,
                           "portal_id": handle.portal_id}}
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


def _provision_token(root: Path, token_file: Path | None) -> None:
    state = root / "state"
    _owner_directory(state, create=True)
    target = state / "token"
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
    validate_state(state)


def _activate(root: Path, identifier: str, stage: Path,
              trusted_key: Path, crane: Path) -> dict[str, object]:
    current = _state(root)
    if current is not None:
        old_stage = root / "fleet-releases" / str(current["active"])
        _verify_stage(old_stage, trusted_key, str(current["active"]))
        probe_runtime(_handle(current), old_stage / "bundle", trusted_key,
                      root / "state", old_stage / "fleet-config.json")
        if current["active"] == identifier:
            return {"result": "unchanged", "active": identifier,
                    "previous": current["previous"]}
    _verify_stage(stage, trusted_key, identifier)
    candidate = start_verified_bundle(stage / "bundle", trusted_key, crane,
                                      stage / "fleet-config.json", root / "state")
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
                  token_file: Path | None = None) -> dict[str, object]:
    _owner_directory(root, create=True)
    with _lock(root):
        _provision_token(root, token_file)
        identifier, stage = _stage(root, bundle, config, trusted_key)
        return _activate(root, identifier, stage, trusted_key, crane)


def fleet_status(root: Path, trusted_key: Path) -> dict[str, object]:
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


def rollback_fleet(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    _owner_directory(root)
    with _lock(root):
        current = _state(root)
        if current is None or current["previous"] is None:
            raise FleetInstallError("no previous Fleet release")
        identifier = str(current["previous"])
        stage = root / "fleet-releases" / identifier
        return _activate(root, identifier, stage, trusted_key, crane)


def recover_fleet(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    _owner_directory(root)
    with _lock(root):
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
                                          stage / "fleet-config.json", root / "state")
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
    for name in ("install", "status", "rollback", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--root", required=True, type=Path)
        command.add_argument("--trusted-key", required=True, type=Path)
        if name != "status":
            command.add_argument("--crane", required=True, type=Path)
        if name == "install":
            command.add_argument("--bundle", required=True, type=Path)
            command.add_argument("--config", required=True, type=Path)
            command.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "install":
            result = install_fleet(args.bundle, args.trusted_key, args.crane,
                                   args.config, args.root, args.token_file)
        elif args.command == "status":
            result = fleet_status(args.root, args.trusted_key)
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
