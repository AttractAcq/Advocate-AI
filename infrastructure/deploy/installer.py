"""Stage verified releases and activate them in a synthetic local installation.

This installer never starts services, changes firewall rules or provisions keys.
The active state file is a local rehearsal mechanism, not a production service
manager or a replacement for protected release approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

from infrastructure.diagnostics import diagnose
from infrastructure.release.bundle import BundleError, verify_bundle

SERVICES = {"console", "core", "knowledge", "policy", "intelligence", "wazuh-simulator"}
NODE_ID = re.compile(r"[a-z][a-z0-9-]{2,31}\Z")
RELEASE_ID = re.compile(r"[0-9a-f]{20}\Z")
CONFIG_FILE = "install-config.json"
STATE_FILE = "state.json"


class InstallError(ValueError):
    """Configuration, release or local install state is invalid."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InstallError("duplicate JSON key")
        result[key] = value
    return result


def validate_config(config: object) -> dict[str, object]:
    """Allow only the six fictional loopback lab services and no secrets."""
    if not isinstance(config, dict) or set(config) != {
            "schema", "mode", "node_id", "bind", "public_egress", "services"}:
        raise InstallError("invalid installation configuration fields")
    if (type(config["schema"]) is not int or config["schema"] != 1
            or config["mode"] != "synthetic-loopback"
            or config["bind"] != "127.0.0.1" or config["public_egress"] is not False
            or not isinstance(config["node_id"], str) or not NODE_ID.fullmatch(config["node_id"])):
        raise InstallError("invalid synthetic installation boundary")
    services = config["services"]
    if (not isinstance(services, dict) or set(services) != SERVICES
            or any(not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535
                   for port in services.values())
            or len(set(services.values())) != len(SERVICES)):
        raise InstallError("invalid local service ports")
    return config


def _config(path: Path) -> tuple[dict[str, object], bytes]:
    if path.is_symlink() or not path.is_file():
        raise InstallError("configuration file is missing or linked")
    raw = path.read_bytes()
    if len(raw) > 16 * 1024:
        raise InstallError("configuration is too large")
    try:
        config = validate_config(json.loads(raw, object_pairs_hook=_unique_object))
    except (ValueError, UnicodeError) as exc:
        raise InstallError("invalid configuration JSON") from exc
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return config, canonical


def _deployment_id(manifest: bytes, config: bytes) -> str:
    return hashlib.sha256(manifest + b"\x00" + config).hexdigest()[:20]


def _prepare_root(root: Path) -> Path:
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise InstallError("invalid installation root")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise InstallError("installation root must be owner-only")
    releases = root / "releases"
    if releases.is_symlink() or (releases.exists() and not releases.is_dir()):
        raise InstallError("invalid release directory")
    releases.mkdir(mode=0o700, exist_ok=True)
    if releases.stat().st_mode & 0o077:
        raise InstallError("release directory must be owner-only")
    return releases


def _state(root: Path) -> dict[str, object] | None:
    if root.is_symlink() or not root.is_dir():
        raise InstallError("invalid installation root")
    if root.stat().st_mode & 0o077:
        raise InstallError("installation root must be owner-only")
    path = root / STATE_FILE
    if path.is_symlink():
        raise InstallError("linked installation state")
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > 4096:
        raise InstallError("invalid installation state")
    try:
        state = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as exc:
        raise InstallError("invalid installation state JSON") from exc
    if (not isinstance(state, dict) or set(state) != {"schema", "active", "previous"}
            or state["schema"] != 1 or not isinstance(state["active"], str)
            or not RELEASE_ID.fullmatch(state["active"])
            or (state["previous"] is not None and
                (not isinstance(state["previous"], str) or not RELEASE_ID.fullmatch(state["previous"])))):
        raise InstallError("invalid installation state fields")
    return state


def _existing_releases(root: Path) -> Path:
    releases = root / "releases"
    if releases.is_symlink() or not releases.is_dir() or releases.stat().st_mode & 0o077:
        raise InstallError("invalid release directory")
    return releases


def _write_state(root: Path, active: str, previous: str | None) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=".state-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps({"schema": 1, "active": active, "previous": previous},
                                    sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, root / STATE_FILE)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def _verify_stage(stage: Path, trusted_key: Path,
                  expected_id: str | None = None) -> tuple[str, dict[str, object]]:
    if (stage.is_symlink() or not stage.is_dir()
            or {item.name for item in stage.iterdir()} != {"bundle", CONFIG_FILE}
            or (stage / CONFIG_FILE).is_symlink()):
        raise InstallError("invalid staged release")
    verify_bundle(stage / "bundle", trusted_key)
    config, canonical = _config(stage / CONFIG_FILE)
    identifier = _deployment_id((stage / "bundle/release-manifest.json").read_bytes(), canonical)
    if (expected_id or stage.name) != identifier:
        raise InstallError("staged release identity mismatch")
    return identifier, config


def install(bundle: Path, trusted_key: Path, config_path: Path, root: Path) -> dict[str, object]:
    """Verify, copy, reverify, then atomically point local state to the release."""
    verify_bundle(bundle, trusted_key)
    _, config_bytes = _config(config_path)
    identifier = _deployment_id((bundle / "release-manifest.json").read_bytes(), config_bytes)
    releases = _prepare_root(root)
    current = _state(root)
    if current:
        _verify_stage(releases / str(current["active"]), trusted_key)
    target = releases / identifier
    if target.exists() or target.is_symlink():
        _verify_stage(target, trusted_key)
    else:
        temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            shutil.copytree(bundle, temporary / "bundle", symlinks=True)
            descriptor = os.open(temporary / CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(config_bytes)
            _verify_stage(temporary, trusted_key, expected_id=identifier)
            candidate = releases / identifier
            if candidate.exists() or candidate.is_symlink():
                raise InstallError("release appeared during staging")
            os.rename(temporary, candidate)
            temporary = candidate
        except Exception:
            if temporary.name.startswith(".staging-"):
                shutil.rmtree(temporary, ignore_errors=True)
            raise
    if current and current["active"] == identifier:
        return {"result": "unchanged", "active": identifier, "previous": current["previous"]}
    previous = current["active"] if current else None
    _write_state(root, identifier, previous)
    return {"result": "installed", "active": identifier, "previous": previous}


def status(root: Path, trusted_key: Path) -> dict[str, object]:
    current = _state(root)
    if current is None:
        raise InstallError("no active installation")
    active = str(current["active"])
    _verify_stage(_existing_releases(root) / active, trusted_key)
    return {"result": "verified", "active": active, "previous": current["previous"]}


def rollback(root: Path, trusted_key: Path) -> dict[str, object]:
    current = _state(root)
    if current is None or current["previous"] is None:
        raise InstallError("no previous release")
    previous = str(current["previous"])
    _verify_stage(_existing_releases(root) / previous, trusted_key)
    _write_state(root, previous, str(current["active"]))
    return {"result": "rolled_back", "active": previous, "previous": current["active"]}


def postcheck(root: Path, trusted_key: Path, health_path: Path) -> dict[str, object]:
    current = status(root, trusted_key)
    config, _ = _config(root / "releases" / str(current["active"]) / CONFIG_FILE)
    if health_path.is_symlink() or not health_path.is_file() or health_path.stat().st_size > 64 * 1024:
        raise InstallError("health configuration is missing or linked")
    checks = json.loads(health_path.read_text(), object_pairs_hook=_unique_object)
    if not isinstance(checks, dict) or checks.get("mode") != "synthetic-loopback":
        raise InstallError("synthetic health configuration required")
    entries = checks.get("checks")
    if not isinstance(entries, list):
        raise InstallError("health check list required")
    service_names = set(config["services"])
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kind") != "https":
            raise InstallError("all synthetic services need HTTPS checks")
        service = entry.get("expected_service")
        if service not in service_names or service in seen:
            raise InstallError("missing or duplicate service check")
        seen.add(service)
        url = urlsplit(str(entry.get("url", "")))
        if url.hostname != config["bind"] or url.port != config["services"][service]:
            raise InstallError("health check does not match staged service port")
    if seen != service_names:
        raise InstallError("incomplete service health inventory")
    report = diagnose(checks, health_path.parent)
    return {"result": "passed" if report["all_ok"] else "failed", "active": current["active"],
            "health": report}


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic signed-bundle staging installer")
    actions = parser.add_subparsers(dest="action", required=True)
    validate = actions.add_parser("validate-config")
    validate.add_argument("config", type=Path)
    for action in ("install", "status", "rollback", "postcheck"):
        command = actions.add_parser(action)
        command.add_argument("--root", required=True, type=Path)
        command.add_argument("--trusted-key", required=True, type=Path)
        if action == "install":
            command.add_argument("--bundle", required=True, type=Path)
            command.add_argument("--config", required=True, type=Path)
        elif action == "postcheck":
            command.add_argument("--health-config", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "validate-config":
            _config(args.config)
            result: dict[str, object] = {"result": "valid_synthetic_config"}
        elif args.action == "install":
            result = install(args.bundle, args.trusted_key, args.config, args.root)
        elif args.action == "status":
            result = status(args.root, args.trusted_key)
        elif args.action == "rollback":
            result = rollback(args.root, args.trusted_key)
        else:
            result = postcheck(args.root, args.trusted_key, args.health_config)
    except (BundleError, InstallError, OSError, ValueError) as exc:
        parser.exit(1, f"install: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    if result.get("result") == "failed":
        parser.exit(1)


if __name__ == "__main__":
    main()
