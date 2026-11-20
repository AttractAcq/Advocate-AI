"""Atomic first activation of a signed synthetic three-image vessel release.

The first-install path stages a verified bundle, provisions an external
Knowledge database, indexes approved sources, checks all three services, and
only then writes the active record. Update and recovery are separate gates.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile

from infrastructure.deploy.container_runtime import (
    RuntimeHandle, _docker, _image_id, _validate_console_config, stop_runtime,
)
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, _credentials, _volume, probe_knowledge,
    start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.postgres_socket import sql as postgres_sql
from infrastructure.deploy.vessel_runtime import (
    _state_options, probe_signed_vessel_services, start_signed_vessel_services,
)
from infrastructure.release.bundle import BundleError, verify_bundle


class VesselInstallError(ValueError):
    """The signed vessel installation is unsafe or incomplete."""


_IDENTIFIER = re.compile(r"[0-9a-f]{24}\Z")
_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _owner_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise VesselInstallError("vessel installation directory must be owner-only")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise VesselInstallError("duplicate vessel installation state key")
        value[key] = item
    return value


def _release_id(bundle: Path, config: Path) -> str:
    return hashlib.sha256((bundle / "release-manifest.json").read_bytes() +
                          b"\0" + config.read_bytes()).hexdigest()[:24]


def _stage(root: Path, bundle: Path, trusted_key: Path,
           config: Path) -> tuple[str, Path]:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise BundleError("vessel installer requires a signed three-image bundle")
    _validate_console_config(config)
    if not stat.S_IMODE(config.stat().st_mode) & 0o004:
        raise VesselInstallError("Console configuration is unreadable by the image user")
    identifier = _release_id(bundle, config)
    releases = root / "vessel-releases"
    releases.mkdir(mode=0o700)
    stage = releases / identifier
    stage.mkdir(mode=0o700)
    shutil.copytree(bundle, stage / "bundle", symlinks=True)
    staged_config = stage / "console-config.json"
    staged_config.write_bytes(config.read_bytes())
    staged_config.chmod(0o644)
    _verify_stage(stage, trusted_key, identifier)
    return identifier, stage


def _verify_stage(stage: Path, trusted_key: Path, identifier: str) -> None:
    if (not _IDENTIFIER.fullmatch(identifier) or stage.is_symlink()
            or not stage.is_dir() or
            {item.name for item in stage.iterdir()} != {"bundle", "console-config.json"}):
        raise VesselInstallError("invalid staged vessel release")
    manifest = verify_bundle(stage / "bundle", trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise VesselInstallError("staged release is not a vessel bundle")
    config = stage / "console-config.json"
    _validate_console_config(config)
    if _release_id(stage / "bundle", config) != identifier:
        raise VesselInstallError("staged vessel release identity mismatch")


def _ingest(bundle: Path, trusted_key: Path, crane: Path,
            state: Path, knowledge_root: Path,
            knowledge: KnowledgeVolumeHandle) -> dict[str, object]:
    manifest = verify_bundle(bundle, trusted_key)
    image = _image_id(bundle, "core", manifest["images"]["core"], crane)
    _, writer, _, _, _ = _credentials(knowledge_root, initialize=False)
    program = """\
import json
from pathlib import Path
from services.knowledge.postgres_index import initialize_schema
from services.knowledge.ingestion import sync_manifest
root=Path('/var/lib/sovereign')
dsn='postgresql://sovereign_ingest@/postgres?host=/run/postgresql'
initialize_schema(dsn)
result=sync_manifest(root,root/'approved.json',dsn)
if result['quarantined']:
 raise RuntimeError('approved source was quarantined')
print(json.dumps({'indexed':len(result['indexed']),'unchanged':len(result['unchanged'])}))
"""
    try:
        completed = subprocess.run(
            ["docker", "run", "--rm", "--pull", "never", "--network", "none",
             "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--user", f"{os.getuid()}:{os.getgid()}",
             "--mount", (f"type=volume,source={knowledge.socket_volume},"
                         "target=/run/postgresql,readonly"),
             "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign,readonly",
             "--mount", (f"type=bind,source={writer.resolve()},"
                         "target=/run/secrets/pgpass,readonly"),
             "-e", "SOVEREIGN_KNOWLEDGE_DB=postgresql://sovereign_ingest@/postgres?host=/run/postgresql",
             "-e", "PGPASSFILE=/run/secrets/pgpass", image, "python", "-c", program],
            capture_output=True, text=True, check=True, timeout=180)
        result = json.loads(completed.stdout, object_pairs_hook=_unique)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError) as exc:
        raise VesselInstallError("signed Knowledge ingestion failed") from exc
    if (not isinstance(result, dict) or set(result) != {"indexed", "unchanged"}
            or any(type(value) is not int or value < 0 for value in result.values())
            or result["indexed"] + result["unchanged"] < 1):
        raise VesselInstallError("signed Knowledge ingestion returned invalid inventory")
    postgres_sql(knowledge.container_id,
                 "GRANT SELECT ON knowledge_sources, knowledge_passages, "
                 "knowledge_quarantine, knowledge_vectors TO sovereign_read")
    return result


def _state_payload(identifier: str, installation_id: str,
                   core_state: Path, lab_password: Path,
                   services: RuntimeHandle,
                   knowledge: KnowledgeVolumeHandle) -> dict[str, object]:
    return {
        "schema": 1, "active": identifier, "installation_id": installation_id,
        "core_state": str(core_state.resolve()),
        "lab_password_file": str(lab_password.resolve()),
        "runtime": {"network_id": services.network_id,
                    "core_id": services.core_id,
                    "console_id": services.console_id,
                    "knowledge_id": knowledge.container_id,
                    "knowledge_run": knowledge.run_name,
                    "socket_volume": knowledge.socket_volume,
                    "data_volume": knowledge.data_volume},
    }


def _write_state(root: Path, payload: dict[str, object]) -> None:
    descriptor, filename = tempfile.mkstemp(prefix=".vessel-state-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(payload, sort_keys=True,
                                    separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, root / "vessel-state.json")
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(filename).unlink(missing_ok=True)


def _cleanup_failed_install(installation_id: str, services: RuntimeHandle | None,
                            knowledge: KnowledgeVolumeHandle | None,
                            data_volume: str, *, retain_data: bool = False) -> bool:
    """Discard a failed candidate only after its labelled resources are absent."""
    try:
        if services is not None:
            stop_runtime(services)
        if knowledge is not None:
            stop_knowledge(knowledge)
        scope = f"label=sovereign.synthetic.install={installation_id}"
        containers = _docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet")
        networks = _docker("network", "ls", "--no-trunc", "--filter", scope,
                           "--quiet")
        if containers or networks:
            return False
        volumes = _docker("volume", "ls", "--filter", scope, "--quiet").splitlines()
        if any(volume != data_volume for volume in volumes):
            return False
        if retain_data:
            if volumes != [data_volume]:
                return False
            _volume(data_volume, installation_id, "knowledge-data", create=False)
            return True
        if volumes:
            _docker("volume", "rm", data_volume)
        return not _docker("volume", "ls", "--filter", scope, "--quiet")
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError):
        return False


def install_vessel(bundle: Path, trusted_key: Path, crane: Path,
                   console_config: Path, root: Path, core_state: Path,
                   lab_password_file: Path) -> dict[str, object]:
    """Create one new signed synthetic installation and activate after health."""
    if (not root.is_absolute() or root.exists() or root.is_symlink()):
        raise VesselInstallError("first vessel installation requires a new absolute root")
    _owner_directory(root.parent)
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise BundleError("vessel installer requires a signed three-image bundle")
    root.mkdir(mode=0o700)
    services = None
    knowledge = None
    installation_id = secrets.token_hex(16)
    data_volume = f"sovereign-{installation_id}-knowledge-data"
    try:
        identifier, stage = _stage(root, bundle, trusted_key, console_config)
        knowledge = start_signed_knowledge(stage / "bundle", trusted_key, crane,
                                           root, installation_id, initialize=True)
        _state_options(core_state, lab_password_file, root)
        ingestion = _ingest(stage / "bundle", trusted_key, crane, core_state,
                            root, knowledge)
        services = start_signed_vessel_services(
            stage / "bundle", trusted_key, crane, stage / "console-config.json",
            core_state, lab_password_file, root, knowledge, installation_id)
        payload = _state_payload(identifier, installation_id, core_state,
                                 lab_password_file, services, knowledge)
        _write_state(root, payload)
        return {"result": "activated", "active": identifier,
                "indexed": ingestion["indexed"], "unchanged": ingestion["unchanged"]}
    except Exception as exc:
        try:
            (root / "vessel-state.json").unlink(missing_ok=True)
        except OSError as cleanup_error:
            raise VesselInstallError(
                "first installation failed; active record could not be cleared"
            ) from cleanup_error
        if not _cleanup_failed_install(installation_id, services, knowledge,
                                       data_volume):
            raise VesselInstallError(
                "first installation failed; cleanup incomplete and private root retained"
            ) from exc
        try:
            shutil.rmtree(root)
        except OSError as cleanup_error:
            raise VesselInstallError(
                "first installation failed; private root cleanup incomplete"
            ) from cleanup_error
        raise


def _read_state(root: Path) -> dict[str, object]:
    _owner_directory(root)
    path = root / "vessel-state.json"
    if (path.is_symlink() or not path.is_file() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077 or
            path.stat().st_size > 4096):
        raise VesselInstallError("invalid vessel active state")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise VesselInstallError("invalid vessel active state JSON") from exc
    if (not isinstance(value, dict) or
            set(value) != {"schema", "active", "installation_id", "core_state",
                           "lab_password_file", "runtime"} or
            type(value["schema"]) is not int or value["schema"] != 1 or
            not isinstance(value["active"], str) or
            not _IDENTIFIER.fullmatch(value["active"]) or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["core_state"], str) or
            not isinstance(value["lab_password_file"], str) or
            not isinstance(value["runtime"], dict) or
            set(value["runtime"]) != {"network_id", "core_id", "console_id",
                                      "knowledge_id", "knowledge_run",
                                      "socket_volume", "data_volume"}):
        raise VesselInstallError("invalid vessel active state fields")
    runtime = value["runtime"]
    if (any(not isinstance(runtime[key], str) or not _DOCKER_ID.fullmatch(runtime[key])
            for key in ("network_id", "core_id", "console_id", "knowledge_id")) or
            not isinstance(runtime["knowledge_run"], str) or
            not isinstance(runtime["socket_volume"], str) or
            not isinstance(runtime["data_volume"], str) or
            runtime["knowledge_run"] + "-socket" != runtime["socket_volume"] or
            runtime["data_volume"] !=
            f"sovereign-{value['installation_id']}-knowledge-data"):
        raise VesselInstallError("invalid vessel runtime record")
    return value


def status_vessel(root: Path, trusted_key: Path, crane: Path) -> dict[str, object]:
    """Fail closed if the active stage, images or three runtimes changed."""
    value = _read_state(root)
    identifier = value["active"]
    stage = root / "vessel-releases" / identifier
    _verify_stage(stage, trusted_key, identifier)
    manifest = verify_bundle(stage / "bundle", trusted_key)
    runtime = value["runtime"]
    knowledge = KnowledgeVolumeHandle(runtime["knowledge_id"],
                                      runtime["socket_volume"],
                                      runtime["data_volume"],
                                      runtime["knowledge_run"],
                                      value["installation_id"])
    services = RuntimeHandle(runtime["network_id"], runtime["core_id"],
                             runtime["console_id"])
    state, password = Path(value["core_state"]), Path(value["lab_password_file"])
    if (state.resolve().is_relative_to(root.resolve()) or
            password.resolve().is_relative_to(root.resolve())):
        raise VesselInstallError("Core state and lab credential must be external")
    _, reader = _state_options(state, password, root)
    probe_knowledge(knowledge)
    probe_signed_vessel_services(services, knowledge, state, password, reader)
    try:
        console_mounts = json.loads(_docker("inspect", services.console_id,
                                            "--format", "{{json .Mounts}}"))
    except json.JSONDecodeError as exc:
        raise VesselInstallError("invalid Console runtime mount metadata") from exc
    matches = [item for item in console_mounts if isinstance(item, dict) and
               item.get("Destination") == "/srv/console-config.json"] \
              if isinstance(console_mounts, list) else []
    if (len(matches) != 1 or matches[0].get("Type") != "bind" or
            matches[0].get("Source") != str((stage / "console-config.json").resolve()) or
            matches[0].get("RW") is not False):
        raise VesselInstallError("Console runtime configuration mount changed")
    for role, identifier_value in (("core", services.core_id),
                                   ("console", services.console_id),
                                   ("knowledge", knowledge.container_id)):
        expected = _image_id(stage / "bundle", role, manifest["images"][role], crane)
        if _docker("inspect", identifier_value, "--format", "{{.Image}}") != expected:
            raise VesselInstallError("installed image differs from signed archive")
    return {"result": "healthy", "active": identifier,
            "installation_id": value["installation_id"]}


def _assert_missing(kind: str, identifier: str) -> None:
    try:
        result = subprocess.run(["docker", kind, "inspect", identifier],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VesselInstallError("cannot confirm old vessel resource absence") from exc
    if result.returncode == 0 or not re.search(r"no such|not found", result.stderr.lower()):
        raise VesselInstallError("old vessel resource remains or cannot be inspected")


def _recovery_inventory(installation_id: str, runtime: dict[str, str]) -> None:
    data_volume = runtime["data_volume"]
    scope = f"label=sovereign.synthetic.install={installation_id}"
    if (_docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("network", "ls", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("volume", "ls", "--filter", scope, "--quiet") != data_volume):
        raise VesselInstallError("stopped recovery requires only the persistent data volume")
    _volume(data_volume, installation_id, "knowledge-data", create=False)
    for kind, identifier in (("container", runtime["core_id"]),
                             ("container", runtime["console_id"]),
                             ("container", runtime["knowledge_id"]),
                             ("network", runtime["network_id"]),
                             ("volume", runtime["socket_volume"])):
        _assert_missing(kind, identifier)


def stop_vessel(root: Path, trusted_key: Path, crane: Path) -> dict[str, str]:
    """Stop a verified synthetic vessel runtime while retaining Knowledge data."""
    healthy = status_vessel(root, trusted_key, crane)
    value = _read_state(root)
    runtime = value["runtime"]
    services = RuntimeHandle(runtime["network_id"], runtime["core_id"],
                             runtime["console_id"])
    knowledge = KnowledgeVolumeHandle(runtime["knowledge_id"],
                                      runtime["socket_volume"],
                                      runtime["data_volume"],
                                      runtime["knowledge_run"],
                                      value["installation_id"])
    stop_runtime(services)
    scope = f"label=sovereign.synthetic.install={value['installation_id']}"
    remaining = _docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet")
    if set(remaining.splitlines()) != {knowledge.container_id}:
        raise VesselInstallError("Core or Console stop is incomplete")
    if _docker("network", "ls", "--no-trunc", "--filter", scope, "--quiet"):
        raise VesselInstallError("vessel network stop is incomplete")
    stop_knowledge(knowledge)
    _recovery_inventory(value["installation_id"], runtime)
    return {"result": "stopped", "active": healthy["active"]}


def recover_vessel(root: Path, trusted_key: Path, crane: Path) -> dict[str, str]:
    """Restart a cleanly stopped vessel from its signed stage and data volume."""
    value = _read_state(root)
    identifier = value["active"]
    stage = root / "vessel-releases" / identifier
    _verify_stage(stage, trusted_key, identifier)
    state, password = Path(value["core_state"]), Path(value["lab_password_file"])
    if (state.resolve().is_relative_to(root.resolve()) or
            password.resolve().is_relative_to(root.resolve())):
        raise VesselInstallError("Core state and lab credential must be external")
    _state_options(state, password, root)
    installation_id = value["installation_id"]
    data_volume = value["runtime"]["data_volume"]
    _recovery_inventory(installation_id, value["runtime"])
    knowledge = None
    services = None
    payload = None
    try:
        knowledge = start_signed_knowledge(stage / "bundle", trusted_key, crane,
                                           root, installation_id, initialize=False)
        services = start_signed_vessel_services(
            stage / "bundle", trusted_key, crane, stage / "console-config.json",
            state, password, root, knowledge, installation_id)
        payload = _state_payload(identifier, installation_id, state, password,
                                 services, knowledge)
        _write_state(root, payload)
        return {"result": "recovered", "active": identifier}
    except Exception as exc:
        try:
            recorded = _read_state(root)
        except Exception:
            recorded = None
        if payload is not None and recorded != value:
            raise VesselInstallError(
                "recovery state may have changed; retain runtime for reconciliation"
            ) from exc
        if not _cleanup_failed_install(installation_id, services, knowledge,
                                       data_volume, retain_data=True):
            raise VesselInstallError(
                "recovery failed; cleanup incomplete and data retained"
            ) from exc
        raise
