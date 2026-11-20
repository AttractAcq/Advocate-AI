"""Atomic first activation of a signed synthetic three-image vessel release.

The first-install path stages a verified bundle, provisions an external
Knowledge database, indexes approved sources, checks all three services, and
only then writes the active record. Update and recovery are separate gates.
"""

from __future__ import annotations

import fcntl
import functools
from contextlib import contextmanager
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
    KnowledgeVolumeHandle, _credentials, _migration_credential, _volume, probe_knowledge,
    start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.postgres_socket import PostgresSocketError, sql as postgres_sql
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


def _candidate_release_id(bundle: Path, trusted_key: Path, config: Path) -> str:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise BundleError("vessel installer requires a signed three-image bundle")
    _validate_console_config(config)
    if not stat.S_IMODE(config.stat().st_mode) & 0o004:
        raise VesselInstallError("Console configuration is unreadable by the image user")
    return _release_id(bundle, config)


def _stage(root: Path, bundle: Path, trusted_key: Path,
           config: Path) -> tuple[str, Path]:
    identifier = _candidate_release_id(bundle, trusted_key, config)
    releases = root / "vessel-releases"
    releases.mkdir(mode=0o700, exist_ok=True)
    _owner_directory(releases)
    stage = releases / identifier
    if stage.exists() or stage.is_symlink():
        _verify_stage(stage, trusted_key, identifier)
        return identifier, stage
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
    migrate, _ = _migration_credential(knowledge_root)
    schema_program = """\
from services.knowledge.postgres_index import _connect, initialize_schema
dsn='postgresql://sovereign_migrate@/postgres?host=/run/postgresql'
initialize_schema(dsn)
with _connect(dsn) as db:
 db.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge_sources, knowledge_passages, knowledge_quarantine, knowledge_vectors TO sovereign_ingest')
 db.execute('GRANT SELECT ON knowledge_sources, knowledge_passages, knowledge_quarantine, knowledge_vectors, knowledge_schema_version TO sovereign_read')
"""
    program = """\
import json
from pathlib import Path
from services.knowledge.ingestion import sync_manifest
root=Path('/var/lib/sovereign')
dsn='postgresql://sovereign_ingest@/postgres?host=/run/postgresql'
result=sync_manifest(root,root/'approved.json',dsn)
if result['quarantined']:
 raise RuntimeError('approved source was quarantined')
print(json.dumps({'indexed':len(result['indexed']),'unchanged':len(result['unchanged'])}))
"""
    def run_task(role: str, credential: Path, code: str) -> subprocess.CompletedProcess[str]:
        command = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
             "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--user", f"{os.getuid()}:{os.getgid()}",
             "--mount", (f"type=volume,source={knowledge.socket_volume},"
                         "target=/run/postgresql,readonly"),
             "--mount", (f"type=bind,source={credential.resolve()},"
                         "target=/run/secrets/pgpass,readonly")]
        if role == "sovereign_ingest":
            command += ["--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign,readonly"]
        command += [
             "-e", f"SOVEREIGN_KNOWLEDGE_DB=postgresql://{role}@/postgres?host=/run/postgresql",
             "-e", "PGPASSFILE=/run/secrets/pgpass", image, "python", "-c", code]
        return subprocess.run(command,
            capture_output=True, text=True, check=True, timeout=180)
    try:
        run_task("sovereign_migrate", migrate, schema_program)
        completed = run_task("sovereign_ingest", writer, program)
        result = json.loads(completed.stdout, object_pairs_hook=_unique)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError) as exc:
        raise VesselInstallError("signed Knowledge ingestion failed") from exc
    if (not isinstance(result, dict) or set(result) != {"indexed", "unchanged"}
            or any(type(value) is not int or value < 0 for value in result.values())
            or result["indexed"] + result["unchanged"] < 1):
        raise VesselInstallError("signed Knowledge ingestion returned invalid inventory")
    return result


def _state_payload(identifier: str, installation_id: str,
                   core_state: Path, lab_password: Path,
                   services: RuntimeHandle,
                   knowledge: KnowledgeVolumeHandle,
                   *, previous: str | None = None) -> dict[str, object]:
    if previous is not None and (not _IDENTIFIER.fullmatch(previous)
                                 or previous == identifier):
        raise VesselInstallError("invalid previous vessel release")
    payload = {
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
    if previous is not None:
        payload["previous"] = previous
    return payload


def _verify_knowledge_schema(knowledge: KnowledgeVolumeHandle) -> None:
    try:
        rows = postgres_sql(
            knowledge.container_id,
            "SELECT singleton::int || ':' || version FROM public.knowledge_schema_version")
    except PostgresSocketError as exc:
        raise VesselInstallError("Knowledge schema version unavailable") from exc
    if rows != "1:1":
        raise VesselInstallError("unsupported or incomplete Knowledge schema version")


def _write_private_record(root: Path, name: str,
                          payload: dict[str, object]) -> None:
    descriptor, filename = tempfile.mkstemp(prefix=".vessel-record-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(payload, sort_keys=True,
                                    separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, root / name)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(filename).unlink(missing_ok=True)


def _write_state(root: Path, payload: dict[str, object]) -> None:
    _write_private_record(root, "vessel-state.json", payload)


def _write_intent(root: Path, identifier: str, installation_id: str,
                  core_state: Path, lab_password_file: Path) -> None:
    _write_private_record(root, "vessel-intent.json", {
        "schema": 1, "release": identifier, "installation_id": installation_id,
        "core_state": str(core_state.resolve()),
        "lab_password_file": str(lab_password_file.resolve()),
        "data_volume": f"sovereign-{installation_id}-knowledge-data",
    })


def _read_intent(root: Path) -> dict[str, object]:
    _owner_directory(root)
    path = root / "vessel-intent.json"
    if (path.is_symlink() or not path.is_file() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077 or
            path.stat().st_size > 4096):
        raise VesselInstallError("invalid vessel install intent")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise VesselInstallError("invalid vessel install intent JSON") from exc
    if (not isinstance(value, dict) or
            set(value) != {"schema", "release", "installation_id", "core_state",
                           "lab_password_file", "data_volume"} or
            type(value["schema"]) is not int or value["schema"] != 1 or
            not isinstance(value["release"], str) or
            not _IDENTIFIER.fullmatch(value["release"]) or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            value["data_volume"] !=
            f"sovereign-{value['installation_id']}-knowledge-data" or
            not isinstance(value["core_state"], str) or
            not Path(value["core_state"]).is_absolute() or
            not isinstance(value["lab_password_file"], str) or
            not Path(value["lab_password_file"]).is_absolute()):
        raise VesselInstallError("invalid vessel install intent fields")
    return value


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
        _write_intent(root, identifier, installation_id, core_state,
                      lab_password_file)
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
        try:
            (root / "vessel-intent.json").unlink(missing_ok=True)
        except OSError:
            pass
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
            set(value) not in (
                {"schema", "active", "installation_id", "core_state",
                 "lab_password_file", "runtime"},
                {"schema", "active", "installation_id", "core_state",
                 "lab_password_file", "runtime", "previous"}) or
            type(value["schema"]) is not int or value["schema"] != 1 or
            not isinstance(value["active"], str) or
            not _IDENTIFIER.fullmatch(value["active"]) or
            not isinstance(value["installation_id"], str) or
            not _INSTALL.fullmatch(value["installation_id"]) or
            not isinstance(value["core_state"], str) or
            not isinstance(value["lab_password_file"], str) or
            not isinstance(value["runtime"], dict) or
            ("previous" in value and
             (not isinstance(value["previous"], str) or
              not _IDENTIFIER.fullmatch(value["previous"]) or
              value["previous"] == value["active"])) or
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
    _verify_knowledge_schema(knowledge)
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


@contextmanager
def _operation_lock(root: Path):
    _owner_directory(root)
    descriptor = os.open(root / ".vessel-operation.lock",
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600)
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o077
                or details.st_nlink != 1):
            raise VesselInstallError("invalid vessel operation lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VesselInstallError("another vessel operation is active") from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _serialized(operation):
    @functools.wraps(operation)
    def locked(root: Path, trusted_key: Path, crane: Path):
        with _operation_lock(root):
            return operation(root, trusted_key, crane)
    return locked


def _scoped_list(*args: str, volume: bool = False) -> list[str]:
    items = _docker(*args).splitlines()
    pattern = r"sovereign-(?:knowledge-[0-9a-f]{12}-socket|[0-9a-f]{32}-knowledge-data)" \
              if volume else r"[0-9a-f]{64}"
    if (len(items) > 20 or len(items) != len(set(items)) or
            any(not re.fullmatch(pattern, item) for item in items)):
        raise VesselInstallError("invalid scoped Docker resource inventory")
    return items


@_serialized
def finish_vessel_stop(root: Path, trusted_key: Path, crane: Path) -> dict[str, str]:
    """Finish an interrupted stop using only the recorded, signed resources."""
    value = _read_state(root)
    identifier = value["active"]
    stage = root / "vessel-releases" / identifier
    _verify_stage(stage, trusted_key, identifier)
    manifest = verify_bundle(stage / "bundle", trusted_key)
    state, password = Path(value["core_state"]), Path(value["lab_password_file"])
    _state_options(state, password, root)
    installation_id = value["installation_id"]
    runtime = value["runtime"]
    scope = f"label=sovereign.synthetic.install={installation_id}"
    containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope, "--quiet")
    networks = _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                            "--quiet")
    volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                           volume=True)
    recorded_ids = {runtime["core_id"], runtime["console_id"],
                    runtime["knowledge_id"]}
    if (not set(containers) <= recorded_ids or
            not set(networks) <= {runtime["network_id"]} or
            not set(volumes) <= {runtime["data_volume"], runtime["socket_volume"]}
            or runtime["data_volume"] not in volumes):
        raise VesselInstallError("interrupted stop contains unrecorded resources")
    _volume(runtime["data_volume"], installation_id, "knowledge-data", create=False)
    socket_present = runtime["socket_volume"] in volumes
    if socket_present:
        _volume(runtime["socket_volume"], installation_id, "knowledge-socket",
                create=False, run_name=runtime["knowledge_run"])
    else:
        _assert_missing("volume", runtime["socket_volume"])
    network_present = runtime["network_id"] in networks
    if network_present:
        labels = json.loads(_docker("network", "inspect", runtime["network_id"],
                                    "--format", "{{json .Labels}}"))
        run_name = _docker("network", "inspect", runtime["network_id"],
                           "--format", "{{.Name}}")
        if (not isinstance(labels, dict) or
                labels.get("sovereign.synthetic.install") != installation_id or
                labels.get("sovereign.synthetic.run") != run_name or
                not re.fullmatch(r"sovereign-synthetic-[0-9a-f]{12}", run_name) or
                _docker("network", "inspect", runtime["network_id"],
                        "--format", "{{.Internal}}") != "true"):
            raise VesselInstallError("recorded vessel network identity mismatch")
    else:
        _assert_missing("network", runtime["network_id"])
        run_name = None
    for role in ("core", "console", "knowledge"):
        container_id = runtime[role + "_id"]
        if container_id not in containers:
            _assert_missing("container", container_id)
            continue
        labels = json.loads(_docker("inspect", container_id,
                                    "--format", "{{json .Config.Labels}}"))
        name = _docker("inspect", container_id, "--format", "{{.Name}}")
        mode = _docker("inspect", container_id,
                       "--format", "{{.HostConfig.NetworkMode}}")
        ports = _docker("inspect", container_id,
                        "--format", "{{json .HostConfig.PortBindings}}")
        expected_image = _image_id(stage / "bundle", role,
                                   manifest["images"][role], crane)
        if (not isinstance(labels, dict) or
                labels.get("sovereign.synthetic.install") != installation_id or
                ports not in ("null", "{}") or
                _docker("inspect", container_id, "--format", "{{.Image}}") !=
                expected_image):
            raise VesselInstallError("recorded vessel container identity mismatch")
        if role == "knowledge":
            if (not socket_present or
                    labels.get("sovereign.synthetic.role") != "knowledge" or
                    labels.get("sovereign.synthetic.run") != runtime["knowledge_run"] or
                    name != "/" + runtime["knowledge_run"] or mode != "none"):
                raise VesselInstallError("recorded Knowledge identity mismatch")
            mounts = json.loads(_docker("inspect", container_id,
                                        "--format", "{{json .Mounts}}"))
            required = {"/var/lib/postgresql/data": runtime["data_volume"],
                        "/var/run/postgresql": runtime["socket_volume"]}
            if (not isinstance(mounts, list) or
                    any(sum(isinstance(item, dict) and
                            item.get("Type") == "volume" and
                            item.get("Destination") == destination and
                            item.get("Name") == volume for item in mounts) != 1
                        for destination, volume in required.items())):
                raise VesselInstallError("recorded Knowledge mount mismatch")
        elif (not network_present or labels.get("sovereign.synthetic.run") != run_name
              or labels.get("sovereign.synthetic.role") is not None
              or name != f"/{run_name}-{role}" or mode != run_name):
            raise VesselInstallError("recorded Core or Console identity mismatch")
    if _read_state(root) != value:
        raise VesselInstallError("vessel active state changed during stop completion")
    for role in ("console", "core"):
        if runtime[role + "_id"] in containers:
            _docker("rm", "-f", runtime[role + "_id"])
    if network_present:
        _docker("network", "rm", runtime["network_id"])
    if runtime["knowledge_id"] in containers:
        knowledge = KnowledgeVolumeHandle(runtime["knowledge_id"],
                                          runtime["socket_volume"],
                                          runtime["data_volume"],
                                          runtime["knowledge_run"],
                                          installation_id)
        running = _docker("inspect", knowledge.container_id,
                          "--format", "{{.State.Running}}")
        if running == "true":
            stop_knowledge(knowledge)
        elif running == "false":
            _docker("rm", "-f", knowledge.container_id)
            _docker("volume", "rm", knowledge.socket_volume)
        else:
            raise VesselInstallError("invalid Knowledge running state")
    elif socket_present:
        _docker("volume", "rm", runtime["socket_volume"])
    _recovery_inventory(installation_id, runtime)
    return {"result": "stopped", "active": identifier}


def _remove_scoped_orphans(installation_id: str, data_volume: str,
                           unchanged) -> dict[str, int | str]:
    """Verify the complete scoped inventory before deleting orphan runtime."""
    scope = f"label=sovereign.synthetic.install={installation_id}"
    containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope, "--quiet")
    networks = _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                            "--quiet")
    volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                           volume=True)
    if volumes.count(data_volume) != 1:
        raise VesselInstallError("persistent Knowledge volume missing from inventory")
    sockets = [name for name in volumes if name != data_volume]
    for name in sockets:
        run_name = name.removesuffix("-socket")
        _volume(name, installation_id, "knowledge-socket", create=False,
                run_name=run_name)
    runs: dict[str, str] = {}
    for network_id in networks:
        labels = json.loads(_docker("network", "inspect", network_id,
                                    "--format", "{{json .Labels}}"))
        run_name = _docker("network", "inspect", network_id, "--format", "{{.Name}}")
        if (not re.fullmatch(r"sovereign-synthetic-[0-9a-f]{12}", run_name)
                or not isinstance(labels, dict)
                or labels.get("sovereign.synthetic.install") != installation_id
                or labels.get("sovereign.synthetic.run") != run_name
                or _docker("network", "inspect", network_id,
                           "--format", "{{.Internal}}") != "true"
                or run_name in runs):
            raise VesselInstallError("orphan vessel network identity mismatch")
        runs[run_name] = network_id
    seen: set[tuple[str, str]] = set()
    for container_id in containers:
        labels = json.loads(_docker("inspect", container_id,
                                    "--format", "{{json .Config.Labels}}"))
        name = _docker("inspect", container_id, "--format", "{{.Name}}")
        mode = _docker("inspect", container_id,
                       "--format", "{{.HostConfig.NetworkMode}}")
        ports = _docker("inspect", container_id,
                        "--format", "{{json .HostConfig.PortBindings}}")
        if not isinstance(labels, dict) or \
                labels.get("sovereign.synthetic.install") != installation_id or \
                ports not in ("null", "{}"):
            raise VesselInstallError("orphan vessel container identity mismatch")
        run_name = labels.get("sovereign.synthetic.run")
        role = labels.get("sovereign.synthetic.role")
        if (isinstance(run_name, str)
                and re.fullmatch(r"sovereign-knowledge-[0-9a-f]{12}", run_name)
                and role == "knowledge" and name == "/" + run_name
                and mode == "none" and run_name + "-socket" in sockets):
            key = (run_name, "knowledge")
            mounts = json.loads(_docker("inspect", container_id,
                                        "--format", "{{json .Mounts}}"))
            required = {"/var/lib/postgresql/data": data_volume,
                        "/var/run/postgresql": run_name + "-socket"}
            if (not isinstance(mounts, list) or
                    any(sum(isinstance(item, dict) and
                            item.get("Type") == "volume" and
                            item.get("Destination") == destination and
                            item.get("Name") == volume for item in mounts) != 1
                        for destination, volume in required.items())):
                raise VesselInstallError("orphan Knowledge volume mount mismatch")
        elif (isinstance(run_name, str) and run_name in runs
              and role is None and mode == run_name
              and name in ("/" + run_name + "-core", "/" + run_name + "-console")):
            key = (run_name, name.removeprefix("/" + run_name + "-"))
        else:
            raise VesselInstallError("orphan vessel container identity mismatch")
        if key in seen:
            raise VesselInstallError("duplicate orphan vessel container role")
        seen.add(key)
    if not unchanged():
        raise VesselInstallError("vessel record changed during reconciliation")
    for container_id in containers:
        _docker("rm", "-f", container_id)
    for network_id in networks:
        _docker("network", "rm", network_id)
    for name in sockets:
        _docker("volume", "rm", name)
    return {"result": "reconciled", "containers": len(containers),
            "networks": len(networks), "sockets": len(sockets)}


def _intent_stage(root: Path, trusted_key: Path,
                  intent: dict[str, object]) -> Path:
    identifier = intent["release"]
    stage = root / "vessel-releases" / identifier
    _verify_stage(stage, trusted_key, identifier)
    if (root / "vessel-state.json").exists() or \
            (root / "vessel-state.json").is_symlink():
        raise VesselInstallError("first-install intent has an active record")
    return stage


def _validate_unbound_secrets(root: Path) -> Path | None:
    directory = root / "knowledge-secrets"
    if not directory.exists() and not directory.is_symlink():
        return None
    _owner_directory(directory)
    if not {item.name for item in directory.iterdir()} <= {
            "admin-password", "writer.pgpass", "reader.pgpass", "migrate.pgpass"}:
        raise VesselInstallError("unexpected first-install credential file")
    for item in directory.iterdir():
        if (item.is_symlink() or not item.is_file() or
                item.stat().st_uid != os.getuid() or
                stat.S_IMODE(item.stat().st_mode) & 0o077):
            raise VesselInstallError("invalid first-install credential file")
    return directory


def _clear_unbound_secrets(root: Path) -> None:
    directory = _validate_unbound_secrets(root)
    if directory is not None:
        shutil.rmtree(directory)


def _reject_restore_intent(root: Path) -> None:
    marker = root / "vessel-restore-intent.json"
    if marker.exists() or marker.is_symlink():
        raise VesselInstallError(
            "restore candidate requires explicit recovery reconciliation")


@_serialized
def reconcile_first_install(root: Path, trusted_key: Path,
                            crane: Path) -> dict[str, int | str]:
    """Remove a checked orphan runtime or reset bootstrap before first activation."""
    _reject_restore_intent(root)
    intent = _read_intent(root)
    _intent_stage(root, trusted_key, intent)
    installation_id = intent["installation_id"]
    data_volume = intent["data_volume"]
    scope = f"label=sovereign.synthetic.install={installation_id}"
    volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                           volume=True)
    if data_volume not in volumes:
        if (_scoped_list("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
                _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                             "--quiet") or volumes):
            raise VesselInstallError("first-install resources lack the data volume")
        _assert_missing("volume", data_volume)
        if _read_intent(root) != intent:
            raise VesselInstallError("first-install intent changed")
        _clear_unbound_secrets(root)
        return {"result": "reconciled", "containers": 0,
                "networks": 0, "sockets": 0}
    _volume(data_volume, installation_id, "knowledge-data", create=False)
    result = _remove_scoped_orphans(
        installation_id, data_volume,
        lambda: _read_intent(root) == intent and
        not (root / "vessel-state.json").exists() and
        not (root / "vessel-state.json").is_symlink())
    if (_docker("ps", "-a", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("network", "ls", "--no-trunc", "--filter", scope, "--quiet") or
            _docker("volume", "ls", "--filter", scope, "--quiet") != data_volume):
        raise VesselInstallError("first-install reconciliation is incomplete")
    return result


@_serialized
def reset_first_install(root: Path, trusted_key: Path,
                        crane: Path) -> dict[str, str]:
    """Explicitly discard one clean, labelled synthetic bootstrap data volume."""
    _reject_restore_intent(root)
    intent = _read_intent(root)
    _intent_stage(root, trusted_key, intent)
    installation_id = intent["installation_id"]
    data_volume = intent["data_volume"]
    scope = f"label=sovereign.synthetic.install={installation_id}"
    containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                              "--quiet")
    networks = _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                            "--quiet")
    volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                           volume=True)
    if containers or networks or volumes != [data_volume]:
        raise VesselInstallError("bootstrap reset requires only the data volume")
    _volume(data_volume, installation_id, "knowledge-data", create=False)
    _validate_unbound_secrets(root)
    if (_read_intent(root) != intent or
            (root / "vessel-state.json").exists() or
            (root / "vessel-state.json").is_symlink()):
        raise VesselInstallError("first-install state changed before bootstrap reset")
    _docker("volume", "rm", data_volume)
    _assert_missing("volume", data_volume)
    _clear_unbound_secrets(root)
    return {"result": "bootstrap-reset", "data_volume": "removed"}


@_serialized
def resume_first_install(root: Path, trusted_key: Path,
                         crane: Path) -> dict[str, int | str]:
    """Resume a clean signed first install identified by its durable intent."""
    _reject_restore_intent(root)
    intent = _read_intent(root)
    active_path = root / "vessel-state.json"
    if active_path.exists() or active_path.is_symlink():
        healthy = status_vessel(root, trusted_key, crane)
        recorded = _read_state(root)
        if (healthy.get("result") != "healthy" or
                recorded["active"] != intent["release"] or
                recorded["installation_id"] != intent["installation_id"] or
                recorded["core_state"] != intent["core_state"] or
                recorded["lab_password_file"] != intent["lab_password_file"] or
                recorded["runtime"]["data_volume"] != intent["data_volume"]):
            raise VesselInstallError("active vessel does not match first-install intent")
        (root / "vessel-intent.json").unlink()
        return {"result": "already-activated", "active": intent["release"]}
    stage = _intent_stage(root, trusted_key, intent)
    state = Path(intent["core_state"])
    password = Path(intent["lab_password_file"])
    if (state.resolve().is_relative_to(root.resolve()) or
            password.resolve().is_relative_to(root.resolve())):
        raise VesselInstallError("first-install state and credential must be external")
    installation_id = intent["installation_id"]
    data_volume = intent["data_volume"]
    scope = f"label=sovereign.synthetic.install={installation_id}"
    containers = _scoped_list("ps", "-a", "--no-trunc", "--filter", scope,
                              "--quiet")
    networks = _scoped_list("network", "ls", "--no-trunc", "--filter", scope,
                            "--quiet")
    volumes = _scoped_list("volume", "ls", "--filter", scope, "--quiet",
                           volume=True)
    if containers or networks or volumes not in ([], [data_volume]):
        raise VesselInstallError("first-install resources require reconciliation")
    initialize = not volumes
    if initialize:
        _assert_missing("volume", data_volume)
        if (root / "knowledge-secrets").exists() or \
                (root / "knowledge-secrets").is_symlink():
            raise VesselInstallError("bootstrap credentials require reconciliation")
    else:
        _volume(data_volume, installation_id, "knowledge-data", create=False)
    if _read_intent(root) != intent:
        raise VesselInstallError("first-install intent changed")
    knowledge = None
    services = None
    try:
        knowledge = start_signed_knowledge(stage / "bundle", trusted_key, crane,
                                           root, installation_id,
                                           initialize=initialize)
        _state_options(state, password, root)
        ingestion = _ingest(stage / "bundle", trusted_key, crane, state,
                            root, knowledge)
        services = start_signed_vessel_services(
            stage / "bundle", trusted_key, crane, stage / "console-config.json",
            state, password, root, knowledge, installation_id)
        payload = _state_payload(intent["release"], installation_id, state,
                                 password, services, knowledge)
        _write_state(root, payload)
        try:
            (root / "vessel-intent.json").unlink(missing_ok=True)
        except OSError:
            pass
        return {"result": "activated", "active": intent["release"],
                "indexed": ingestion["indexed"], "unchanged": ingestion["unchanged"]}
    except Exception as exc:
        if (root / "vessel-state.json").exists() or \
                (root / "vessel-state.json").is_symlink():
            raise VesselInstallError(
                "first-install state may have changed; retain runtime for reconciliation"
            ) from exc
        if not _cleanup_failed_install(installation_id, services, knowledge,
                                       data_volume, retain_data=not initialize):
            raise VesselInstallError(
                "first-install resume failed; cleanup incomplete and data retained"
            ) from exc
        raise


@_serialized
def reconcile_vessel(root: Path, trusted_key: Path, crane: Path) -> dict[str, int | str]:
    """Remove checked orphan runtime resources after interrupted recovery."""
    value = _read_state(root)
    identifier = value["active"]
    _verify_stage(root / "vessel-releases" / identifier, trusted_key, identifier)
    state, password = Path(value["core_state"]), Path(value["lab_password_file"])
    _state_options(state, password, root)
    installation_id = value["installation_id"]
    runtime = value["runtime"]
    for kind, old_id in (("container", runtime["core_id"]),
                         ("container", runtime["console_id"]),
                         ("container", runtime["knowledge_id"]),
                         ("network", runtime["network_id"]),
                         ("volume", runtime["socket_volume"])):
        _assert_missing(kind, old_id)
    data_volume = runtime["data_volume"]
    _volume(data_volume, installation_id, "knowledge-data", create=False)
    counts = _remove_scoped_orphans(
        installation_id, data_volume, lambda: _read_state(root) == value)
    _recovery_inventory(installation_id, runtime)
    return counts


@_serialized
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


@_serialized
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
        _verify_knowledge_schema(knowledge)
        services = start_signed_vessel_services(
            stage / "bundle", trusted_key, crane, stage / "console-config.json",
            state, password, root, knowledge, installation_id)
        payload = _state_payload(identifier, installation_id, state, password,
                                 services, knowledge,
                                 previous=value.get("previous"))
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
