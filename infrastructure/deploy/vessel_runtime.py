"""Run signed Core and Console beside a persistent, networkless Knowledge DB.

This is an installation building block. It uses only the three-image vessel
bundle and an already provisioned Knowledge handle; activation records and
coordinated database recovery belong to the installer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from infrastructure.deploy.container_runtime import (
    RuntimeHandle, RuntimeError as ContainerRuntimeError, _docker, _health,
    _image_id, _validate_console_config, stop_runtime, verify_runtime_identity,
)
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, _credentials, probe_knowledge,
)
from infrastructure.deploy.postgres_socket import verify_login
from infrastructure.release.bundle import BundleError, verify_bundle
from services.knowledge.manifest_io import load_manifest
from services.policy.audit import verify as verify_audit
from services.policy.policy_file import load_policy


class VesselRuntimeError(ValueError):
    """The signed three-image service runtime failed its safety checks."""


_READER_DSN = "postgresql://sovereign_read@/postgres?host=/run/postgresql"
_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _private_file(path: Path, *, maximum: int = 4096) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or not 0 < path.stat().st_size <= maximum):
        raise VesselRuntimeError("invalid private vessel runtime file")


def _persistent_file(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if (path.is_symlink() or not path.is_file() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise VesselRuntimeError("invalid persistent vessel Core file")


def _state_options(state: Path, lab_password: Path,
                   knowledge_root: Path) -> tuple[list[str], Path]:
    if (not state.is_absolute() or state.is_symlink() or not state.is_dir()
            or state.stat().st_uid != os.getuid()
            or stat.S_IMODE(state.stat().st_mode) & 0o077):
        raise VesselRuntimeError("Core state must be owner-only")
    if state.resolve().is_relative_to(knowledge_root.resolve()) or \
            knowledge_root.resolve().is_relative_to(state.resolve()):
        raise VesselRuntimeError("Core and Knowledge state overlap")
    policy, manifest = state / "roles.json", state / "approved.json"
    _private_file(policy)
    _private_file(manifest, maximum=1024 * 1024)
    if not isinstance(load_policy(policy), dict):
        raise VesselRuntimeError("Core policy unavailable")
    parsed = load_manifest(manifest)
    if (not isinstance(parsed, dict) or type(parsed.get("schema")) is not int
            or parsed["schema"] != 1 or not isinstance(parsed.get("sources"), list)
            or len(parsed["sources"]) > 10000):
        raise VesselRuntimeError("invalid approved Knowledge manifest")
    sources = state / "sources"
    if (sources.is_symlink() or not sources.is_dir()
            or sources.stat().st_uid != os.getuid()
            or stat.S_IMODE(sources.stat().st_mode) & 0o077):
        raise VesselRuntimeError("invalid Core source directory")
    audit_path = state / "audit.jsonl"
    _persistent_file(audit_path)
    for name in ("history.db", "history.db-wal", "history.db-shm"):
        _persistent_file(state / name)
    try:
        verify_audit(audit_path, require_current_clock=True)
    except (OSError, ValueError) as exc:
        raise VesselRuntimeError("vessel audit trail is invalid") from exc
    _private_file(lab_password)
    if lab_password.resolve().is_relative_to(state.resolve()):
        raise VesselRuntimeError("lab credential must be outside Core state")
    password = lab_password.read_text(encoding="utf-8")
    if (not 16 <= len(password.rstrip("\n")) <= 200 or
            "\r" in password or "\n" in password.rstrip("\n")):
        raise VesselRuntimeError("invalid lab credential length")
    _, _, reader, _, reader_secret = _credentials(knowledge_root, initialize=False)
    options = ["--user", f"{os.getuid()}:{os.getgid()}",
               "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign",
               "--mount", (f"type=bind,source={lab_password.resolve()},"
                           "target=/run/secrets/lab-password,readonly"),
               "--mount", (f"type=bind,source={reader.resolve()},"
                           "target=/run/secrets/pgpass,readonly"),
               "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
               "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
               "-e", "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
               "-e", f"SOVEREIGN_KNOWLEDGE_DB={_READER_DSN}",
               "-e", "SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl",
               "-e", "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
               "-e", "PGPASSFILE=/run/secrets/pgpass"]
    return options, reader


def _core_database_health(core_id: str) -> None:
    _docker("exec", core_id, "python", "-c",
            "from services.knowledge.postgres_index import _connect; "
            "db=_connect('postgresql://sovereign_read@/postgres?host=/run/postgresql'); "
            "assert db.execute('SELECT current_user').fetchone()['current_user']=='sovereign_read'; "
            "assert db.execute('SELECT count(*) AS n FROM knowledge_sources').fetchone()['n']>=1; "
            "db.close()")


def start_signed_vessel_services(bundle: Path, trusted_key: Path, crane: Path,
                                 console_config: Path, state: Path,
                                 lab_password: Path, knowledge_root: Path,
                                 knowledge: KnowledgeVolumeHandle,
                                 installation_id: str) -> RuntimeHandle:
    """Launch verified Core and Console around the checked Knowledge socket."""
    if not _INSTALL.fullmatch(installation_id) or \
            knowledge.installation_id != installation_id:
        raise VesselRuntimeError("vessel installation identity mismatch")
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise BundleError("vessel runtime requires the signed three-image bundle")
    _validate_console_config(console_config)
    if not stat.S_IMODE(console_config.stat().st_mode) & 0o004:
        raise VesselRuntimeError("Console configuration is unreadable by the image user")
    probe_knowledge(knowledge)
    options, reader = _state_options(state, lab_password, knowledge_root)
    reader_secret = _credentials(knowledge_root, initialize=False)[4]
    verify_login(knowledge.container_id, "sovereign_read", reader_secret)
    images = {role: _image_id(bundle, role, manifest["images"][role], crane)
              for role in ("core", "console")}
    name = f"sovereign-synthetic-{uuid.uuid4().hex[:12]}"
    labels = ["--label", f"sovereign.synthetic.run={name}",
              "--label", f"sovereign.synthetic.install={installation_id}"]
    network_id = _docker("network", "create", "--internal", *labels, name)
    if not _DOCKER_ID.fullmatch(network_id) or \
            _docker("network", "inspect", network_id, "--format", "{{.Internal}}") != "true":
        stop_runtime(RuntimeHandle(network_id, "", ""))
        raise VesselRuntimeError("isolated vessel network was not created")
    core_id = console_id = ""
    try:
        core_id = _docker("run", "-d", "--pull", "never", "--name", name + "-core",
                          *labels, "--network", name, "--network-alias", "core",
                          "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                          "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                          "--mount", (f"type=volume,source={knowledge.socket_volume},"
                                      "target=/run/postgresql,readonly"),
                          *options, images["core"])
        console_id = _docker("run", "-d", "--pull", "never", "--name", name + "-console",
                             *labels, "--network", name, "--network-alias", "console",
                             "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                             "--mount", (f"type=bind,source={console_config.resolve()},"
                                         "target=/srv/console-config.json,readonly"),
                             images["console"])
        handle = RuntimeHandle(network_id, core_id, console_id)
        for attempt in range(30):
            try:
                probe_signed_vessel_services(handle, knowledge, state, lab_password,
                                             reader)
                return handle
            except (ContainerRuntimeError, VesselRuntimeError):
                if attempt == 29:
                    raise
                time.sleep(1)
    except Exception:
        stop_runtime(RuntimeHandle(network_id, core_id, console_id))
        raise
    raise AssertionError("unreachable vessel runtime activation")


def probe_signed_vessel_services(handle: RuntimeHandle,
                                 knowledge: KnowledgeVolumeHandle,
                                 state: Path, lab_password: Path,
                                 reader_passfile: Path) -> None:
    """Check persisted image, network, mount and database role boundaries."""
    verify_runtime_identity(handle)
    probe_knowledge(knowledge)
    for identifier in (handle.core_id, handle.console_id):
        if _docker("inspect", identifier, "--format", "{{.State.Running}}") != "true":
            raise VesselRuntimeError("vessel service stopped")
        if _docker("inspect", identifier, "--format",
                   "{{json .HostConfig.PortBindings}}") not in ("null", "{}"):
            raise VesselRuntimeError("vessel service published a host port")
    try:
        mounts = json.loads(_docker("inspect", handle.core_id, "--format",
                                   "{{json .Mounts}}"))
        environment = json.loads(_docker("inspect", handle.core_id, "--format",
                                        "{{json .Config.Env}}"))
    except json.JSONDecodeError as exc:
        raise VesselRuntimeError("invalid Core runtime metadata") from exc
    expected_mounts = {
        "/var/lib/sovereign": ("bind", str(state.resolve()), True),
        "/run/secrets/lab-password": ("bind", str(lab_password.resolve()), False),
        "/run/secrets/pgpass": ("bind", str(reader_passfile.resolve()), False),
        "/run/postgresql": ("volume", knowledge.socket_volume, False),
    }
    if not isinstance(mounts, list) or not isinstance(environment, list):
        raise VesselRuntimeError("invalid Core runtime metadata")
    for destination, (kind, source, writable) in expected_mounts.items():
        matching = [item for item in mounts if isinstance(item, dict)
                    and item.get("Destination") == destination]
        if (len(matching) != 1 or matching[0].get("Type") != kind
                or matching[0].get("Source" if kind == "bind" else "Name") != source
                or matching[0].get("RW") is not writable):
            raise VesselRuntimeError("Core runtime mount changed")
    expected_env = {"SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                    "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                    "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
                    f"SOVEREIGN_KNOWLEDGE_DB={_READER_DSN}",
                    "SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl",
                    "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                    "PGPASSFILE=/run/secrets/pgpass"}
    selected = [item for item in environment if isinstance(item, str) and
                item.split("=", 1)[0] in {entry.split("=", 1)[0]
                                         for entry in expected_env}]
    if len(selected) != len(expected_env) or set(selected) != expected_env:
        raise VesselRuntimeError("Core runtime database environment changed")
    _health(handle.core_id)
    _core_database_health(handle.core_id)
