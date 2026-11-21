"""Run signed Core and Console beside a persistent, networkless Knowledge DB.

This is an installation building block. It uses only the three-image vessel
bundle and an already provisioned Knowledge handle; activation records and
coordinated database recovery belong to the installer.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
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
from infrastructure.deploy.vessel_identity import VesselIdentity, preflight_vessel_identity
from infrastructure.release.bundle import (
    BundleError, require_supported_vessel_compatibility, verify_bundle,
)
from services.knowledge.manifest_io import load_manifest
from services.policy.audit import verify as verify_audit
from services.policy.policy_file import load_policy
from apps.api.auth import _history_shape, verify_history_format
from services.intelligence.threat_snapshot import ThreatSnapshotReader


class VesselRuntimeError(ValueError):
    """The signed three-image service runtime failed its safety checks."""


_READER_DSN = "postgresql://sovereign_read@/postgres?host=/run/postgresql"
_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_MODEL_ENDPOINT = "http://127.0.0.1:11434/v1"
_FEED_STORE = "/run/sovereign-threat"
_FEED_KEY = "/run/secrets/threat-snapshot-key"


@dataclass(frozen=True)
class ThreatFeedMount:
    store: Path
    trusted_key: Path


def _feed_options(feed: ThreatFeedMount, state: Path,
                  knowledge_root: Path | None) -> list[str]:
    store, key = feed.store, feed.trusted_key
    if (not store.is_absolute() or store.is_symlink() or not store.is_dir()
            or store.stat().st_uid != os.getuid()
            or stat.S_IMODE(store.stat().st_mode) & 0o077):
        raise VesselRuntimeError("threat feed store must be an owner-only directory")
    _private_file(key)
    if key.stat().st_nlink != 1:
        raise VesselRuntimeError("threat feed key must have one link")
    for source in (state, *([knowledge_root] if knowledge_root is not None else [])):
        if (store.resolve().is_relative_to(source.resolve()) or
                source.resolve().is_relative_to(store.resolve()) or
                key.resolve().is_relative_to(source.resolve())):
            raise VesselRuntimeError("threat feed must be separate from writable state")
    if key.resolve().is_relative_to(store.resolve()):
        raise VesselRuntimeError("threat feed key must be outside its store")
    # Core verifies the signature again on every status read. This preflight
    # rejects a corrupt package before starting a new signed runtime.
    ThreatSnapshotReader(store, key).status()
    return ["--mount", f"type=bind,source={store.resolve()},target={_FEED_STORE},readonly",
            "--mount", f"type=bind,source={key.resolve()},target={_FEED_KEY},readonly",
            "-e", f"SOVEREIGN_THREAT_SNAPSHOT_STORE={_FEED_STORE}",
            "-e", f"SOVEREIGN_THREAT_SNAPSHOT_KEY={_FEED_KEY}"]


def _signed_model_id(manifest: dict[str, object]) -> str | None:
    return manifest["model"]["id"] if manifest["schema"] in (7, 8) else None


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


def _state_options(state: Path, lab_password: Path | None,
                   knowledge_root: Path, *,
                   allow_legacy_history: bool = False,
                   model_id: str | None = None,
                   identity: VesselIdentity | None = None,
                   threat_feed: ThreatFeedMount | None = None) -> tuple[list[str], Path]:
    if model_id is not None and not _MODEL_ID.fullmatch(model_id):
        raise VesselRuntimeError("invalid signed model request name")
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
    history = state / "history.db"
    if allow_legacy_history and not history.exists():
        raise VesselRuntimeError("legacy vessel Core history is missing")
    if history.exists():
        try:
            with closing(sqlite3.connect(history.resolve().as_uri() + "?mode=ro",
                                         uri=True)) as database:
                if allow_legacy_history:
                    if database.execute("PRAGMA user_version").fetchone() != (0,):
                        raise ValueError("Core history is not legacy")
                    _history_shape(database)
                else:
                    verify_history_format(database)
        except (sqlite3.DatabaseError, ValueError) as exc:
            raise VesselRuntimeError("unsupported vessel Core history format") from exc
    try:
        verify_audit(audit_path, require_current_clock=True)
    except (OSError, ValueError) as exc:
        raise VesselRuntimeError("vessel audit trail is invalid") from exc
    if identity is None:
        if lab_password is None:
            raise VesselRuntimeError("lab credential is required in lab mode")
        _private_file(lab_password)
        if lab_password.resolve().is_relative_to(state.resolve()):
            raise VesselRuntimeError("lab credential must be outside Core state")
        password = lab_password.read_text(encoding="utf-8")
        if (not 16 <= len(password.rstrip("\n")) <= 200 or
                "\r" in password or "\n" in password.rstrip("\n")):
            raise VesselRuntimeError("invalid lab credential length")
    elif lab_password is not None:
        raise VesselRuntimeError("OIDC mode cannot mount a lab credential")
    _, _, reader, _, reader_secret = _credentials(knowledge_root, initialize=False)
    options = ["--user", f"{os.getuid()}:{os.getgid()}",
               "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign",
               "--mount", (f"type=bind,source={reader.resolve()},"
                           "target=/run/secrets/pgpass,readonly"),
               "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
               "-e", "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
               "-e", f"SOVEREIGN_KNOWLEDGE_DB={_READER_DSN}",
               "-e", "SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl",
               "-e", "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
               "-e", "PGPASSFILE=/run/secrets/pgpass"]
    if identity is None:
        assert lab_password is not None
        options += ["--mount", (f"type=bind,source={lab_password.resolve()},"
                                "target=/run/secrets/lab-password,readonly"),
                    "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password"]
    else:
        if (identity.ca_file != state / "oidc-ca.pem" or
                identity.revocations_file != state / "oidc-revocations.jsonl"):
            raise VesselRuntimeError("OIDC material must live in Core state")
        options += ["-e", f"SOVEREIGN_OIDC_ISSUER={identity.issuer}",
                    "-e", "SOVEREIGN_OIDC_CA_FILE=/var/lib/sovereign/oidc-ca.pem",
                    "-e", "SOVEREIGN_OIDC_REVOCATIONS=/var/lib/sovereign/oidc-revocations.jsonl"]
    if model_id is not None:
        options += ["-e", f"SOVEREIGN_MODEL_NAME={model_id}",
                    "-e", f"SOVEREIGN_MODEL_ENDPOINT={_MODEL_ENDPOINT}"]
    if threat_feed is not None:
        options += _feed_options(threat_feed, state, knowledge_root)
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
                                 lab_password: Path | None, knowledge_root: Path,
                                 knowledge: KnowledgeVolumeHandle,
                                 installation_id: str, *,
                                 restore_attempt: str | None = None,
                                 identity: VesselIdentity | None = None,
                                 threat_feed: ThreatFeedMount | None = None) -> RuntimeHandle:
    """Launch verified Core and Console around the checked Knowledge socket."""
    if not _INSTALL.fullmatch(installation_id) or \
            knowledge.installation_id != installation_id:
        raise VesselRuntimeError("vessel installation identity mismatch")
    if restore_attempt is not None and not _INSTALL.fullmatch(restore_attempt):
        raise VesselRuntimeError("invalid vessel restore attempt")
    manifest = verify_bundle(bundle, trusted_key)
    require_supported_vessel_compatibility(manifest)
    model_id = _signed_model_id(manifest)
    issuer = _validate_console_config(console_config, allow_oidc=identity is not None)
    if issuer != (identity.issuer if identity is not None else None):
        raise VesselRuntimeError("Core and Console OIDC issuer mismatch")
    if identity is not None and preflight_vessel_identity(
            console_config, state, identity.network_name) != identity:
        raise VesselRuntimeError("vessel identity resource changed")
    if not stat.S_IMODE(console_config.stat().st_mode) & 0o004:
        raise VesselRuntimeError("Console configuration is unreadable by the image user")
    probe_knowledge(knowledge)
    options, reader = _state_options(state, lab_password, knowledge_root,
                                     model_id=model_id, identity=identity,
                                     threat_feed=threat_feed)
    reader_secret = _credentials(knowledge_root, initialize=False)[4]
    verify_login(knowledge.container_id, "sovereign_read", reader_secret)
    images = {role: _image_id(bundle, role, manifest["images"][role], crane)
              for role in ("core", "console")}
    name = f"sovereign-synthetic-{uuid.uuid4().hex[:12]}"
    labels = ["--label", f"sovereign.synthetic.run={name}",
              "--label", f"sovereign.synthetic.install={installation_id}"]
    if restore_attempt is not None:
        labels += ["--label", f"sovereign.synthetic.restore_attempt={restore_attempt}"]
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
        if identity is not None:
            _docker("network", "connect", identity.network_name, core_id)
        console_id = _docker("run", "-d", "--pull", "never", "--name", name + "-console",
                             *labels, "--network", name, "--network-alias", "console",
                             "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                             "--mount", (f"type=bind,source={console_config.resolve()},"
                                         "target=/srv/console-config.json,readonly"),
                             images["console"])
        handle = RuntimeHandle(network_id, core_id, console_id,
                               identity.network_id if identity else None,
                               identity.network_name if identity else None)
        for attempt in range(30):
            try:
                probe_signed_vessel_services(handle, knowledge, state, lab_password,
                                             reader, model_id=model_id, identity=identity,
                                             threat_feed=threat_feed)
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
                                 state: Path, lab_password: Path | None,
                                 reader_passfile: Path,
                                 *, model_id: str | None = None,
                                 identity: VesselIdentity | None = None,
                                 threat_feed: ThreatFeedMount | None = None) -> None:
    """Check persisted image, network, mount and database role boundaries."""
    verify_runtime_identity(handle)
    if ((identity is None) != (handle.identity_network_id is None) or
            (identity is not None and
             (handle.identity_network_id != identity.network_id or
              handle.identity_network_name != identity.network_name))):
        raise VesselRuntimeError("vessel identity network mode changed")
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
        "/run/secrets/pgpass": ("bind", str(reader_passfile.resolve()), False),
        "/run/postgresql": ("volume", knowledge.socket_volume, False),
    }
    if identity is None:
        if lab_password is None:
            raise VesselRuntimeError("lab credential is missing")
        expected_mounts["/run/secrets/lab-password"] = (
            "bind", str(lab_password.resolve()), False)
    elif lab_password is not None:
        raise VesselRuntimeError("OIDC runtime has a lab credential")
    if threat_feed is not None:
        _feed_options(threat_feed, state, None)
        expected_mounts[_FEED_STORE] = ("bind", str(threat_feed.store.resolve()), False)
        expected_mounts[_FEED_KEY] = ("bind", str(threat_feed.trusted_key.resolve()), False)
    if not isinstance(mounts, list) or not isinstance(environment, list):
        raise VesselRuntimeError("invalid Core runtime metadata")
    if threat_feed is None and any(
            isinstance(item, dict) and item.get("Destination") in {_FEED_STORE, _FEED_KEY}
            for item in mounts):
        raise VesselRuntimeError("unconfigured threat feed mount")
    if identity is not None and any(
            isinstance(item, dict) and item.get("Destination") == "/run/secrets/lab-password"
            for item in mounts):
        raise VesselRuntimeError("OIDC Core retained a lab credential mount")
    for destination, (kind, source, writable) in expected_mounts.items():
        matching = [item for item in mounts if isinstance(item, dict)
                    and item.get("Destination") == destination]
        if (len(matching) != 1 or matching[0].get("Type") != kind
                or matching[0].get("Source" if kind == "bind" else "Name") != source
                or matching[0].get("RW") is not writable):
            raise VesselRuntimeError("Core runtime mount changed")
    expected_env = {"SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                    "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
                    f"SOVEREIGN_KNOWLEDGE_DB={_READER_DSN}",
                    "SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl",
                    "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                    "PGPASSFILE=/run/secrets/pgpass"}
    if identity is None:
        expected_env.add("SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password")
    else:
        expected_env.update({f"SOVEREIGN_OIDC_ISSUER={identity.issuer}",
                             "SOVEREIGN_OIDC_CA_FILE=/var/lib/sovereign/oidc-ca.pem",
                             "SOVEREIGN_OIDC_REVOCATIONS=/var/lib/sovereign/oidc-revocations.jsonl"})
    if model_id is not None:
        if not _MODEL_ID.fullmatch(model_id):
            raise VesselRuntimeError("invalid signed model request name")
        expected_env.update({f"SOVEREIGN_MODEL_NAME={model_id}",
                             f"SOVEREIGN_MODEL_ENDPOINT={_MODEL_ENDPOINT}"})
    if threat_feed is not None:
        expected_env.update({f"SOVEREIGN_THREAT_SNAPSHOT_STORE={_FEED_STORE}",
                             f"SOVEREIGN_THREAT_SNAPSHOT_KEY={_FEED_KEY}"})
    checked_names = {entry.split("=", 1)[0] for entry in expected_env}
    checked_names.update({"SOVEREIGN_MODEL_NAME", "SOVEREIGN_MODEL_ENDPOINT",
                          "SOVEREIGN_LAB_PASSWORD_FILE", "SOVEREIGN_OIDC_ISSUER",
                          "SOVEREIGN_OIDC_CA_FILE", "SOVEREIGN_OIDC_REVOCATIONS",
                          "SOVEREIGN_THREAT_SNAPSHOT_STORE", "SOVEREIGN_THREAT_SNAPSHOT_KEY"})
    selected = [item for item in environment if isinstance(item, str) and
                item.split("=", 1)[0] in checked_names]
    if len(selected) != len(expected_env) or set(selected) != expected_env:
        raise VesselRuntimeError("Core runtime environment changed")
    _health(handle.core_id, issuer=identity.issuer if identity else None)
    if identity is not None:
        _docker("exec", handle.core_id, "python", "-c",
                'import json, ssl, urllib.request; '
                'ctx=ssl.create_default_context(cafile="/var/lib/sovereign/oidc-ca.pem"); '
                f'keys=json.load(urllib.request.urlopen({identity.issuer!r} + '
                '"/protocol/openid-connect/certs", timeout=5, context=ctx)); '
                'assert isinstance(keys.get("keys"),list) and keys["keys"]')
    _core_database_health(handle.core_id)
