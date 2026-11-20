"""Provision a signed Knowledge image on a persistent synthetic PG volume.

The data volume survives a stop. The per-run socket volume does not. This is
an installer building block; Core, Console, migration and backup are separate.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import uuid

from infrastructure.deploy.container_runtime import _image_id
from infrastructure.deploy.postgres_socket import (
    docker, ready, secure_database, verify_login, verify_security,
)
from infrastructure.release.bundle import BundleError, verify_bundle


class KnowledgeVolumeError(ValueError):
    """The persistent Knowledge runtime cannot be safely started."""


@dataclass(frozen=True)
class KnowledgeVolumeHandle:
    container_id: str
    socket_volume: str
    data_volume: str
    run_name: str
    installation_id: str


_INSTALL = re.compile(r"[0-9a-f]{32}\Z")
_DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _private_root(root: Path) -> None:
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root.stat().st_uid != os.getuid()
            or stat.S_IMODE(root.stat().st_mode) & 0o077):
        raise KnowledgeVolumeError("Knowledge installation root must be owner-only")


def _secret(path: Path, content: str | None = None) -> str:
    if content is not None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or not 0 < path.stat().st_size <= 256):
        raise KnowledgeVolumeError("invalid Knowledge credential file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW |
                         os.O_CLOEXEC)
    with os.fdopen(descriptor, "r", encoding="ascii") as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o077
                or not 0 < details.st_size <= 256):
            raise KnowledgeVolumeError("invalid Knowledge credential file")
        raw = stream.read(257)
    return raw


def _credentials(root: Path, *, initialize: bool) -> tuple[Path, Path, Path, str, str]:
    directory = root / "knowledge-secrets"
    if initialize:
        directory.mkdir(mode=0o700)
    _private_root(directory)
    admin = directory / "admin-password"
    writer = directory / "writer.pgpass"
    reader = directory / "reader.pgpass"
    if initialize:
        admin_secret, writer_secret, reader_secret = (secrets.token_hex(32)
                                                      for _ in range(3))
        _secret(admin, admin_secret + "\n")
        _secret(writer, f"/run/postgresql:5432:postgres:sovereign_ingest:{writer_secret}\n")
        _secret(reader, f"/run/postgresql:5432:postgres:sovereign_read:{reader_secret}\n")
    else:
        if not re.fullmatch(r"[0-9a-f]{64}\n", _secret(admin)):
            raise KnowledgeVolumeError("invalid Knowledge administrator credential")
        writer_secret = _secret(writer).removeprefix(
            "/run/postgresql:5432:postgres:sovereign_ingest:").strip()
        reader_secret = _secret(reader).removeprefix(
            "/run/postgresql:5432:postgres:sovereign_read:").strip()
    if (not re.fullmatch(r"[0-9a-f]{64}", writer_secret)
            or not re.fullmatch(r"[0-9a-f]{64}", reader_secret)
            or _secret(writer) !=
            f"/run/postgresql:5432:postgres:sovereign_ingest:{writer_secret}\n"
            or _secret(reader) !=
            f"/run/postgresql:5432:postgres:sovereign_read:{reader_secret}\n"):
        raise KnowledgeVolumeError("invalid Knowledge role credentials")
    return admin, writer, reader, writer_secret, reader_secret


def _volume(name: str, installation_id: str, role: str, *, create: bool,
            run_name: str | None = None) -> None:
    if create:
        probe = subprocess.run(["docker", "volume", "inspect", name],
                               capture_output=True, timeout=10)
        if probe.returncode == 0:
            raise KnowledgeVolumeError("Knowledge volume already exists")
        if b"No such volume" not in probe.stderr:
            raise KnowledgeVolumeError("cannot confirm Knowledge volume absence")
        labels = ["--label", f"sovereign.synthetic.install={installation_id}",
                  "--label", f"sovereign.synthetic.role={role}"]
        if run_name is not None:
            labels += ["--label", f"sovereign.synthetic.run={run_name}"]
        docker("volume", "create", *labels, name)
    raw = docker("volume", "inspect", name, "--format", "{{json .}}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KnowledgeVolumeError("invalid Knowledge volume metadata") from exc
    expected = {"sovereign.synthetic.install": installation_id,
                "sovereign.synthetic.role": role}
    if run_name is not None:
        expected["sovereign.synthetic.run"] = run_name
    if (not isinstance(value, dict) or value.get("Name") != name
            or value.get("Driver") != "local"
            or not isinstance(value.get("Labels"), dict)
            or any(value["Labels"].get(key) != label for key, label in expected.items())):
        raise KnowledgeVolumeError("Knowledge volume identity mismatch")


def start_signed_knowledge(bundle: Path, trusted_key: Path, crane: Path,
                           root: Path, installation_id: str, *,
                           initialize: bool) -> KnowledgeVolumeHandle:
    """Start the exact signed Knowledge archive with durable data and private socket."""
    _private_root(root)
    if not _INSTALL.fullmatch(installation_id):
        raise KnowledgeVolumeError("invalid Knowledge installation identifier")
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 6 or manifest.get("target") != "vessel":
        raise BundleError("Knowledge runtime requires a signed vessel bundle")
    image_id = _image_id(bundle, "knowledge", manifest["images"]["knowledge"], crane)
    data_name = f"sovereign-{installation_id}-knowledge-data"
    run_name = f"sovereign-knowledge-{uuid.uuid4().hex[:12]}"
    socket_name = run_name + "-socket"
    created_data = created_socket = False
    container = ""
    try:
        admin, _, _, writer_secret, reader_secret = _credentials(
            root, initialize=initialize)
        _volume(data_name, installation_id, "knowledge-data", create=initialize)
        created_data = initialize
        _volume(socket_name, installation_id, "knowledge-socket", create=True,
                run_name=run_name)
        created_socket = True
        container = docker(
            "run", "-d", "--pull", "never", "--name", run_name,
            "--label", f"sovereign.synthetic.install={installation_id}",
            "--label", f"sovereign.synthetic.run={run_name}",
            "--label", "sovereign.synthetic.role=knowledge",
            "--network", "none",
            "--mount", f"type=volume,source={data_name},target=/var/lib/postgresql/data",
            "--mount", f"type=volume,source={socket_name},target=/var/run/postgresql",
            "--mount", (f"type=bind,source={admin.resolve()},"
                        "target=/run/secrets/postgres-password,readonly"),
            "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password", image_id)
        if not _DOCKER_ID.fullmatch(container):
            raise KnowledgeVolumeError("invalid Knowledge container identity")
        if (docker("inspect", container, "--format", "{{.HostConfig.NetworkMode}}") != "none"
                or docker("inspect", container, "--format",
                          "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
            raise KnowledgeVolumeError("Knowledge container has a network route")
        ready(container)
        if initialize:
            secure_database(container, writer_secret, reader_secret)
        else:
            verify_security(container)
        verify_login(container, "sovereign_ingest", writer_secret)
        verify_login(container, "sovereign_read", reader_secret)
        return KnowledgeVolumeHandle(container, socket_name, data_name, run_name,
                                     installation_id)
    except Exception:
        if container:
            try:
                docker("rm", "-f", container)
            except Exception:
                pass
        if created_socket:
            try:
                docker("volume", "rm", socket_name)
            except Exception:
                pass
        if created_data:
            try:
                docker("volume", "rm", data_name)
            except Exception:
                pass
        if initialize:
            shutil.rmtree(root / "knowledge-secrets", ignore_errors=True)
        raise


def stop_knowledge(handle: KnowledgeVolumeHandle) -> None:
    """Stop one runtime and discard only its socket; retain database data."""
    if (not _DOCKER_ID.fullmatch(handle.container_id)
            or not _INSTALL.fullmatch(handle.installation_id)
            or handle.data_volume !=
            f"sovereign-{handle.installation_id}-knowledge-data"
            or handle.socket_volume != handle.run_name + "-socket"
            or not re.fullmatch(r"sovereign-knowledge-[0-9a-f]{12}", handle.run_name)):
        raise KnowledgeVolumeError("invalid Knowledge runtime handle")
    labels = json.loads(docker("inspect", handle.container_id, "--format",
                               "{{json .Config.Labels}}"))
    if (not isinstance(labels, dict)
            or labels.get("sovereign.synthetic.install") != handle.installation_id
            or labels.get("sovereign.synthetic.run") != handle.run_name
            or labels.get("sovereign.synthetic.role") != "knowledge"):
        raise KnowledgeVolumeError("Knowledge container identity mismatch")
    _volume(handle.socket_volume, handle.installation_id, "knowledge-socket",
            create=False, run_name=handle.run_name)
    _volume(handle.data_volume, handle.installation_id, "knowledge-data",
            create=False)
    docker("stop", "-t", "15", handle.container_id, timeout=30)
    docker("rm", handle.container_id)
    docker("volume", "rm", handle.socket_volume)
