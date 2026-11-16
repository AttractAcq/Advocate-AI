"""Launch a verified synthetic two-image bundle on an isolated Docker network.

This is a disposable lab rehearsal. It never publishes a host port or starts
model, identity, NAS or Wazuh services.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time
import uuid

from infrastructure.release.bundle import BundleError, verify_bundle
from infrastructure.release.upstream import validate_image_archive


class RuntimeError(ValueError):
    """A verified image could not be loaded or safely started in the lab."""


@dataclass(frozen=True)
class RuntimeHandle:
    network_id: str
    core_id: str
    console_id: str


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _core_state_options(state: Path | None, password_file: Path | None) -> list[str]:
    """Validate and mount disposable, restored lab state outside signed images."""
    if state is None and password_file is None:
        return []
    if state is None or password_file is None:
        raise RuntimeError("Core state and lab credential must be supplied together")
    if (not state.is_absolute() or state.is_symlink() or not state.is_dir()
            or state.stat().st_uid != os.getuid()
            or stat.S_IMODE(state.stat().st_mode) & 0o077):
        raise RuntimeError("Core state directory must be owner-only")
    for relative in ("roles.json", "manifest.csv", "history.db"):
        item = state / relative
        if (item.is_symlink() or not item.is_file() or
                item.stat().st_uid != os.getuid() or
                stat.S_IMODE(item.stat().st_mode) & 0o022):
            raise RuntimeError("invalid restored Core state file")
    sources = state / "sources"
    if (sources.is_symlink() or not sources.is_dir() or
            sources.stat().st_uid != os.getuid() or
            stat.S_IMODE(sources.stat().st_mode) & 0o022):
        raise RuntimeError("invalid restored Core source directory")
    if (not password_file.is_absolute() or password_file.is_symlink() or
            not password_file.is_file() or password_file.stat().st_uid != os.getuid()
            or stat.S_IMODE(password_file.stat().st_mode) & 0o077
            or password_file.stat().st_size > 4096
            or password_file.resolve().is_relative_to(state.resolve())):
        raise RuntimeError("invalid separate synthetic lab credential")
    return ["--user", f"{os.getuid()}:{os.getgid()}",
            "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign",
            "--mount", (f"type=bind,source={password_file.resolve()},"
                        "target=/run/secrets/lab-password,readonly"),
            "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
            "-e", "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
            "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password"]


def _archive_image_ids(archive: Path, role: str) -> set[str]:
    """Read IDs bound to the one platform image in a validated Docker save."""
    try:
        with tarfile.open(archive, "r") as stream:
            members_by_name: dict[str, list[tarfile.TarInfo]] = {}
            for member in stream.getmembers():
                members_by_name.setdefault(member.name, []).append(member)

            def small_bytes(name: str) -> bytes:
                members = members_by_name.get(name, [])
                if len(members) != 1 or not members[0].isfile() or members[0].size > 1024 * 1024:
                    raise RuntimeError("invalid archive control file")
                source = stream.extractfile(members[0])
                if source is None:
                    raise RuntimeError("missing archive control file")
                return source.read()

            def small_json(name: str) -> object:
                return json.loads(small_bytes(name))

            def blob(digest: str) -> object:
                if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                    raise RuntimeError("invalid OCI blob digest")
                raw = small_bytes("blobs/sha256/" + digest[7:])
                if hashlib.sha256(raw).hexdigest() != digest[7:]:
                    raise RuntimeError("OCI image blob hash mismatch")
                return json.loads(raw)

            docker_manifest = small_json("manifest.json")
            if (not isinstance(docker_manifest, list) or len(docker_manifest) != 1 or
                    docker_manifest[0].get("RepoTags") != [f"sovereign-{role}:synthetic"]):
                raise RuntimeError("archive is not the expected single synthetic image")
            config_path = docker_manifest[0].get("Config")
            if isinstance(config_path, str) and re.fullmatch(r"[0-9a-f]{64}\.json", config_path):
                config_digest = "sha256:" + config_path[:-5]
            elif isinstance(config_path, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_path):
                config_digest = "sha256:" + config_path.rsplit("/", 1)[-1]
            else:
                raise RuntimeError("invalid Docker configuration path")
            config_bytes = small_bytes(config_path)
            if hashlib.sha256(config_bytes).hexdigest() != config_digest[7:]:
                raise RuntimeError("Docker image configuration hash mismatch")
            if "index.json" not in members_by_name:
                return {config_digest}
            index_bytes = small_bytes("index.json")
            index = json.loads(index_bytes)
            if (not isinstance(index, dict) or index.get("schemaVersion") != 2 or
                    not isinstance(index.get("manifests"), list) or
                    not 1 <= len(index["manifests"]) <= 10):
                raise RuntimeError("invalid OCI image index")
            matches: list[set[str]] = []
            seen: set[str] = set()

            def walk(descriptor: object, depth: int, ancestors: set[str]) -> None:
                if not isinstance(descriptor, dict) or depth > 3:
                    raise RuntimeError("invalid OCI descriptor")
                digest = descriptor.get("digest")
                if not isinstance(digest, str) or digest in seen:
                    raise RuntimeError("duplicate OCI descriptor")
                seen.add(digest)
                document = blob(digest)
                if not isinstance(document, dict):
                    raise RuntimeError("invalid OCI descriptor content")
                if isinstance(document.get("config"), dict):
                    if document["config"].get("digest") == config_digest:
                        matches.append(ancestors | {digest})
                elif isinstance(document.get("manifests"), list):
                    children = document["manifests"]
                    if not 1 <= len(children) <= 10:
                        raise RuntimeError("invalid nested OCI index")
                    for child in children:
                        walk(child, depth + 1, ancestors | {digest})
                else:
                    raise RuntimeError("invalid OCI image manifest")

            for descriptor in index["manifests"]:
                walk(descriptor, 0, set())
            if len(matches) != 1:
                raise RuntimeError("OCI index does not identify one Docker image")
            return matches[0] | {config_digest, "sha256:" + hashlib.sha256(index_bytes).hexdigest()}
    except (OSError, tarfile.TarError, json.JSONDecodeError, TypeError, AttributeError, KeyError) as exc:
        raise RuntimeError("invalid single-image archive metadata") from exc


def _docker(*args: str, timeout: int = 120) -> str:
    try:
        completed = subprocess.run(["docker", *args], capture_output=True, text=True,
                                   check=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Docker operation failed: {args[0]} {args[1] if len(args) > 1 else ''}") from exc
    return completed.stdout.strip()


def _image_id(bundle: Path, role: str, item: dict[str, str], crane: Path) -> str:
    archive = bundle / item["archive_path"]
    identity = validate_image_archive(archive, item["image_ref"], crane,
                                      item["crane_sha256"])
    if identity["archive_sha256"] != item["archive_sha256"]:
        raise RuntimeError("image archive changed after bundle verification")
    expected_ids = _archive_image_ids(archive, role)
    _docker("load", "-i", str(archive), timeout=300)
    tag = f"sovereign-{role}:synthetic"
    raw = _docker("image", "inspect", tag, "--format", "{{json .RepoDigests}}|{{.Id}}")
    try:
        digests_json, image_id = raw.split("|", 1)
        digests = json.loads(digests_json)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("loaded image has invalid identity") from exc
    if (not isinstance(digests, list) or
            image_id not in expected_ids or
            not image_id.startswith("sha256:") or len(image_id) != 71):
        raise RuntimeError(f"loaded image does not match signed archive: "
                           f"loaded={image_id} expected={sorted(expected_ids)} "
                           f"repo_digests={digests}")
    return image_id


def _validate_console_config(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise RuntimeError("synthetic Console configuration is missing or linked")
    try:
        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate configuration key")
                result[key] = value
            return result

        config = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("invalid synthetic Console configuration") from exc
    if (not isinstance(config, dict) or
            config != {"schema": 1, "oidc_issuer": None} or type(config["schema"]) is not int):
        raise RuntimeError("only the synthetic no-issuer Console configuration is allowed")


def _health(core_id: str) -> None:
    _docker("exec", core_id, "python", "-c",
            'import urllib.error, urllib.request; '
            'assert urllib.request.urlopen("http://127.0.0.1:18100/health", timeout=3).status == 200')
    _docker("exec", core_id, "python", "-c",
            'import json, urllib.request; '
            'r=urllib.request.urlopen("http://console:8080/console-config.json", timeout=3); '
            'assert json.load(r)=={"schema":1,"oidc_issuer":None}; '
            'assert r.headers["Cache-Control"]=="no-store"')
    _docker("exec", core_id, "python", "-c",
            'import urllib.request; '
            'assert b"root" in urllib.request.urlopen("http://console:8080/", timeout=3).read()')
    _docker("exec", core_id, "python", "-c",
            'import urllib.error, urllib.request\n'
            'try:\n urllib.request.urlopen("http://console:8080/api/models", timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code == 401\n'
            'else:\n raise AssertionError("unauthorised API passed")')


def stop_runtime(handle: RuntimeHandle) -> None:
    """Remove only resources created by this invocation."""
    for identifier in (handle.console_id, handle.core_id):
        if identifier:
            try:
                _docker("rm", "-f", identifier)
            except RuntimeError:
                pass
    if handle.network_id:
        try:
            _docker("network", "rm", handle.network_id)
        except RuntimeError:
            pass


def verify_runtime_identity(handle: RuntimeHandle) -> None:
    """Bind persisted Docker IDs to one labelled internal synthetic network."""
    run_name = _docker("network", "inspect", handle.network_id, "--format",
                       '{{index .Labels "sovereign.synthetic.run"}}')
    if (not re.fullmatch(r"sovereign-synthetic-[0-9a-f]{12}", run_name) or
            _docker("network", "inspect", handle.network_id, "--format",
                    "{{.Internal}}") != "true"):
        raise RuntimeError("synthetic runtime network identity mismatch")
    for identifier in (handle.core_id, handle.console_id):
        if _docker("inspect", identifier, "--format",
                   '{{index .Config.Labels "sovereign.synthetic.run"}}') != run_name:
            raise RuntimeError("synthetic runtime container identity mismatch")
        networks = json.loads(_docker("inspect", identifier, "--format",
                                    "{{json .NetworkSettings.Networks}}"))
        if (not isinstance(networks, dict) or len(networks) != 1 or
                run_name not in networks or not isinstance(networks[run_name], dict) or
                networks[run_name].get("NetworkID") != handle.network_id):
            raise RuntimeError("synthetic runtime network attachment mismatch")


def _verify_core_state_runtime(handle: RuntimeHandle, core_state: Path | None,
                               lab_password_file: Path | None) -> None:
    """Check that a running Core still uses the installation's declared mounts."""
    _core_state_options(core_state, lab_password_file)
    try:
        mounts = json.loads(_docker("inspect", handle.core_id, "--format", "{{json .Mounts}}"))
        environment = json.loads(_docker("inspect", handle.core_id, "--format",
                                         "{{json .Config.Env}}"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("invalid Core runtime mount metadata") from exc
    if not isinstance(mounts, list) or not isinstance(environment, list):
        raise RuntimeError("invalid Core runtime mount metadata")
    targets = {"/var/lib/sovereign", "/run/secrets/lab-password"}
    selected = [item for item in mounts if isinstance(item, dict)
                and item.get("Destination") in targets]
    prefixes = ("SOVEREIGN_FIXTURE_ROOT=", "SOVEREIGN_HISTORY_DB=",
                "SOVEREIGN_LAB_PASSWORD_FILE=")
    relevant = [item for item in environment if isinstance(item, str)
                and item.startswith(prefixes)]
    if core_state is None:
        if selected or relevant:
            raise RuntimeError("unexpected Core state mount")
        return
    expected = {"/var/lib/sovereign": ("bind", str(core_state.resolve()), True),
                "/run/secrets/lab-password": ("bind", str(lab_password_file.resolve()), False)}
    if (len(selected) != 2 or
            {item["Destination"]: (item.get("Type"), item.get("Source"), item.get("RW"))
             for item in selected} != expected or
            _docker("inspect", handle.core_id, "--format", "{{.Config.User}}") !=
            f"{os.getuid()}:{os.getgid()}"):
        raise RuntimeError("Core state mount identity mismatch")
    required = {"SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password"}
    if len(relevant) != 3 or set(relevant) != required:
        raise RuntimeError("Core state environment mismatch")


def probe_runtime(handle: RuntimeHandle, core_state: Path | None = None,
                  lab_password_file: Path | None = None) -> None:
    """Fail if the current Core and Console no longer satisfy lab health checks."""
    verify_runtime_identity(handle)
    for identifier in (handle.core_id, handle.console_id):
        if _docker("inspect", identifier, "--format", "{{.State.Running}}") != "true":
            raise RuntimeError("synthetic runtime is stopped")
    _verify_core_state_runtime(handle, core_state, lab_password_file)
    _health(handle.core_id)


def cleanup_orphan_runtimes(installation_id: str,
                            active: RuntimeHandle) -> dict[str, int]:
    """Remove only labelled synthetic resources outside the verified active pair."""
    if not re.fullmatch(r"[0-9a-f]{32}", installation_id):
        raise RuntimeError("invalid synthetic installation identifier")
    scope = f"label=sovereign.synthetic.install={installation_id}"

    def listed(*args: str) -> list[str]:
        lines = [item for item in _docker(*args).splitlines() if item]
        if len(lines) > 50 or any(not re.fullmatch(r"[0-9a-f]{64}", item)
                               for item in lines) or len(set(lines)) != len(lines):
            raise RuntimeError("invalid scoped Docker resource list")
        return lines

    network_ids = listed("network", "ls", "--no-trunc", "--filter", scope, "--quiet")
    container_ids = listed("ps", "-a", "--no-trunc", "--filter", scope, "--quiet")
    networks: dict[str, str] = {}
    for network_id in network_ids:
        name = _docker("network", "inspect", network_id, "--format", "{{.Name}}")
        labels = json.loads(_docker("network", "inspect", network_id,
                                   "--format", "{{json .Labels}}"))
        internal = _docker("network", "inspect", network_id,
                           "--format", "{{.Internal}}")
        if (not re.fullmatch(r"sovereign-synthetic-[0-9a-f]{12}", name)
                or not isinstance(labels, dict)
                or labels.get("sovereign.synthetic.run") != name
                or labels.get("sovereign.synthetic.install") != installation_id
                or internal != "true" or name in networks):
            raise RuntimeError("scoped Docker network identity mismatch")
        networks[name] = network_id

    orphan_containers: list[str] = []
    active_ids = {active.core_id, active.console_id}
    active_network_name = next((name for name, identifier in networks.items()
                                if identifier == active.network_id), None)
    for container_id in container_ids:
        labels = json.loads(_docker("inspect", container_id, "--format",
                                   "{{json .Config.Labels}}"))
        name = _docker("inspect", container_id, "--format", "{{.Name}}")
        attached = json.loads(_docker("inspect", container_id, "--format",
                                      "{{json .NetworkSettings.Networks}}"))
        run_name = labels.get("sovereign.synthetic.run") if isinstance(labels, dict) else None
        if (not isinstance(run_name, str) or run_name not in networks
                or labels.get("sovereign.synthetic.install") != installation_id
                or name not in (f"/{run_name}-core", f"/{run_name}-console")
                or not isinstance(attached, dict)
                or (attached and
                    (set(attached) != {run_name} or
                     not isinstance(attached[run_name], dict) or
                     attached[run_name].get("NetworkID") != networks[run_name]))):
            raise RuntimeError("scoped Docker container identity mismatch")
        if container_id in active_ids:
            if run_name != active_network_name:
                raise RuntimeError("active Docker container identity mismatch")
        elif run_name == active_network_name:
            raise RuntimeError("unexpected container on active Docker network")
        else:
            orphan_containers.append(container_id)

    orphan_networks = [identifier for identifier in network_ids
                       if identifier != active.network_id]
    for container_id in orphan_containers:
        _docker("rm", "-f", container_id)
    for network_id in orphan_networks:
        _docker("network", "rm", network_id)
    return {"containers": len(orphan_containers), "networks": len(orphan_networks)}


def switch_verified_bundle(current: RuntimeHandle | None, bundle: Path,
                           trusted_key: Path, crane: Path,
                           console_config: Path) -> RuntimeHandle:
    """Start and check a candidate before retiring the previous lab runtime."""
    if current is not None:
        probe_runtime(current)
    candidate = start_verified_bundle(bundle, trusted_key, crane, console_config)
    if current is not None:
        stop_runtime(current)
    return candidate


def start_verified_bundle(bundle: Path, trusted_key: Path, crane: Path,
                          console_config: Path,
                          installation_id: str | None = None,
                          core_state: Path | None = None,
                          lab_password_file: Path | None = None) -> RuntimeHandle:
    """Load exact signed archives, launch two isolated services and check them."""
    manifest = verify_bundle(bundle, trusted_key)
    if manifest["schema"] != 4:
        raise BundleError("synthetic runtime requires a two-image product bundle")
    _validate_console_config(console_config)
    if installation_id is not None and not re.fullmatch(r"[0-9a-f]{32}", installation_id):
        raise RuntimeError("invalid synthetic installation identifier")
    core_options = _core_state_options(core_state, lab_password_file)
    images = manifest["images"]
    ids = {role: _image_id(bundle, role, images[role], crane)
           for role in ("core", "console")}
    name = f"sovereign-synthetic-{uuid.uuid4().hex[:12]}"
    labels = ["--label", f"sovereign.synthetic.run={name}"]
    if installation_id is not None:
        labels += ["--label", f"sovereign.synthetic.install={installation_id}"]
    network_id = _docker("network", "create", "--internal", *labels, name)
    if len(network_id) != 64 or _docker("network", "inspect", network_id,
                                     "--format", "{{.Internal}}") != "true":
        stop_runtime(RuntimeHandle(network_id, "", ""))
        raise RuntimeError("isolated Docker network was not created")
    core_id = ""
    console_id = ""
    try:
        core_id = _docker("run", "-d", "--pull", "never", "--name", name + "-core",
                          *labels,
                          "--network", name, "--network-alias", "core", "--read-only",
                          "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                          "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                          *core_options,
                          ids["core"])
        console_id = _docker("run", "-d", "--pull", "never", "--name", name + "-console",
                             *labels,
                             "--network", name, "--network-alias", "console", "--read-only",
                             "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                             "--mount", f"type=bind,source={console_config.resolve()},target=/srv/console-config.json,readonly",
                             ids["console"])
        for identifier in (core_id, console_id):
            ports = _docker("inspect", identifier, "--format",
                            "{{json .HostConfig.PortBindings}}")
            if ports not in ("null", "{}"):
                raise RuntimeError("synthetic container published a host port")
        for attempt in range(30):
            try:
                _health(core_id)
                break
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(1)
        return RuntimeHandle(network_id, core_id, console_id)
    except Exception:
        stop_runtime(RuntimeHandle(network_id, core_id, console_id))
        raise
