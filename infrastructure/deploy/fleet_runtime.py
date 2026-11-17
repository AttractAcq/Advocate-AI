"""Isolated synthetic runtime for a separately signed company Fleet bundle."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from infrastructure.deploy.container_runtime import (
    RuntimeError, _archive_image_ids, _docker, _image_id,
)
from infrastructure.release.bundle import BundleError, verify_bundle

_ID = re.compile(r"[0-9a-f]{64}\Z")
_RUN = re.compile(r"sovereign-fleet-[0-9a-f]{12}\Z")


@dataclass(frozen=True)
class FleetRuntime:
    network_id: str
    api_id: str
    portal_id: str


def validate_config(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise RuntimeError("invalid Fleet runtime configuration")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("invalid Fleet runtime configuration") from exc
    if value != {"schema": 1, "oidc_issuer": None} or type(value["schema"]) is not int:
        raise RuntimeError("only synthetic local Fleet configuration is allowed")


def validate_state(state: Path) -> None:
    token = state / "token"
    if (not state.is_absolute() or state.is_symlink() or not state.is_dir() or
            state.stat().st_uid != os.getuid() or
            stat.S_IMODE(state.stat().st_mode) & 0o077 or
            token.is_symlink() or not token.is_file() or
            token.stat().st_uid != os.getuid() or
            stat.S_IMODE(token.stat().st_mode) & 0o077 or
            not 32 <= token.stat().st_size <= 201):
        raise RuntimeError("Fleet state and token must be owner-only")


def stop_runtime(handle: FleetRuntime) -> None:
    for identifier in (handle.portal_id, handle.api_id):
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


def _health(api_id: str) -> None:
    _docker("exec", api_id, "python", "-c",
            'import urllib.request; '
            'assert urllib.request.urlopen("http://127.0.0.1:18800/health", timeout=3).status == 200')
    _docker("exec", api_id, "python", "-c",
            'import json, urllib.error, urllib.request\n'
            'base="http://fleet-portal:8080"\n'
            'r=urllib.request.urlopen(base+"/fleet-config.json", timeout=3)\n'
            'assert json.load(r)=={"schema":1,"oidc_issuer":None}\n'
            'assert r.headers["Cache-Control"]=="no-store"\n'
            'assert b"root" in urllib.request.urlopen(base+"/", timeout=3).read()\n'
            'try:\n urllib.request.urlopen(base+"/api/fleet/me", timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code==401\n'
            'else:\n raise AssertionError("unauthorised Fleet API passed")\n'
            'token=open("/state/token").read().strip()\n'
            'request=urllib.request.Request(base+"/api/fleet/me", '
            'headers={"X-Fleet-Lab-Token":token})\n'
            'assert json.load(urllib.request.urlopen(request, timeout=3))["role"]=="fleet_admin"\n'
            'try:\n urllib.request.urlopen(base+"/api/models", timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code==404\n'
            'else:\n raise AssertionError("vessel API reached Fleet")')


def verify_runtime_identity(handle: FleetRuntime, bundle: Path,
                            trusted_key: Path, state: Path, config: Path) -> None:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise BundleError("Fleet runtime requires a signed Fleet bundle")
    name = _docker("network", "inspect", handle.network_id, "--format", "{{.Name}}")
    if not _RUN.fullmatch(name) or _docker("network", "inspect", handle.network_id,
                                        "--format", "{{.Internal}}") != "true" or \
            _docker("network", "inspect", handle.network_id, "--format",
                    '{{index .Labels "sovereign.fleet.run"}}') != name:
        raise RuntimeError("Fleet network identity mismatch")
    for identifier, role in ((handle.api_id, "fleet-api"),
                             (handle.portal_id, "fleet-portal")):
        if (not _ID.fullmatch(identifier) or
                _docker("inspect", identifier, "--format",
                        '{{index .Config.Labels "sovereign.fleet.run"}}') != name or
                _docker("inspect", identifier, "--format", "{{.Image}}") not in
                _archive_image_ids(bundle / manifest["images"][role]["archive_path"], role) or
                _docker("inspect", identifier, "--format",
                        "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
            raise RuntimeError("Fleet container identity mismatch")
        networks = json.loads(_docker("inspect", identifier, "--format",
                                     "{{json .NetworkSettings.Networks}}"))
        if set(networks) != {name} or networks[name].get("NetworkID") != handle.network_id:
            raise RuntimeError("Fleet container network mismatch")
        mounts = json.loads(_docker("inspect", identifier, "--format", "{{json .Mounts}}"))
        expected = {"fleet-api": ("/state", str(state.resolve()), True),
                    "fleet-portal": ("/srv/fleet-config.json", str(config.resolve()), False)}
        destination, source, writable = expected[role]
        selected = [item for item in mounts if item.get("Destination") == destination]
        if (len(selected) != 1 or selected[0].get("Type") != "bind" or
                selected[0].get("Source") != source or
                selected[0].get("RW") is not writable):
            raise RuntimeError("Fleet container mount identity mismatch")
        if role == "fleet-api":
            environment = json.loads(_docker("inspect", identifier, "--format",
                                             "{{json .Config.Env}}"))
            relevant = [item for item in environment if item.startswith("SOVEREIGN_FLEET_")]
            if (set(relevant) != {"SOVEREIGN_FLEET_DB=/state/fleet.db",
                                  "SOVEREIGN_FLEET_TOKEN_FILE=/state/token"} or
                    len(relevant) != 2 or
                    _docker("inspect", identifier, "--format", "{{.Config.User}}") !=
                    f"{os.getuid()}:{os.getgid()}"):
                raise RuntimeError("Fleet API state environment mismatch")


def probe_runtime(handle: FleetRuntime, bundle: Path, trusted_key: Path,
                  state: Path, config: Path) -> None:
    validate_state(state)
    validate_config(config)
    verify_runtime_identity(handle, bundle, trusted_key, state, config)
    if any(_docker("inspect", identifier, "--format", "{{.State.Running}}") != "true"
           for identifier in (handle.api_id, handle.portal_id)):
        raise RuntimeError("Fleet container is stopped")
    _health(handle.api_id)


def start_verified_bundle(bundle: Path, trusted_key: Path, crane: Path,
                          config: Path, state: Path) -> FleetRuntime:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise BundleError("Fleet runtime requires a signed Fleet bundle")
    validate_config(config)
    validate_state(state)
    ids = {role: _image_id(bundle, role, manifest["images"][role], crane)
           for role in ("fleet-api", "fleet-portal")}
    name = f"sovereign-fleet-{uuid.uuid4().hex[:12]}"
    labels = ["--label", f"sovereign.fleet.run={name}"]
    network_id = _docker("network", "create", "--internal", *labels, name)
    if not _ID.fullmatch(network_id):
        stop_runtime(FleetRuntime(network_id, "", ""))
        raise RuntimeError("isolated Fleet network was not created")
    api_id = ""
    portal_id = ""
    try:
        api_id = _docker(
            "run", "-d", "--pull", "never", "--name", name + "-api", *labels,
            "--network", name, "--network-alias", "fleet-api",
            "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", f"type=bind,source={state.resolve()},target=/state",
            "-e", "SOVEREIGN_FLEET_DB=/state/fleet.db",
            "-e", "SOVEREIGN_FLEET_TOKEN_FILE=/state/token", ids["fleet-api"])
        portal_id = _docker(
            "run", "-d", "--pull", "never", "--name", name + "-portal", *labels,
            "--network", name, "--network-alias", "fleet-portal", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", f"type=bind,source={config.resolve()},target=/srv/fleet-config.json,readonly",
            ids["fleet-portal"])
        handle = FleetRuntime(network_id, api_id, portal_id)
        for attempt in range(30):
            try:
                probe_runtime(handle, bundle, trusted_key, state, config)
                return handle
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(1)
        raise RuntimeError("Fleet candidate did not become healthy")
    except Exception:
        stop_runtime(FleetRuntime(network_id, api_id, portal_id))
        raise
