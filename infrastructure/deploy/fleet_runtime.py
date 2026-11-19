"""Isolated synthetic runtime for a separately signed company Fleet bundle."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
import uuid

from apps.api.oidc import OidcVerifier
from infrastructure.deploy.container_runtime import (
    RuntimeError, _archive_image_ids, _docker, _image_id,
)
from infrastructure.release.bundle import BundleError, verify_bundle
from services.fleet.offline_import import key_id, load_import_key

_ID = re.compile(r"[0-9a-f]{64}\Z")
_RUN = re.compile(r"sovereign-fleet-[0-9a-f]{12}\Z")
_NETWORK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}\Z")


@dataclass(frozen=True)
class FleetRuntime:
    network_id: str
    api_id: str
    portal_id: str
    identity_network_id: str | None = None
    identity_network_name: str | None = None


def validate_config(path: Path) -> str | None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise RuntimeError("invalid Fleet runtime configuration")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("invalid Fleet runtime configuration") from exc
    if (not isinstance(value, dict) or set(value) != {"schema", "oidc_issuer"} or
            type(value["schema"]) is not int or value["schema"] != 1):
        raise RuntimeError("invalid Fleet runtime configuration fields")
    issuer = value["oidc_issuer"]
    if issuer is None:
        return None
    if not isinstance(issuer, str) or len(issuer) > 512 or not issuer.startswith("https://"):
        raise RuntimeError("installed Fleet OIDC requires an HTTPS issuer")
    try:
        OidcVerifier(issuer, Path("/dev/null"), allow_https_issuer=True)
    except ValueError as exc:
        raise RuntimeError("invalid Fleet HTTPS issuer") from exc
    return issuer


def _import_trust(state: Path) -> Path | None:
    """Validate optional, separately provisioned offline receipt trust."""
    root = state.parent / "receipt-import"
    if not root.exists() and not root.is_symlink():
        return None
    if (root.is_symlink() or not root.is_dir() or
            root.stat().st_uid != os.getuid() or
            stat.S_IMODE(root.stat().st_mode) & 0o077):
        raise RuntimeError("Fleet receipt trust directory must be owner-only")
    manifest = root / "trusted-issuers.json"
    if (manifest.is_symlink() or not manifest.is_file() or
            manifest.stat().st_uid != os.getuid() or
            stat.S_IMODE(manifest.stat().st_mode) & 0o077 or
            manifest.stat().st_size > 4096):
        raise RuntimeError("invalid Fleet receipt trust manifest")
    try:
        paths = json.loads(manifest.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("invalid Fleet receipt trust manifest") from exc
    if (not isinstance(paths, list) or not 1 <= len(paths) <= 4 or
            paths != [f"/etc/fleet-import/issuer-{index}.pem"
                      for index in range(1, len(paths) + 1)] or
            {item.name for item in root.iterdir()} !=
            {"trusted-issuers.json"} |
            {f"issuer-{index}.pem" for index in range(1, len(paths) + 1)}):
        raise RuntimeError("invalid Fleet receipt trust inventory")
    try:
        keys = [load_import_key(root / f"issuer-{index}.pem")
                for index in range(1, len(paths) + 1)]
    except (OSError, ValueError) as exc:
        raise RuntimeError("invalid Fleet receipt trust issuer") from exc
    if len({key_id(key) for key in keys}) != len(keys):
        raise RuntimeError("duplicate Fleet receipt trust issuer")
    return root


def validate_state(state: Path, issuer: str | None = None) -> None:
    token = state / "token"
    if (not state.is_absolute() or state.is_symlink() or not state.is_dir() or
            state.stat().st_uid != os.getuid() or
            stat.S_IMODE(state.stat().st_mode) & 0o077 or
            (issuer is None and
             (token.is_symlink() or not token.is_file() or
              token.stat().st_uid != os.getuid() or
              stat.S_IMODE(token.stat().st_mode) & 0o077 or
              not 32 <= token.stat().st_size <= 201)) or
            (issuer is not None and (token.exists() or token.is_symlink()))):
        raise RuntimeError("Fleet state identity mode is invalid")
    if issuer is not None:
        identity = state.parent / "identity"
        roles = identity / "roles.json"
        ca = identity / "ca.pem"
        if (identity.is_symlink() or not identity.is_dir() or
                identity.stat().st_uid != os.getuid() or
                stat.S_IMODE(identity.stat().st_mode) & 0o077 or
                roles.is_symlink() or not roles.is_file() or
                roles.stat().st_uid != os.getuid() or
                stat.S_IMODE(roles.stat().st_mode) & 0o077 or
                roles.stat().st_size > 1024 * 1024):
            raise RuntimeError("Fleet OIDC roles must be owner-only and separate from state")
        try:
            policy = json.loads(roles.read_bytes())
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError("invalid Fleet OIDC roles JSON") from exc
        users = policy.get("users") if isinstance(policy, dict) else None
        if (not isinstance(policy, dict) or set(policy) != {"users"} or
                not isinstance(users, list) or
                not 1 <= len(users) <= 1000 or
                not any(isinstance(user, dict) and user.get("role") == "fleet_admin" and
                        user.get("status") == "active" and
                        user.get("customer_codes") == ["*"] for user in users)):
            raise RuntimeError("Fleet OIDC roles require an active global administrator")
        if ca.exists() or ca.is_symlink():
            if (ca.is_symlink() or not ca.is_file() or
                    ca.stat().st_uid != os.getuid() or
                    stat.S_IMODE(ca.stat().st_mode) & 0o077 or
                    ca.stat().st_size > 64 * 1024):
                raise RuntimeError("Fleet OIDC CA must be owner-only")
            try:
                ssl.create_default_context(cafile=str(ca))
            except ssl.SSLError as exc:
                raise RuntimeError("invalid Fleet OIDC CA certificate") from exc
    _import_trust(state)


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


def _health(api_id: str, issuer: str | None = None,
            custom_ca: bool = False) -> None:
    _docker("exec", api_id, "python", "-c",
            'import urllib.request; '
            'assert urllib.request.urlopen("http://127.0.0.1:18800/health", timeout=3).status == 200')
    script = (
            'import json, urllib.error, urllib.request\n'
            'base="http://fleet-portal:8080"\n'
            'r=urllib.request.urlopen(base+"/fleet-config.json", timeout=3)\n'
            f'assert json.load(r)=={{"schema":1,"oidc_issuer":{issuer!r}}}\n'
            'assert r.headers["Cache-Control"]=="no-store"\n'
            'assert b"root" in urllib.request.urlopen(base+"/", timeout=3).read()\n'
            'try:\n urllib.request.urlopen(base+"/api/fleet/me", timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code==401\n'
            'else:\n raise AssertionError("unauthorised Fleet API passed")\n')
    if issuer is None:
        script += (
            'token=open("/state/token").read().strip()\n'
            'request=urllib.request.Request(base+"/api/fleet/me", '
            'headers={"X-Fleet-Lab-Token":token})\n'
            'assert json.load(urllib.request.urlopen(request, timeout=3))["role"]=="fleet_admin"\n')
    else:
        if custom_ca:
            script += ('import ssl\n'
                       'context=ssl.create_default_context(cafile="/etc/fleet-ca.pem")\n')
        script += (
            'request=urllib.request.Request(base+"/api/fleet/me", '
            'headers={"X-Fleet-Lab-Token":"synthetic-fleet-admin-token-0123456789"})\n'
            'try:\n urllib.request.urlopen(request, timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code==401\n'
            'else:\n raise AssertionError("lab token accepted in OIDC mode")\n'
            f'keys=json.load(urllib.request.urlopen({issuer!r}+'
            '"/protocol/openid-connect/certs", timeout=5'
            + (', context=context' if custom_ca else '') + '))\n'
            'assert isinstance(keys.get("keys"), list) and keys["keys"]\n')
    script += (
            'try:\n urllib.request.urlopen(base+"/api/models", timeout=3)\n'
            'except urllib.error.HTTPError as exc:\n assert exc.code==404\n'
            'else:\n raise AssertionError("vessel API reached Fleet")')
    _docker("exec", api_id, "python", "-c", script)


def _identity_network(name: str) -> str:
    if not _NETWORK.fullmatch(name) or name.startswith("sovereign-fleet-"):
        raise RuntimeError("invalid Fleet identity network name")
    identifier = _docker("network", "inspect", name, "--format", "{{.Id}}")
    if (not _ID.fullmatch(identifier) or
            _docker("network", "inspect", name, "--format", "{{.Internal}}") != "true" or
            _docker("network", "inspect", name, "--format",
                    '{{index .Labels "sovereign.fleet.identity"}}') != "true"):
        raise RuntimeError("Fleet identity network must be labelled and internal")
    return identifier


def verify_runtime_identity(handle: FleetRuntime, bundle: Path,
                            trusted_key: Path, state: Path, config: Path) -> None:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise BundleError("Fleet runtime requires a signed Fleet bundle")
    issuer = validate_config(config)
    custom_ca = issuer is not None and (state.parent / "identity" / "ca.pem").exists()
    import_trust = _import_trust(state)
    if issuer is None:
        if handle.identity_network_id is not None or handle.identity_network_name is not None:
            raise RuntimeError("lab Fleet runtime has unexpected identity network")
    elif (handle.identity_network_name is None or handle.identity_network_id is None or
          _identity_network(handle.identity_network_name) != handle.identity_network_id):
        raise RuntimeError("Fleet identity network changed")
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
        expected_networks = ({name, handle.identity_network_name}
                             if role == "fleet-api" and issuer is not None else {name})
        if (set(networks) != expected_networks or
                networks[name].get("NetworkID") != handle.network_id or
                (issuer is not None and role == "fleet-api" and
                 networks[handle.identity_network_name].get("NetworkID") !=
                 handle.identity_network_id)):
            raise RuntimeError("Fleet container network mismatch")
        mounts = json.loads(_docker("inspect", identifier, "--format", "{{json .Mounts}}"))
        required_mounts = ({"/state", "/etc/fleet-roles.json"} |
                           ({"/etc/fleet-ca.pem"} if custom_ca else set())
                           if role == "fleet-api" and issuer is not None else
                           {"/state"} if role == "fleet-api" else
                           {"/srv/fleet-config.json"})
        if role == "fleet-api" and import_trust is not None:
            required_mounts.add("/etc/fleet-import")
        if {item.get("Destination") for item in mounts} != required_mounts or \
                len(mounts) != len(required_mounts):
            raise RuntimeError("Fleet container mount set mismatch")
        expected = {"fleet-api": ("/state", str(state.resolve()), True),
                    "fleet-portal": ("/srv/fleet-config.json", str(config.resolve()), False)}
        destination, source, writable = expected[role]
        selected = [item for item in mounts if item.get("Destination") == destination]
        if (len(selected) != 1 or selected[0].get("Type") != "bind" or
                selected[0].get("Source") != source or
                selected[0].get("RW") is not writable):
            raise RuntimeError("Fleet container mount identity mismatch")
        if role == "fleet-api":
            if import_trust is not None:
                bound_trust = [item for item in mounts if item.get("Destination") ==
                               "/etc/fleet-import"]
                if (len(bound_trust) != 1 or bound_trust[0].get("Type") != "bind" or
                        bound_trust[0].get("Source") != str(import_trust.resolve()) or
                        bound_trust[0].get("RW") is not False):
                    raise RuntimeError("Fleet receipt trust mount identity mismatch")
            if issuer is not None:
                roles = state.parent / "identity" / "roles.json"
                bound = [item for item in mounts if item.get("Destination") ==
                         "/etc/fleet-roles.json"]
                if (len(bound) != 1 or bound[0].get("Type") != "bind" or
                        bound[0].get("Source") != str(roles.resolve()) or
                        bound[0].get("RW") is not False):
                    raise RuntimeError("Fleet roles mount identity mismatch")
                if custom_ca:
                    ca = state.parent / "identity" / "ca.pem"
                    bound_ca = [item for item in mounts if item.get("Destination") ==
                                "/etc/fleet-ca.pem"]
                    if (len(bound_ca) != 1 or bound_ca[0].get("Type") != "bind" or
                            bound_ca[0].get("Source") != str(ca.resolve()) or
                            bound_ca[0].get("RW") is not False):
                        raise RuntimeError("Fleet CA mount identity mismatch")
            environment = json.loads(_docker("inspect", identifier, "--format",
                                             "{{json .Config.Env}}"))
            relevant = [item for item in environment if item.startswith("SOVEREIGN_FLEET_")]
            expected_env = {"SOVEREIGN_FLEET_DB=/state/fleet.db"}
            if import_trust is not None:
                expected_env.add("SOVEREIGN_FLEET_IMPORT_TRUST_FILE=/etc/fleet-import/trusted-issuers.json")
            if issuer is None:
                expected_env.add("SOVEREIGN_FLEET_TOKEN_FILE=/state/token")
            else:
                expected_env.update({f"SOVEREIGN_FLEET_OIDC_ISSUER={issuer}",
                                     "SOVEREIGN_FLEET_ROLES_FILE=/etc/fleet-roles.json"})
                if custom_ca:
                    expected_env.add("SOVEREIGN_FLEET_CA_FILE=/etc/fleet-ca.pem")
            if (set(relevant) != expected_env or
                    len(relevant) != len(expected_env) or
                    _docker("inspect", identifier, "--format", "{{.Config.User}}") !=
                    f"{os.getuid()}:{os.getgid()}"):
                raise RuntimeError("Fleet API state environment mismatch")


def probe_runtime(handle: FleetRuntime, bundle: Path, trusted_key: Path,
                  state: Path, config: Path) -> None:
    issuer = validate_config(config)
    validate_state(state, issuer)
    verify_runtime_identity(handle, bundle, trusted_key, state, config)
    if any(_docker("inspect", identifier, "--format", "{{.State.Running}}") != "true"
           for identifier in (handle.api_id, handle.portal_id)):
        raise RuntimeError("Fleet container is stopped")
    _health(handle.api_id, issuer,
            issuer is not None and (state.parent / "identity" / "ca.pem").exists())


def start_verified_bundle(bundle: Path, trusted_key: Path, crane: Path,
                          config: Path, state: Path,
                          identity_network: str | None = None) -> FleetRuntime:
    manifest = verify_bundle(bundle, trusted_key)
    if manifest.get("schema") != 5 or manifest.get("target") != "fleet":
        raise BundleError("Fleet runtime requires a signed Fleet bundle")
    issuer = validate_config(config)
    validate_state(state, issuer)
    import_trust = _import_trust(state)
    if (issuer is None) != (identity_network is None):
        raise RuntimeError("Fleet identity mode and network do not match")
    identity_id = _identity_network(identity_network) if identity_network else None
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
        api_args = [
            "run", "-d", "--pull", "never", "--name", name + "-api", *labels,
            "--network", name, "--network-alias", "fleet-api",
            "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", f"type=bind,source={state.resolve()},target=/state",
            "-e", "SOVEREIGN_FLEET_DB=/state/fleet.db"]
        if import_trust is not None:
            api_args.extend((
                "--mount", f"type=bind,source={import_trust.resolve()},target=/etc/fleet-import,readonly",
                "-e", "SOVEREIGN_FLEET_IMPORT_TRUST_FILE=/etc/fleet-import/trusted-issuers.json"))
        if issuer is None:
            api_args.extend(("-e", "SOVEREIGN_FLEET_TOKEN_FILE=/state/token"))
        else:
            roles = state.parent / "identity" / "roles.json"
            api_args.extend((
                "--mount", f"type=bind,source={roles.resolve()},target=/etc/fleet-roles.json,readonly",
                "-e", f"SOVEREIGN_FLEET_OIDC_ISSUER={issuer}",
                "-e", "SOVEREIGN_FLEET_ROLES_FILE=/etc/fleet-roles.json"))
            ca = state.parent / "identity" / "ca.pem"
            if ca.exists():
                api_args.extend((
                    "--mount", f"type=bind,source={ca.resolve()},target=/etc/fleet-ca.pem,readonly",
                    "-e", "SOVEREIGN_FLEET_CA_FILE=/etc/fleet-ca.pem"))
        api_id = _docker(*api_args, ids["fleet-api"])
        if identity_network is not None:
            _docker("network", "connect", identity_network, api_id)
        portal_id = _docker(
            "run", "-d", "--pull", "never", "--name", name + "-portal", *labels,
            "--network", name, "--network-alias", "fleet-portal", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", f"type=bind,source={config.resolve()},target=/srv/fleet-config.json,readonly",
            ids["fleet-portal"])
        handle = FleetRuntime(network_id, api_id, portal_id,
                              identity_id, identity_network)
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
        stop_runtime(FleetRuntime(network_id, api_id, portal_id,
                                  identity_id, identity_network))
        raise
