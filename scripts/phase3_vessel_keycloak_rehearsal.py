"""Exercise vessel Core against a real, pinned synthetic Keycloak instance."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import jwt

from infrastructure.backup import BackupError, create_backup, generate_key, inspect_backup
from scripts.phase3_identity import KEYCLOAK_BASE64_FLAG
from scripts.phase8_fleet_keycloak_rehearsal import (
    _ADMIN_ROTATE, _FLOW, _run, _verify_base64_mitigation,
)
from scripts.phase8_fleet_oidc_rehearsal import IDENTITY_HOST, _identity_material


ISSUER = f"https://{IDENTITY_HOST}/realms/sovereign"


def _realm(password: str, mfa: bool = False) -> dict[str, object]:
    users = []
    for username, role in (("lab-chief_engineer-1", "chief_engineer"),
                           ("lab-deckhand-1", "deckhand")):
        users.append({
            "username": username, "enabled": True, "emailVerified": True,
            "email": username + "@synthetic.example.invalid",
            "firstName": "Synthetic", "lastName": "Crew",
            "requiredActions": ["CONFIGURE_TOTP"] if mfa else [],
            "realmRoles": [role],
            "credentials": [{"type": "password", "value": password,
                             "temporary": False}],
        })
    return {
        "realm": "sovereign", "enabled": True, "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "accessTokenLifespan": 300,
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
        "roles": {"realm": [{"name": "chief_engineer"}, {"name": "deckhand"}]},
        "clients": [{
            "clientId": "sovereign-core", "enabled": True,
            "bearerOnly": True, "publicClient": False,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        }, {
            "clientId": "sovereign-console", "enabled": True,
            "publicClient": True, "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": ["https://vessel.example.invalid/"],
            "webOrigins": ["https://vessel.example.invalid"],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "protocol": "openid-connect",
            "protocolMappers": [{
                "name": "core-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                "config": {"included.client.audience": "sovereign-core",
                           "access.token.claim": "true"},
            }],
        }],
        "users": users,
    }


_VESSEL_FLOW = _FLOW.replace("fleet.example.invalid", "vessel.example.invalid").replace(
    "sovereign-fleet-portal", "sovereign-console").replace(
    "/realms/fleet", "/realms/sovereign")
_VESSEL_FLOW = _VESSEL_FLOW.replace(
    '"username": "admin"', '"username": user_name').replace(
    '"http://fleet-portal:8080/api/fleet/me"', '"http://127.0.0.1:18100/api/me"')
_VESSEL_FLOW = _VESSEL_FLOW.replace(
    'assert me.json() == {"id": "admin", "role": "fleet_admin", "customer_codes": ["*"]}',
    'assert me.json() == {"id": user_name, "role": expected_role}')
_VESSEL_FLOW = _VESSEL_FLOW.replace(
    'print(json.dumps({"keycloak_flow": "authorization-code-pkce-authorized",\n'
    '                  "fleet_role": "fleet_admin", "lab_token": "denied",\n'
    '                  "access_token": access}))',
    'print(json.dumps({"token": access, "role": expected_role, "lab_token": "denied"}))')
_VESSEL_FLOW = _VESSEL_FLOW.replace(
    'with httpx.Client(verify=ca, trust_env=False, follow_redirects=False, timeout=10) as client:',
    'user_name = __USER__\nexpected_role = __ROLE__\n'
    'with httpx.Client(verify=ca, trust_env=False, follow_redirects=False, timeout=10) as client:')


def _api(core: str, token: str, path: str, method: str = "GET") -> tuple[int, object]:
    code = (
        'import httpx,json,sys\n'
        'token,path,method=sys.argv[1:]\n'
        'headers={"Authorization":"Bearer "+token} if token!="-" else {}\n'
        'with httpx.Client(trust_env=False,timeout=10) as client:\n'
        ' body={"user_id":"lab-chief_engineer-1","password":"synthetic-invalid"}'
        ' if path=="/api/login" else None\n'
        ' r=client.request(method,"http://127.0.0.1:18100"+path,'
        'headers=headers,json=body)\n'
        ' print(json.dumps({"status":r.status_code,"body":r.json()}))\n')
    outcome = json.loads(_run("docker", "exec", core, "python", "-c", code,
                              token, path, method, timeout=30))
    return outcome["status"], outcome["body"]


def _flow(core: str, password: str, username: str, role: str) -> str:
    code = (_VESSEL_FLOW.replace("__ISSUER__", repr(ISSUER))
            .replace("__PASSWORD__", repr(password))
            .replace("__USER__", repr(username))
            .replace("__ROLE__", repr(role))
            .replace('ca = "/etc/fleet-ca.pem"', 'ca = "/state/ca.pem"'))
    return json.loads(_run("docker", "exec", core, "python", "-c", code,
                           timeout=90))["token"]


def _rotate(core: str, password: str, action: str, old_kid: str,
            old_provider: str = "", new_kid: str = "") -> dict[str, object]:
    script = (_ADMIN_ROTATE.replace("/realms/fleet", "/realms/sovereign")
              .replace("/admin/realms/fleet", "/admin/realms/sovereign")
              .replace("/etc/fleet-ca.pem", "/state/ca.pem")
              .replace("synthetic-rotator", "synthetic-admin")
              .replace("__ISSUER__", repr(ISSUER))
              .replace("__PASSWORD__", repr(password))
              .replace("__ACTION__", repr(action))
              .replace("__OLD_KID__", repr(old_kid))
              .replace("__OLD_PROVIDER__", repr(old_provider))
              .replace("__NEW_KID__", repr(new_kid)))
    return json.loads(_run("docker", "exec", core, "python", "-c", script,
                           timeout=90))


def _rehearse_rotation(core: str, password: str) -> dict[str, str]:
    old_token = _flow(core, password, "lab-chief_engineer-1", "chief_engineer")
    old_kid = jwt.get_unverified_header(old_token)["kid"]
    added = _rotate(core, password, "add", old_kid)
    new_kid = str(added["new_kid"])
    new_token = _flow(core, password, "lab-chief_engineer-1", "chief_engineer")
    if jwt.get_unverified_header(new_token)["kid"] != new_kid:
        raise AssertionError("vessel token was not signed by new Keycloak key")
    for token in (old_token, new_token):
        if _api(core, token, "/api/me")[0] != 200:
            raise AssertionError("Core rejected a token during signing-key overlap")
    _rotate(core, password, "retire", old_kid,
            str(added["old_provider"]), new_kid)
    _run("docker", "restart", core)
    for _ in range(30):
        probe = subprocess.run([
            "docker", "exec", core, "python", "-c",
            "import httpx; assert httpx.get('http://127.0.0.1:18100/health', "
            "trust_env=False, timeout=2).status_code == 200",
        ], capture_output=True, timeout=5)
        if probe.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise AssertionError("Core did not restart after Keycloak key retirement")
    if _api(core, old_token, "/api/me")[0] != 401:
        raise AssertionError("Core accepted a retired signing key")
    if _api(core, new_token, "/api/me")[0] != 200:
        raise AssertionError("Core rejected the current signing key")
    sources_status, sources = _api(core, new_token, "/api/sources")
    if (sources_status != 200 or
            {row["collection"] for row in sources["sources"]} !=
            {"engineering", "deck"}):
        raise AssertionError("signing-key rollover changed source permissions")
    return {"keycloak_rotation": "overlap-old-key-retired",
            "retired_key": "denied", "source_scope": "role-restricted"}


def _backup_realm(source: Path, root: Path, archive: Path, key: Path) -> str:
    spec = root / (archive.stem + "-spec.json")
    spec.write_text(json.dumps({"schema": 1, "files": [{
        "name": "sovereign-realm.json", "kind": "file", "source": str(source),
    }]}))
    spec.chmod(0o600)
    create_backup(spec, archive, key)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def _checked_restore(archive: Path, key: Path, destination: Path,
                     trusted_digest: str) -> None:
    if not hmac.compare_digest(hashlib.sha256(archive.read_bytes()).hexdigest(),
                               trusted_digest):
        raise BackupError("vessel identity archive differs from trusted checkpoint")
    manifest = inspect_backup(archive, key, destination)
    if [row["name"] for row in manifest["files"]] != ["sovereign-realm.json"]:
        raise BackupError("unexpected vessel identity export inventory")
    realm = json.loads((destination / "sovereign-realm.json").read_text())
    if realm.get("realm") != "sovereign" or not realm.get("users"):
        raise BackupError("restored vessel realm or users are missing")


def _recover(root: Path, reference: str, keycloak: str, core: str,
             network: str, idp: Path, data_volume: str, password: str,
             stale_archive: Path, backup_key: Path, revoked_token: str) -> dict[str, str]:
    network_info = json.loads(_run("docker", "inspect", keycloak, "--format",
                                   "{{json .NetworkSettings.Networks}}"))
    keycloak_ip = network_info[network]["IPAddress"]
    _run("docker", "stop", keycloak)
    exported = root / "exported"
    exported.mkdir(mode=0o777)
    exported.chmod(0o777)
    _run("docker", "run", "--rm", "--network", "none",
         "--mount", f"type=volume,source={data_volume},target=/opt/keycloak/data",
         "--mount", f"type=bind,source={exported},target=/synthetic-export",
         reference, "export", "--realm", "sovereign", "--users", "realm_file",
         "--dir", "/synthetic-export", timeout=180)
    exported_realm = exported / "sovereign-realm.json"
    if not exported_realm.is_file():
        raise AssertionError("stopped Keycloak did not export the vessel realm")
    archive = root / "current.svbk"
    digest = _backup_realm(exported_realm, root, archive, backup_key)
    for candidate, expected in ((stale_archive, digest), (archive, "0" * 64)):
        try:
            _checked_restore(candidate, backup_key, root / "rejected", expected)
        except BackupError:
            pass
        else:
            raise AssertionError("stale vessel identity archive passed checkpoint")
    altered = root / "altered.svbk"
    payload = bytearray(archive.read_bytes())
    payload[len(payload) // 2] ^= 1
    altered.write_bytes(payload)
    altered.chmod(0o600)
    try:
        _checked_restore(altered, backup_key, root / "rejected",
                         hashlib.sha256(payload).hexdigest())
    except BackupError:
        pass
    else:
        raise AssertionError("altered vessel identity archive authenticated")
    restored = root / "restored"
    _checked_restore(archive, backup_key, restored, digest)
    restored.chmod(0o755)
    (restored / "sovereign-realm.json").chmod(0o644)
    _run("docker", "rm", keycloak)
    _run("docker", "run", "-d", "--name", keycloak,
         "--network", network, "--network-alias", IDENTITY_HOST,
         "--ip", keycloak_ip, "--env", KEYCLOAK_BASE64_FLAG,
         "--mount", f"type=bind,source={idp / 'cert.pem'},target=/tmp/vessel-cert.pem,readonly",
         "--mount", f"type=bind,source={idp / 'key.pem'},target=/tmp/vessel-key.pem,readonly",
         "--mount", f"type=bind,source={restored},target=/opt/keycloak/data/import,readonly",
         reference, "start-dev", "--import-realm", "--http-enabled=false",
         "--hostname=https://" + IDENTITY_HOST,
         "--https-port=443", "--https-certificate-file=/tmp/vessel-cert.pem",
         "--https-certificate-key-file=/tmp/vessel-key.pem")
    for _ in range(90):
        probe = subprocess.run([
            "docker", "exec", core, "python", "-c",
            "import httpx; assert httpx.get('" + ISSUER +
            "/protocol/openid-connect/certs', verify='/state/ca.pem', "
            "trust_env=False, timeout=3).status_code == 200",
        ], capture_output=True, timeout=10)
        if probe.returncode == 0:
            break
        time.sleep(1)
    else:
        raise AssertionError("restored vessel Keycloak did not become ready")
    _verify_base64_mitigation(keycloak)
    _run("docker", "restart", core)
    for _ in range(30):
        probe = subprocess.run([
            "docker", "exec", core, "python", "-c",
            "import httpx; assert httpx.get('http://127.0.0.1:18100/health', "
            "trust_env=False, timeout=2).status_code == 200",
        ], capture_output=True, timeout=5)
        if probe.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise AssertionError("Core did not restart after identity restore")
    if _api(core, revoked_token, "/api/me")[0] != 401:
        raise AssertionError("Core accepted logged-out token after identity recovery")
    fresh = _flow(core, password, "lab-chief_engineer-1", "chief_engineer")
    if _api(core, fresh, "/api/me") != (200, {"id": "lab-chief_engineer-1",
                                               "role": "chief_engineer"}):
        raise AssertionError("restored vessel identity did not authorize engineer")
    return {"keycloak_recovery": "clean-export-import-authorized",
            "stale_archive": "denied", "altered_archive": "denied",
            "revoked_core_token": "denied"}


def rehearse(*, recovery: bool = False, rotation: bool = False) -> dict[str, str]:
    if recovery and rotation:
        raise ValueError("recovery and key rotation use separate synthetic realms")
    suffix = uuid.uuid4().hex[:8]
    network = "vessel-keycloak-" + suffix
    app_network = "vessel-app-" + suffix
    keycloak = "vessel-keycloak-" + suffix
    core = "vessel-core-" + suffix
    data_volume = "vessel-keycloak-data-" + suffix
    reference = json.loads(Path("infrastructure/lab/container-image.json").read_text())
    reference = reference["name"] + "@" + reference["digest"]
    with tempfile.TemporaryDirectory(prefix="vessel-keycloak-") as scratch:
        root = Path(scratch)
        idp, ca, _ = _identity_material(root)
        # The pinned Keycloak image runs as a non-root user; these fictional
        # test-only materials must be readable by that container.
        idp.chmod(0o755)
        for name in ("cert.pem", "key.pem"):
            (idp / name).chmod(0o644)
        password = "synthetic-" + uuid.uuid4().hex
        realm = root / "realm"
        realm.mkdir(mode=0o755)
        (realm / "sovereign-realm.json").write_text(json.dumps(_realm(password)))
        (realm / "sovereign-realm.json").chmod(0o644)
        stale_archive = root / "stale.svbk"
        backup_key = root / "backup.key"
        if recovery:
            generate_key(backup_key)
            _backup_realm(realm / "sovereign-realm.json", root,
                          stale_archive, backup_key)
        state = root / "state"
        shutil.copytree("fixtures", state)
        subprocess.run([sys.executable, str(state / "generate.py")],
                       check=True, capture_output=True, text=True, timeout=30)
        (state / "ca.pem").write_bytes(ca.read_bytes())
        (state / "ca.pem").chmod(0o600)
        (state / "revoked.jsonl").write_bytes(b"")
        (state / "revoked.jsonl").chmod(0o600)
        _run("docker", "network", "create", "--internal", "--label",
             "sovereign.vessel.identity=true", network)
        _run("docker", "network", "create", "--internal", app_network)
        if recovery:
            _run("docker", "volume", "create", data_volume)
        try:
            _run("docker", "run", "-d", "--name", keycloak,
                 "--network", network, "--network-alias", IDENTITY_HOST,
                 "--env", KEYCLOAK_BASE64_FLAG,
                 *(["--mount", f"type=volume,source={data_volume},target=/opt/keycloak/data"]
                   if recovery else []),
                 "--mount", f"type=bind,source={idp / 'cert.pem'},target=/tmp/vessel-cert.pem,readonly",
                 "--mount", f"type=bind,source={idp / 'key.pem'},target=/tmp/vessel-key.pem,readonly",
                 "--mount", f"type=bind,source={realm},target=/opt/keycloak/data/import,readonly",
                 "--env", "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-admin",
                 "--env", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + password,
                 reference, "start-dev", "--import-realm", "--http-enabled=false",
                 "--hostname=https://" + IDENTITY_HOST,
                 "--https-port=443", "--https-certificate-file=/tmp/vessel-cert.pem",
                 "--https-certificate-key-file=/tmp/vessel-key.pem")
            _run("docker", "run", "-d", "--name", core,
                 "--network", app_network,
                 "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={state},target=/state",
                 "-e", "SOVEREIGN_FIXTURE_ROOT=/state",
                 "-e", "SOVEREIGN_OIDC_ISSUER=" + ISSUER,
                 "-e", "SOVEREIGN_OIDC_CA_FILE=/state/ca.pem",
                 "-e", "SOVEREIGN_OIDC_REVOCATIONS=/state/revoked.jsonl",
                 "sovereign-core:synthetic")
            _run("docker", "network", "connect", network, core)
            for _ in range(90):
                ready = subprocess.run([
                    "docker", "exec", core, "python", "-c",
                    "import httpx; assert httpx.get('" + ISSUER +
                    "/protocol/openid-connect/certs', verify='/state/ca.pem', "
                    "trust_env=False, timeout=3).status_code == 200",
                ], capture_output=True, text=True, timeout=10)
                if ready.returncode == 0:
                    break
                if _run("docker", "inspect", keycloak, "--format", "{{.State.Running}}") != "true":
                    break
                time.sleep(1)
            else:
                raise AssertionError("synthetic vessel Keycloak did not become ready")
            if ready.returncode:
                raise AssertionError("synthetic vessel Keycloak stopped before readiness")
            _verify_base64_mitigation(keycloak)
            assert _api(core, "-", "/api/me")[0] == 401
            assert _api(core, "-", "/api/login", "POST")[0] == 404
            revoked_token = ""
            for username, role in (("lab-chief_engineer-1", "chief_engineer"),
                                   ("lab-deckhand-1", "deckhand")):
                token = _flow(core, password, username, role)
                assert _api(core, token, "/api/me") == (200, {"id": username, "role": role})
                sources = _api(core, token, "/api/sources")
                assert sources[0] == 200, sources
                collections = {row["collection"] for row in sources[1]["sources"]}
                assert "management" not in collections and "interior" not in collections
                if role == "deckhand":
                    assert collections == {"deck"}, collections
                else:
                    assert collections == {"engineering", "deck"}, collections
                assert _api(core, token, "/api/logout", "POST")[0] == 200
                assert _api(core, token, "/api/me")[0] == 401
                if role == "chief_engineer":
                    revoked_token = token
            outcome = {"keycloak_flow": "authorization-code-pkce-authorized",
                       "core_roles": "chief_engineer,deckhand",
                       "source_scope": "role-restricted", "lab_fallback": "denied",
                       "logout_reuse": "denied"}
            if recovery:
                outcome.update(_recover(root, reference, keycloak, core, network,
                                        idp, data_volume, password, stale_archive,
                                        backup_key, revoked_token))
            if rotation:
                outcome.update(_rehearse_rotation(core, password))
            return outcome
        finally:
            subprocess.run(["docker", "rm", "-f", core, keycloak],
                           capture_output=True, text=True)
            subprocess.run(["docker", "network", "rm", app_network, network],
                           capture_output=True, text=True)
            if recovery:
                subprocess.run(["docker", "volume", "rm", data_volume],
                               capture_output=True, text=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery", action="store_true")
    parser.add_argument("--rotation", action="store_true")
    args = parser.parse_args()
    print(json.dumps(rehearse(recovery=args.recovery, rotation=args.rotation),
                     sort_keys=True))
