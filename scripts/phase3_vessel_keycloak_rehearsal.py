"""Exercise vessel Core against a real, pinned synthetic Keycloak instance."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from scripts.phase3_identity import KEYCLOAK_BASE64_FLAG
from scripts.phase8_fleet_keycloak_rehearsal import _FLOW, _run, _verify_base64_mitigation
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


def rehearse() -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    network = "vessel-keycloak-" + suffix
    app_network = "vessel-app-" + suffix
    keycloak = "vessel-keycloak-" + suffix
    core = "vessel-core-" + suffix
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
        try:
            _run("docker", "run", "-d", "--name", keycloak,
                 "--network", network, "--network-alias", IDENTITY_HOST,
                 "--env", KEYCLOAK_BASE64_FLAG,
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
            for username, role in (("lab-chief_engineer-1", "chief_engineer"),
                                   ("lab-deckhand-1", "deckhand")):
                flow = (_VESSEL_FLOW.replace("__ISSUER__", repr(ISSUER))
                        .replace("__PASSWORD__", repr(password))
                        .replace("__USER__", repr(username))
                        .replace("__ROLE__", repr(role))
                        .replace('ca = "/etc/fleet-ca.pem"', 'ca = "/state/ca.pem"'))
                outcome = json.loads(_run("docker", "exec", core, "python", "-c", flow,
                                          timeout=90))
                token = outcome["token"]
                assert outcome["role"] == role and outcome["lab_token"] == "denied"
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
            return {"keycloak_flow": "authorization-code-pkce-authorized",
                    "core_roles": "chief_engineer,deckhand",
                    "source_scope": "role-restricted", "lab_fallback": "denied",
                    "logout_reuse": "denied"}
        finally:
            subprocess.run(["docker", "rm", "-f", core, keycloak],
                           capture_output=True, text=True)
            subprocess.run(["docker", "network", "rm", app_network, network],
                           capture_output=True, text=True)


if __name__ == "__main__":
    print(json.dumps(rehearse(), sort_keys=True))
