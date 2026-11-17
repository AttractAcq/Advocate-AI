"""Exercise Fleet's real Keycloak authorization-code contract in a synthetic lab."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from scripts.phase8_fleet_oidc_rehearsal import IDENTITY_HOST, ISSUER, _identity_material


def _run(*args: str, timeout: int = 120) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"synthetic Docker command failed ({args[0]} {args[1]}): " +
                           result.stderr[-1200:])
    return result.stdout.strip()


def _realm(password: str) -> dict[str, object]:
    return {
        "realm": "fleet", "enabled": True, "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "accessTokenLifespan": 300,
        "roles": {"realm": [{"name": "fleet_admin"}]},
        "clients": [{
            "clientId": "sovereign-fleet-portal", "enabled": True,
            "publicClient": True, "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": ["https://fleet.example.invalid/"],
            "webOrigins": ["https://fleet.example.invalid"],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "protocol": "openid-connect",
            "protocolMappers": [{
                "name": "fleet-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                "config": {"included.client.audience": "sovereign-fleet",
                           "access.token.claim": "true"},
            }],
        }],
        "users": [{
            "username": "admin", "enabled": True, "emailVerified": True,
            "email": "admin@synthetic.example.invalid", "firstName": "Synthetic",
            "lastName": "Administrator",
            "requiredActions": [], "realmRoles": ["fleet_admin"],
            "credentials": [{"type": "password", "value": password,
                             "temporary": False}],
        }],
    }


_FLOW = '''import base64, hashlib, html.parser, json, secrets, urllib.parse
import httpx
import jwt

issuer = __ISSUER__
password = __PASSWORD__
ca = "/etc/fleet-ca.pem"
redirect = "https://fleet.example.invalid/"
verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode()

class LoginForm(html.parser.HTMLParser):
    action = None
    fields = {}
    inside = False
    def handle_starttag(self, tag, attrs):
        if tag == "form" and dict(attrs).get("id") == "kc-form-login":
            self.action = dict(attrs).get("action")
            self.inside = True
        if self.inside and tag == "input" and dict(attrs).get("name"):
            item = dict(attrs)
            self.fields[item["name"]] = item.get("value", "")
    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False

with httpx.Client(verify=ca, trust_env=False, follow_redirects=False, timeout=10) as client:
    auth = client.get(issuer + "/protocol/openid-connect/auth", params={
        "client_id": "sovereign-fleet-portal", "redirect_uri": redirect,
        "response_type": "code", "scope": "openid", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    assert auth.status_code == 200, ("auth", auth.status_code, auth.text[:200])
    form = LoginForm()
    form.feed(auth.text)
    assert form.action and form.action.startswith(issuer + "/"), "missing Keycloak login form"
    login = client.post(form.action, data={**form.fields, "username": "admin",
                                           "password": password})
    assert login.status_code in (302, 303), ("login", login.status_code, login.text[:200])
    location = login.headers["location"]
    for _ in range(5):
        if location.startswith(redirect):
            break
        next_url = urllib.parse.urljoin(issuer + "/", location)
        assert next_url.startswith(issuer + "/"), "login redirected outside Keycloak"
        next_page = client.get(next_url)
        assert next_page.status_code in (302, 303), (
            "intermediate login redirect", next_page.status_code,
            urllib.parse.urlsplit(next_url).path)
        location = next_page.headers["location"]
    assert location.startswith(redirect), "login redirected outside the Fleet callback"
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    assert query.get("state") == [state] and len(query.get("code", [])) == 1, "invalid PKCE callback"
    token = client.post(issuer + "/protocol/openid-connect/token", data={
        "grant_type": "authorization_code", "client_id": "sovereign-fleet-portal",
        "redirect_uri": redirect, "code": query["code"][0],
        "code_verifier": verifier})
    assert token.status_code == 200, ("token", token.status_code, token.text[:200])
    access = token.json()["access_token"]
    claims = jwt.decode(access, options={"verify_signature": False,
                                         "verify_aud": False})

with httpx.Client(trust_env=False, timeout=10) as client:
    me = client.get("http://fleet-portal:8080/api/fleet/me",
                    headers={"Authorization": "Bearer " + access})
    assert me.status_code == 200, ("Fleet API", me.status_code,
        {key: claims.get(key) for key in ("iss", "aud", "azp", "typ",
                                         "preferred_username", "realm_access")})
    assert me.json() == {"id": "admin", "role": "fleet_admin", "customer_codes": ["*"]}
    lab = client.get("http://fleet-portal:8080/api/fleet/me",
                     headers={"X-Fleet-Lab-Token": "synthetic-fleet-admin-token-0123456789"})
    assert lab.status_code == 401, "lab token accepted in company mode"
print(json.dumps({"keycloak_flow": "authorization-code-pkce-authorized",
                  "fleet_role": "fleet_admin", "lab_token": "denied"}))
'''


def rehearse() -> dict[str, str]:
    image = json.loads(Path("infrastructure/lab/container-image.json").read_text())
    if image.get("schema") != 1 or image.get("purpose") != "synthetic Keycloak lab only":
        raise ValueError("unapproved Keycloak lab image configuration")
    reference = image["name"] + "@" + image["digest"]
    suffix = uuid.uuid4().hex[:8]
    identity_network = "fleet-keycloak-identity-" + suffix
    app_network = "fleet-keycloak-app-" + suffix
    keycloak = "fleet-keycloak-" + suffix
    api = "fleet-keycloak-api-" + suffix
    portal = "fleet-keycloak-portal-" + suffix
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        certs, ca, _ = _identity_material(root)
        # Only synthetic, short-lived Keycloak credentials are mounted here.
        (certs / "cert.pem").chmod(0o644)
        (certs / "key.pem").chmod(0o644)
        realm = root / "realm"
        realm.mkdir(mode=0o755)
        password = "synthetic-fleet-" + uuid.uuid4().hex
        (realm / "fleet-realm.json").write_text(json.dumps(_realm(password)))
        (realm / "fleet-realm.json").chmod(0o644)
        state = root / "state"
        state.mkdir(mode=0o700)
        roles = root / "roles.json"
        roles.write_text(json.dumps({"users": [{"id": "admin", "role": "fleet_admin",
                                               "status": "active", "customer_codes": ["*"]}]}))
        roles.chmod(0o600)
        config = root / "fleet-config.json"
        config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}))
        config.chmod(0o644)
        _run("docker", "network", "create", "--internal", "--label",
             "sovereign.fleet.identity=true", identity_network)
        _run("docker", "network", "create", "--internal", app_network)
        try:
            _run("docker", "run", "-d", "--name", keycloak,
                 "--network", identity_network, "--network-alias", IDENTITY_HOST,
                 "--mount", f"type=bind,source={certs / 'cert.pem'},target=/tmp/fleet-cert.pem,readonly",
                 "--mount", f"type=bind,source={certs / 'key.pem'},target=/tmp/fleet-key.pem,readonly",
                 "--mount", f"type=bind,source={realm},target=/opt/keycloak/data/import,readonly",
                 reference, "start-dev", "--import-realm", "--http-enabled=false",
                 "--hostname=" + ISSUER.removesuffix("/realms/fleet"),
                 "--https-port=443", "--https-certificate-file=/tmp/fleet-cert.pem",
                 "--https-certificate-key-file=/tmp/fleet-key.pem")
            settings = json.loads(_run("docker", "inspect", keycloak, "--format",
                                       "{{json .NetworkSettings.Networks}}"))
            keycloak_ip = settings[identity_network]["IPAddress"]
            _run("docker", "run", "-d", "--name", api,
                 "--network", app_network, "--network-alias", "fleet-api",
                 "--add-host", f"{IDENTITY_HOST}:{keycloak_ip}",
                 "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={state},target=/state",
                 "--mount", f"type=bind,source={roles},target=/etc/fleet-roles.json,readonly",
                 "--mount", f"type=bind,source={ca},target=/etc/fleet-ca.pem,readonly",
                 "-e", "SOVEREIGN_FLEET_DB=/state/fleet.db",
                 "-e", "SOVEREIGN_FLEET_OIDC_ISSUER=" + ISSUER,
                 "-e", "SOVEREIGN_FLEET_ROLES_FILE=/etc/fleet-roles.json",
                 "-e", "SOVEREIGN_FLEET_CA_FILE=/etc/fleet-ca.pem",
                 "sovereign-fleet-api:synthetic")
            _run("docker", "network", "connect", identity_network, api)
            _run("docker", "run", "-d", "--name", portal,
                 "--network", app_network, "--network-alias", "fleet-portal",
                 "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={config},target=/srv/fleet-config.json,readonly",
                 "sovereign-fleet-portal:synthetic")
            ready = False
            for _ in range(90):
                status = subprocess.run(
                    ["docker", "exec", api, "python", "-c",
                     "import httpx; assert httpx.get('" + ISSUER +
                     "/protocol/openid-connect/certs', verify='/etc/fleet-ca.pem', "
                     "trust_env=False, timeout=3).status_code == 200"],
                    capture_output=True, text=True, timeout=10)
                if status.returncode == 0:
                    ready = True
                    break
                if _run("docker", "inspect", keycloak, "--format", "{{.State.Running}}") != "true":
                    break
                time.sleep(1)
            if not ready:
                logs = subprocess.run(["docker", "logs", "--tail", "30", keycloak],
                                      capture_output=True, text=True)
                raise AssertionError("synthetic Keycloak did not become ready: " +
                                     logs.stderr[-1600:])
            flow = _FLOW.replace("__ISSUER__", repr(ISSUER)).replace(
                "__PASSWORD__", repr(password))
            outcome = json.loads(_run("docker", "exec", api, "python", "-c", flow))
            return outcome
        finally:
            for name in (portal, api, keycloak):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            for name in (app_network, identity_network):
                subprocess.run(["docker", "network", "rm", name], capture_output=True)


if __name__ == "__main__":
    print(json.dumps(rehearse(), sort_keys=True))
