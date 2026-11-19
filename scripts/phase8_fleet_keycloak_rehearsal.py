"""Exercise Fleet's real Keycloak authorization-code contract in a synthetic lab."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from urllib.request import Request, urlopen
import ssl

import jwt

from infrastructure.backup import BackupError, create_backup, generate_key, inspect_backup
from scripts.phase8_fleet_browser_rehearsal import FLEET, certificate, driver_request, until
from scripts.phase8_fleet_oidc_rehearsal import IDENTITY_HOST, ISSUER, _identity_material


def _run(*args: str, timeout: int = 120) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"synthetic Docker command failed ({args[0]} {args[1]}): " +
                           result.stderr[-1200:])
    return result.stdout.strip()


def _realm(password: str, mfa: bool = False) -> dict[str, object]:
    return {
        "realm": "fleet", "enabled": True, "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "accessTokenLifespan": 300,
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
        "roles": {"realm": [{"name": "fleet_admin"}]},
        "clients": [{
            "clientId": "sovereign-fleet", "enabled": True,
            "bearerOnly": True, "publicClient": False,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        }, {
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
            "requiredActions": ["CONFIGURE_TOTP"] if mfa else [],
            "realmRoles": ["fleet_admin"],
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
                  "fleet_role": "fleet_admin", "lab_token": "denied",
                  "access_token": access}))
'''

_ADMIN_ROTATE = '''import json
import httpx

issuer = __ISSUER__
password = __PASSWORD__
action = __ACTION__
old_kid = __OLD_KID__
old_provider = __OLD_PROVIDER__
new_kid = __NEW_KID__
base = issuer.removesuffix("/realms/fleet")
with httpx.Client(verify="/etc/fleet-ca.pem", trust_env=False, timeout=10) as client:
    response = client.post(base + "/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": "synthetic-rotator", "password": password})
    assert response.status_code == 200, ("admin token", response.status_code, response.text[:200])
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    admin = base + "/admin/realms/fleet"
    before = client.get(issuer + "/protocol/openid-connect/certs").json()
    before_kids = {item["kid"] for item in before["keys"] if item.get("alg") == "RS256"}
    if action == "add":
        assert old_kid in before_kids, "original signing key missing"
        realm = client.get(admin, headers=headers)
        assert realm.status_code == 200, ("realm", realm.status_code)
        realm_id = realm.json()["id"]
        listing = client.get(admin + "/components", headers=headers, params={
            "parent": realm_id, "type": "org.keycloak.keys.KeyProvider"})
        assert listing.status_code == 200, ("providers", listing.status_code)
        originals = [item for item in listing.json()
                     if item.get("providerId") == "rsa-generated"]
        assert len(originals) == 1, "expected one original RSA signing provider"
        old_provider = originals[0]["id"]
        created = client.post(admin + "/components", headers=headers, json={
            "name": "sovereign-synthetic-rollover", "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm_id,
            "config": {"priority": ["1000"], "enabled": ["true"],
                       "active": ["true"], "keySize": ["2048"]}})
        assert created.status_code in (200, 201, 204), (
            "create provider", created.status_code, created.text[:200])
        after = client.get(issuer + "/protocol/openid-connect/certs").json()
        after_kids = {item["kid"] for item in after["keys"] if item.get("alg") == "RS256"}
        added = after_kids - before_kids
        assert old_kid in after_kids and len(added) == 1, "signing-key overlap missing"
        print(json.dumps({"old_provider": old_provider, "new_kid": added.pop()}))
    else:
        assert action == "retire" and old_provider and new_kid
        removed = client.delete(admin + "/components/" + old_provider, headers=headers)
        assert removed.status_code == 204, ("retire provider", removed.status_code)
        after = client.get(issuer + "/protocol/openid-connect/certs").json()
        after_kids = {item["kid"] for item in after["keys"] if item.get("alg") == "RS256"}
        assert old_kid not in after_kids and new_kid in after_kids, "old signing key persisted"
        print(json.dumps({"retired": True}))
'''


def _api_token(api: str, token: str, allowed: bool) -> None:
    script = ('import httpx\n'
              'r=httpx.get("http://fleet-portal:8080/api/fleet/me", '
              f'headers={{"Authorization":"Bearer {token}"}},trust_env=False,timeout=5)\n'
              f'assert r.status_code=={200 if allowed else 401}, r.status_code\n')
    _run("docker", "exec", api, "python", "-c", script)


def _admin_rotate(api: str, password: str, action: str, old_kid: str,
                  old_provider: str = "", new_kid: str = "") -> dict[str, object]:
    script = (_ADMIN_ROTATE.replace("__ISSUER__", repr(ISSUER))
              .replace("__PASSWORD__", repr(password))
              .replace("__ACTION__", repr(action))
              .replace("__OLD_KID__", repr(old_kid))
              .replace("__OLD_PROVIDER__", repr(old_provider))
              .replace("__NEW_KID__", repr(new_kid)))
    return json.loads(_run("docker", "exec", api, "python", "-c", script))


def _checked_realm_restore(archive: Path, key: Path, destination: Path,
                           trusted_sha256: str) -> None:
    """Require a separately retained checkpoint before decrypting an export."""
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, trusted_sha256):
        raise BackupError("Keycloak archive is stale or differs from trusted checkpoint")
    manifest = inspect_backup(archive, key, destination)
    if [row["name"] for row in manifest["files"]] != ["fleet-realm.json"]:
        raise BackupError("unexpected Keycloak export inventory")
    realm = json.loads((destination / "fleet-realm.json").read_text())
    if realm.get("realm") != "fleet" or not realm.get("users"):
        raise BackupError("restored Keycloak realm or users are missing")


def _backup_realm(source: Path, root: Path, archive: Path, key: Path) -> str:
    spec = root / (archive.stem + "-spec.json")
    spec.write_text(json.dumps({"schema": 1, "files": [{"name": "fleet-realm.json",
        "kind": "file", "source": str(source)}]}))
    spec.chmod(0o600)
    create_backup(spec, archive, key)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def _recover_keycloak(root: Path, reference: str, keycloak: str, api: str,
                      identity_network: str, keycloak_ip: str, certs: Path,
                      data_volume: str, flow: str,
                      stale_archive: Path, backup_key: Path) -> dict[str, str]:
    _run("docker", "stop", keycloak)
    exported = root / "exported"
    exported.mkdir(mode=0o777)
    exported.chmod(0o777)
    _run("docker", "run", "--rm", "--network", "none",
         "--mount", f"type=volume,source={data_volume},target=/opt/keycloak/data",
         "--mount", f"type=bind,source={exported},target=/synthetic-export",
         reference, "export", "--realm", "fleet", "--users", "realm_file",
         "--dir", "/synthetic-export", timeout=180)
    exported_realm = exported / "fleet-realm.json"
    if not exported_realm.is_file():
        raise AssertionError("stopped Keycloak did not export the Fleet realm")
    archive = root / "current.svbk"
    checkpoint = _backup_realm(exported_realm, root, archive, backup_key)
    for candidate, expected in ((stale_archive, checkpoint), (archive, "0" * 64)):
        try:
            _checked_realm_restore(candidate, backup_key, root / "rejected", expected)
        except BackupError:
            pass
        else:
            raise AssertionError("stale Keycloak archive passed checkpoint")
    altered = root / "altered.svbk"
    payload = bytearray(archive.read_bytes())
    payload[len(payload) // 2] ^= 1
    altered.write_bytes(payload)
    altered.chmod(0o600)
    try:
        _checked_realm_restore(altered, backup_key, root / "rejected",
                               hashlib.sha256(payload).hexdigest())
    except BackupError:
        pass
    else:
        raise AssertionError("altered Keycloak archive authenticated")
    restored = root / "restored"
    _checked_realm_restore(archive, backup_key, restored, checkpoint)
    _run("docker", "rm", keycloak)
    # Recreate identity service from the verified export; no old database or
    # import directory is mounted into this second instance.
    _run("docker", "run", "-d", "--name", keycloak,
         "--network", identity_network, "--network-alias", IDENTITY_HOST,
         "--ip", keycloak_ip,
         "--mount", f"type=bind,source={certs / 'cert.pem'},target=/tmp/fleet-cert.pem,readonly",
         "--mount", f"type=bind,source={certs / 'key.pem'},target=/tmp/fleet-key.pem,readonly",
         "--mount", f"type=bind,source={restored},target=/opt/keycloak/data/import,readonly",
         reference, "start-dev", "--import-realm", "--http-enabled=false",
         "--hostname=" + ISSUER.removesuffix("/realms/fleet"),
         "--https-port=443", "--https-certificate-file=/tmp/fleet-cert.pem",
         "--https-certificate-key-file=/tmp/fleet-key.pem")
    for _ in range(90):
        probe = subprocess.run(["docker", "exec", api, "python", "-c",
            "import httpx; assert httpx.get('" + ISSUER +
            "/protocol/openid-connect/certs', verify='/etc/fleet-ca.pem', "
            "trust_env=False, timeout=3).status_code == 200"],
            capture_output=True, timeout=10)
        if probe.returncode == 0:
            break
        time.sleep(1)
    else:
        raise AssertionError("restored Keycloak did not become ready")
    _run("docker", "restart", api)
    for _ in range(20):
        probe = subprocess.run(["docker", "exec", api, "python", "-c",
            "import httpx; assert httpx.get('http://127.0.0.1:18800/health', "
            "trust_env=False, timeout=2).status_code == 200"],
            capture_output=True, timeout=5)
        if probe.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise AssertionError("Fleet API did not restart after identity restore")
    result = json.loads(_run("docker", "exec", api, "python", "-c", flow))
    result.pop("access_token")
    assert result["fleet_role"] == "fleet_admin" and result["lab_token"] == "denied"
    return {"keycloak_recovery": "clean-export-import-authorized",
            "stale_archive": "denied", "altered_archive": "denied"}


def _totp(secret: str, offset: int = 0, at: float | None = None) -> str:
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    counter = int((time.time() if at is None else at) // 30) + offset
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    start = digest[-1] & 15
    number = int.from_bytes(digest[start:start + 4], "big") & 0x7fffffff
    return f"{number % 1_000_000:06d}"


def browser_flow(password: str, chromedriver: str, mfa: bool = False) -> dict[str, str]:
    driver = subprocess.Popen([chromedriver, "--port=9515", "--allowed-ips=127.0.0.1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session = None
    try:
        for _ in range(50):
            try:
                with urlopen("http://127.0.0.1:9515/status", timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        options = {"browserName": "chrome", "acceptInsecureCerts": True,
                   "goog:chromeOptions": {"args": ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
                       "--no-proxy-server", "--host-resolver-rules=MAP fleet.example.invalid 127.0.0.2,"
                       "MAP identity.fleet 127.0.0.3"]}}
        result = driver_request("POST", "/session", {"capabilities": {"alwaysMatch": options}})
        assert isinstance(result, dict)
        session = result["sessionId"]
        driver_request("POST", f"/session/{session}/url", {"url": f"https://{FLEET}/"})
        until(session, "document.querySelector('button.primary')?.textContent?.includes('Sign in with local identity')")
        driver_request("POST", f"/session/{session}/execute/sync",
                       {"script": "document.querySelector('button.primary').click()", "args": []})
        until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('form#kc-form-login input[name=username]')", 45)
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            document.querySelector('input[name=username]').value = arguments[0];
            document.querySelector('input[name=password]').value = arguments[1];
            document.querySelector('form#kc-form-login').requestSubmit();
        """, "args": ["admin", password]})
        secret = ""
        if mfa:
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-totp-settings-form')", 45)
            assert not driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "return location.href.startsWith('https://fleet.example.invalid/?code=')", "args": []})
            driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "document.querySelector('#mode-manual').click()", "args": []})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-totp-secret-key')", 20)
            secret = driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "return document.querySelector('#kc-totp-secret-key').textContent.trim()", "args": []})
            assert isinstance(secret, str) and 16 <= len(secret) <= 128
            enrollment_code = _totp(secret)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=totp]').value = arguments[0];
                document.querySelector('input[name=userLabel]').value = 'Synthetic Fleet device';
                document.querySelector('#kc-totp-settings-form').requestSubmit();
            """, "args": [enrollment_code]})
        until(session, "location.hostname === 'fleet.example.invalid' && document.body.textContent.includes('admin · fleet admin')", 45)
        cleared = driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            return !location.search && !sessionStorage.getItem('sovereign_fleet_oidc_state')
                && !sessionStorage.getItem('sovereign_fleet_pkce_verifier');
        """, "args": []})
        assert cleared, "real Keycloak callback state or code remained in the browser"
        driver_request("POST", f"/session/{session}/execute/sync",
                       {"script": "document.querySelector('.sidebar-bottom button').click()", "args": []})
        outcome = until(session, """location.hostname === 'fleet.example.invalid'
            && document.body.textContent.includes('Sign in with local identity') ? 'fleet' :
            location.hostname === 'identity.fleet' && !!document.querySelector('form') ? 'confirm' : false""", 45)
        if outcome == "confirm":
            driver_request("POST", f"/session/{session}/execute/sync",
                           {"script": "document.querySelector('form').requestSubmit()", "args": []})
            until(session, "location.hostname === 'fleet.example.invalid' && document.body.textContent.includes('Sign in with local identity')", 45)
        assert not driver_request("POST", f"/session/{session}/execute/sync",
                                  {"script": "return document.body.textContent.includes('admin · fleet admin')", "args": []})
        if mfa:
            driver_request("POST", f"/session/{session}/execute/sync",
                           {"script": "document.querySelector('button.primary').click()", "args": []})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('form#kc-form-login input[name=username]')", 45)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=username]').value = arguments[0];
                document.querySelector('input[name=password]').value = arguments[1];
                document.querySelector('form#kc-form-login').requestSubmit();
            """, "args": ["admin", password]})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-otp-login-form input[name=otp]')", 45)
            valid_nearby = {_totp(secret, shift) for shift in (-1, 0, 1)}
            bad = next(value for value in ("000000", "999999", "123456") if value not in valid_nearby)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=otp]').value = arguments[0];
                document.querySelector('#kc-otp-login-form').requestSubmit();
            """, "args": [bad]})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-otp-login-form input[aria-invalid=true]')", 30)
            # Keycloak may reject reuse of the code used to enrol this device.
            # Wait for a distinct time-step value before the successful login.
            deadline = time.monotonic() + 40
            while _totp(secret) == enrollment_code:
                if time.monotonic() >= deadline:
                    raise AssertionError("synthetic OTP did not advance to a new period")
                time.sleep(0.2)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=otp]').value = arguments[0];
                document.querySelector('#kc-otp-login-form').requestSubmit();
            """, "args": [_totp(secret)]})
            try:
                until(session, "location.hostname === 'fleet.example.invalid' && document.body.textContent.includes('admin · fleet admin')", 45)
            except AssertionError as error:
                state = driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                    return {host: location.hostname, otpForm: !!document.querySelector('#kc-otp-login-form'),
                        otpError: !!document.querySelector('#kc-otp-login-form input[aria-invalid=true]')};
                """, "args": []})
                raise AssertionError(f"valid synthetic OTP did not reach Fleet: {state}") from error
            return {"browser_flow": "keycloak-mfa-enrolled-and-authorized",
                    "invalid_otp": "denied", "callback_state": "cleared", "api_role": "fleet_admin"}
        return {"browser_flow": "real-keycloak-pkce-sign-in-and-sign-out", "callback_state": "cleared",
                "api_role": "fleet_admin"}
    finally:
        if session:
            try:
                driver_request("DELETE", f"/session/{session}")
            except Exception:
                pass
        driver.terminate()
        driver.wait(timeout=5)


def rehearse(browser: bool = False, chromedriver: str = "chromedriver",
             mfa: bool = False, recovery: bool = False) -> dict[str, str]:
    if mfa and not browser:
        raise ValueError("MFA rehearsal requires the browser")
    if recovery and (mfa or browser):
        raise ValueError("clean recovery uses the non-browser fictional realm")
    image = json.loads(Path("infrastructure/lab/container-image.json").read_text())
    if image.get("schema") != 1 or image.get("purpose") != "synthetic Keycloak lab only":
        raise ValueError("unapproved Keycloak lab image configuration")
    reference = image["name"] + "@" + image["digest"]
    suffix = uuid.uuid4().hex[:8]
    identity_network = "fleet-keycloak-identity-" + suffix
    app_network = "fleet-keycloak-app-" + suffix
    browser_network = "fleet-keycloak-browser-" + suffix
    keycloak = "fleet-keycloak-" + suffix
    data_volume = "fleet-keycloak-data-" + suffix
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
        admin_password = "synthetic-rotator-" + uuid.uuid4().hex
        (realm / "fleet-realm.json").write_text(json.dumps(_realm(password, mfa)))
        (realm / "fleet-realm.json").chmod(0o644)
        stale_archive = root / "stale.svbk"
        backup_key = root / "backup.key"
        if recovery:
            generate_key(backup_key)
            _backup_realm(realm / "fleet-realm.json", root, stale_archive, backup_key)
        state = root / "state"
        state.mkdir(mode=0o700)
        roles = root / "roles.json"
        roles.write_text(json.dumps({"users": [{"id": "admin", "role": "fleet_admin",
                                               "status": "active", "customer_codes": ["*"]}]}))
        roles.chmod(0o600)
        config = root / "fleet-config.json"
        config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}))
        config.chmod(0o644)
        proxy = None
        if browser:
            certificate(root, FLEET)
        _run("docker", "network", "create", "--internal", "--label",
             "sovereign.fleet.identity=true", identity_network)
        _run("docker", "network", "create", "--internal", app_network)
        if recovery:
            _run("docker", "volume", "create", data_volume)
        if browser:
            # This test-only bridge permits host loopback ingress. The API
            # remains exclusively on the two internal application networks.
            _run("docker", "network", "create", "--label",
                 "sovereign.fleet.browser-test=true", browser_network)
        try:
            _run("docker", "run", "-d", "--name", keycloak,
                 "--network", browser_network if browser else identity_network,
                 *([] if browser else ["--network-alias", IDENTITY_HOST]),
                 *(["--publish", "127.0.0.3:443:443"] if browser else []),
                 "--mount", f"type=bind,source={certs / 'cert.pem'},target=/tmp/fleet-cert.pem,readonly",
                 "--mount", f"type=bind,source={certs / 'key.pem'},target=/tmp/fleet-key.pem,readonly",
                 *(["--mount", f"type=volume,source={data_volume},target=/opt/keycloak/data"]
                   if recovery else []),
                 "--mount", f"type=bind,source={realm},target=/opt/keycloak/data/import,readonly",
                 "--env", "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-rotator",
                 "--env", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + admin_password,
                 reference, "start-dev", "--import-realm", "--http-enabled=false",
                 "--hostname=" + ISSUER.removesuffix("/realms/fleet"),
                 "--https-port=443", "--https-certificate-file=/tmp/fleet-cert.pem",
                 "--https-certificate-key-file=/tmp/fleet-key.pem")
            if browser:
                _run("docker", "network", "connect", "--alias", IDENTITY_HOST,
                     identity_network, keycloak)
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
                 "--network", browser_network if browser else app_network,
                 *([] if browser else ["--network-alias", "fleet-portal"]),
                 *(["--publish", "127.0.0.1:18080:8080"] if browser else []),
                 "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={config},target=/srv/fleet-config.json,readonly",
                 "sovereign-fleet-portal:synthetic")
            if browser:
                _run("docker", "network", "connect", "--alias", "fleet-portal",
                     app_network, portal)
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
            if mfa:
                _run("docker", "exec", api, "python", "-c",
                     "import httpx; r=httpx.get('http://fleet-portal:8080/api/fleet/me', "
                     "headers={'X-Fleet-Lab-Token': 'synthetic-fleet-admin-token-0123456789'}, "
                     "trust_env=False); assert r.status_code == 401")
                outcome = {"keycloak_flow": "mfa-required", "lab_token": "denied"}
            else:
                flow = _FLOW.replace("__ISSUER__", repr(ISSUER)).replace(
                    "__PASSWORD__", repr(password))
                outcome = json.loads(_run("docker", "exec", api, "python", "-c", flow))
                old_token = outcome.pop("access_token")
                if not browser:
                    old_kid = jwt.get_unverified_header(old_token)["kid"]
                    added = _admin_rotate(api, admin_password, "add", old_kid)
                    new_kid = added["new_kid"]
                    new_outcome = json.loads(_run("docker", "exec", api,
                                                  "python", "-c", flow))
                    new_token = new_outcome.pop("access_token")
                    assert jwt.get_unverified_header(new_token)["kid"] == new_kid
                    _api_token(api, old_token, True)
                    _api_token(api, new_token, True)
                    _admin_rotate(api, admin_password, "retire", old_kid,
                                  added["old_provider"], new_kid)
                    _run("docker", "restart", api)
                    for _ in range(20):
                        healthy = subprocess.run(
                            ["docker", "exec", api, "python", "-c",
                             "import httpx; assert httpx.get('http://127.0.0.1:18800/health', "
                             "trust_env=False, timeout=2).status_code == 200"],
                            capture_output=True, timeout=5)
                        if healthy.returncode == 0:
                            break
                        time.sleep(0.5)
                    else:
                        raise AssertionError("Fleet API did not restart after key retirement")
                    _api_token(api, old_token, False)
                    _api_token(api, new_token, True)
                    outcome["keycloak_rotation"] = "overlap-old-key-retired"
                    if recovery:
                        outcome.update(_recover_keycloak(root, reference, keycloak, api,
                            identity_network, keycloak_ip, certs, data_volume, flow,
                            stale_archive, backup_key))
            if browser:
                try:
                    with urlopen("http://127.0.0.1:18080/", timeout=3) as response:
                        assert response.status == 200, "published Fleet portal did not return 200"
                except OSError as error:
                    raise RuntimeError(f"published Fleet portal is unreachable: {error}") from error
                proxy = subprocess.Popen(["sudo", "-n", str(Path.cwd() / ".venv/bin/python"), "-m",
                                          "scripts.phase8_fleet_https_proxy", "--cert", str(root / f"{FLEET}.crt"),
                                          "--key", str(root / f"{FLEET}.key")],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                last_error = "no response"
                for _ in range(50):
                    if proxy.poll() is not None:
                        raise RuntimeError("Fleet HTTPS bridge failed: " + proxy.stderr.read().decode())
                    try:
                        request = Request("https://127.0.0.2/", headers={"Host": FLEET})
                        with urlopen(request, context=ssl._create_unverified_context(), timeout=1):
                            break
                    except OSError as error:
                        last_error = f"{type(error).__name__}: {error}"
                        time.sleep(0.2)
                else:
                    raise RuntimeError(f"Fleet HTTPS bridge did not become ready: {last_error}")
                outcome.update(browser_flow(password, chromedriver, mfa))
            return outcome
        finally:
            if proxy:
                proxy.terminate()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=5)
            for name in (portal, api, keycloak):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            for name in (app_network, identity_network, *([browser_network] if browser else [])):
                subprocess.run(["docker", "network", "rm", name], capture_output=True)
            if recovery:
                subprocess.run(["docker", "volume", "rm", data_volume], capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--mfa", action="store_true")
    parser.add_argument("--recovery", action="store_true")
    parser.add_argument("--chromedriver", default=os.environ.get("CHROMEDRIVER", "chromedriver"))
    arguments = parser.parse_args()
    print(json.dumps(rehearse(arguments.browser, arguments.chromedriver,
                             arguments.mfa, arguments.recovery), sort_keys=True))
