"""Drive the built vessel Console through synthetic Keycloak and Core in Chrome."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.phase3_identity import KEYCLOAK_BASE64_FLAG
from scripts.phase3_vessel_keycloak_rehearsal import ISSUER, _realm, _run, _verify_base64_mitigation
from scripts.phase8_fleet_keycloak_rehearsal import _totp
from scripts.phase8_fleet_browser_rehearsal import certificate, driver_request, until
from scripts.phase8_fleet_oidc_rehearsal import IDENTITY_HOST, _identity_material
from services.intelligence.threat_snapshot import import_package, sign_payload, trusted_key


CONSOLE_HOST = "vessel.example.invalid"


def _browser(password: str, chromedriver: str, *, mfa: bool = False) -> dict[str, str]:
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
        else:
            raise AssertionError("ChromeDriver did not become ready")
        options = {"browserName": "chrome", "acceptInsecureCerts": True,
                   "goog:chromeOptions": {"args": [
                       "--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
                       "--no-proxy-server",
                       "--host-resolver-rules=MAP vessel.example.invalid 127.0.0.2,"
                       "MAP identity.fleet 127.0.0.3",
                   ]}}
        result = driver_request("POST", "/session",
                                {"capabilities": {"alwaysMatch": options}}, timeout=45)
        assert isinstance(result, dict)
        session = result["sessionId"]
        driver_request("POST", f"/session/{session}/url",
                       {"url": f"https://{CONSOLE_HOST}/"}, timeout=45)
        until(session, "document.body.textContent.includes('Continue to local sign-in')", 45)
        assert not driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('Lab passphrase')", "args": []}), \
            "OIDC Console exposed lab credential input"
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            [...document.querySelectorAll('button')]
              .find(button => button.textContent.includes('Continue to local sign-in')).click();
        """, "args": []})
        until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('form#kc-form-login input[name=username]')", 45)
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            document.querySelector('input[name=username]').value = arguments[0];
            document.querySelector('input[name=password]').value = arguments[1];
            document.querySelector('form#kc-form-login').requestSubmit();
        """, "args": ["lab-chief_engineer-1", password]})
        secret = ""
        enrollment_code = ""
        if mfa:
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-totp-settings-form')", 45)
            assert not driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "return location.hostname === 'vessel.example.invalid'", "args": []}), \
                "Keycloak allowed Console before second-factor enrollment"
            driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "document.querySelector('#mode-manual').click()", "args": []})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-totp-secret-key')", 20)
            secret = driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "return document.querySelector('#kc-totp-secret-key').textContent.trim()",
                "args": []})
            assert isinstance(secret, str) and 16 <= len(secret) <= 128
            enrollment_code = _totp(secret)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=totp]').value = arguments[0];
                document.querySelector('input[name=userLabel]').value = 'Synthetic vessel device';
                document.querySelector('#kc-totp-settings-form').requestSubmit();
            """, "args": [enrollment_code]})
        until(session, "location.hostname === 'vessel.example.invalid' && document.body.textContent.includes('Chief Engineer workspace')", 60)
        cleared = driver_request("POST", f"/session/{session}/execute/sync", {
            "script": """return !location.search && !sessionStorage.getItem('sovereign_oidc_state')
                && !sessionStorage.getItem('sovereign_pkce_verifier');""", "args": []})
        assert cleared, "Console retained callback code or PKCE state"
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            [...document.querySelectorAll('nav[aria-label="Workspace"] button')]
              .find(button => button.textContent === 'Documents').click();
        """, "args": []})
        until(session, "document.body.textContent.includes('Approved documents')", 30)
        assert driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('ENG-001')", "args": []}), \
            "engineer document was not visible"
        assert not driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('MAN-001')", "args": []}), \
            "management document leaked into engineer view"
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            [...document.querySelectorAll('aside button')]
              .find(button => button.textContent === 'Sign out').click();
        """, "args": []})
        outcome = until(session, """location.hostname === 'vessel.example.invalid'
            && document.body.textContent.includes('Continue to local sign-in') ? 'console' :
            location.hostname === 'identity.fleet' && !!document.querySelector('form') ? 'confirm' : false""", 45)
        if outcome == "confirm":
            driver_request("POST", f"/session/{session}/execute/sync", {
                "script": "document.querySelector('form').requestSubmit()", "args": []})
            until(session, "location.hostname === 'vessel.example.invalid' && document.body.textContent.includes('Continue to local sign-in')", 45)
        assert not driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('Chief Engineer workspace')",
            "args": []}), "Console retained identity after sign-out"
        if mfa:
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                [...document.querySelectorAll('button')]
                  .find(button => button.textContent.includes('Continue to local sign-in')).click();
            """, "args": []})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('form#kc-form-login input[name=username]')", 45)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=username]').value = arguments[0];
                document.querySelector('input[name=password]').value = arguments[1];
                document.querySelector('form#kc-form-login').requestSubmit();
            """, "args": ["lab-chief_engineer-1", password]})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-otp-login-form input[name=otp]')", 45)
            valid_nearby = {_totp(secret, shift) for shift in (-1, 0, 1)}
            invalid = next(value for value in ("000000", "999999", "123456")
                           if value not in valid_nearby)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=otp]').value = arguments[0];
                document.querySelector('#kc-otp-login-form').requestSubmit();
            """, "args": [invalid]})
            until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('#kc-otp-login-form input[aria-invalid=true]')", 30)
            deadline = time.monotonic() + 40
            while _totp(secret) == enrollment_code:
                if time.monotonic() >= deadline:
                    raise AssertionError("synthetic OTP did not advance")
                time.sleep(0.2)
            driver_request("POST", f"/session/{session}/execute/sync", {"script": """
                document.querySelector('input[name=otp]').value = arguments[0];
                document.querySelector('#kc-otp-login-form').requestSubmit();
            """, "args": [_totp(secret)]})
            until(session, "location.hostname === 'vessel.example.invalid' && document.body.textContent.includes('Chief Engineer workspace')", 45)
            return {"browser_flow": "keycloak-console-mfa-enrolled-and-authorized",
                    "invalid_otp": "denied", "api_role": "chief_engineer",
                    "callback_state": "cleared", "source_scope": "engineering-only"}
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            [...document.querySelectorAll('button')]
              .find(button => button.textContent.includes('Continue to local sign-in')).click();
        """, "args": []})
        until(session, "location.hostname === 'identity.fleet' && !!document.querySelector('form#kc-form-login input[name=username]')", 45)
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            document.querySelector('input[name=username]').value = arguments[0];
            document.querySelector('input[name=password]').value = arguments[1];
            document.querySelector('form#kc-form-login').requestSubmit();
        """, "args": ["lab-avit_admin-1", password]})
        until(session, "location.hostname === 'vessel.example.invalid' && document.body.textContent.includes('AV/IT Administrator workspace')", 45)
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            [...document.querySelectorAll('nav[aria-label="Workspace"] button')]
              .find(button => button.textContent === 'Security').click();
        """, "args": []})
        until(session, "document.body.textContent.includes('Offline threat intelligence: stale')", 30)
        assert driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('synthetic-feed') && document.body.textContent.includes('Offline threat intelligence is stale')",
            "args": []}), "Console did not show signed feed provenance and stale warning"
        assert not driver_request("POST", f"/session/{session}/execute/sync", {
            "script": "return document.body.textContent.includes('203.0.113.7')",
            "args": []}), "Console exposed threat indicator value"
        return {"browser_flow": "keycloak-console-pkce-sign-in-and-sign-out",
                "callback_state": "cleared", "source_scope": "engineering-only",
                "lab_password_input": "absent",
                "threat_snapshot": "stale-warning-withheld-values"}
    finally:
        if session:
            try:
                driver_request("DELETE", f"/session/{session}")
            except Exception:
                pass
        driver.terminate()
        driver.wait(timeout=5)


def rehearse(chromedriver: str, *, mfa: bool = False) -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    identity_network = "vessel-browser-identity-" + suffix
    app_network = "vessel-browser-app-" + suffix
    browser_network = "vessel-browser-ingress-" + suffix
    keycloak = "vessel-browser-keycloak-" + suffix
    core = "vessel-browser-core-" + suffix
    console = "vessel-browser-console-" + suffix
    image = json.loads(Path("infrastructure/lab/container-image.json").read_text())
    if image.get("schema") != 1 or image.get("purpose") != "synthetic Keycloak lab only":
        raise ValueError("unapproved synthetic Keycloak image")
    reference = image["name"] + "@" + image["digest"]
    with tempfile.TemporaryDirectory(prefix="vessel-browser-") as scratch:
        root = Path(scratch)
        idp, ca, _ = _identity_material(root)
        idp.chmod(0o755)
        for name in ("cert.pem", "key.pem"):
            (idp / name).chmod(0o644)
        console_cert, console_key = certificate(root, CONSOLE_HOST)
        password = "synthetic-" + uuid.uuid4().hex
        realm = root / "realm"
        realm.mkdir(mode=0o755)
        realm_payload = _realm(password, mfa)
        realm_payload["roles"]["realm"].append({"name": "avit_admin"})
        realm_payload["users"].append({
            "username": "lab-avit_admin-1", "enabled": True, "emailVerified": True,
            "email": "lab-avit_admin-1@synthetic.example.invalid",
            "firstName": "Synthetic", "lastName": "AVIT", "requiredActions": [],
            "realmRoles": ["avit_admin"],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        })
        (realm / "sovereign-realm.json").write_text(json.dumps(realm_payload))
        (realm / "sovereign-realm.json").chmod(0o644)
        state = root / "state"
        shutil.copytree("fixtures", state)
        subprocess.run([sys.executable, str(state / "generate.py")],
                       check=True, capture_output=True, text=True, timeout=30)
        (state / "ca.pem").write_bytes(ca.read_bytes())
        (state / "ca.pem").chmod(0o600)
        (state / "revoked.jsonl").write_bytes(b"")
        (state / "revoked.jsonl").chmod(0o600)
        threat_store = state / "threat-intel"
        threat_store.mkdir(mode=0o700)
        signer = Ed25519PrivateKey.generate()
        signing_key = root / "threat-signer.pem"
        signing_key.write_bytes(signer.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        signing_key.chmod(0o600)
        trusted = threat_store / "trusted.pem"
        trusted.write_bytes(signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        issued = datetime.now(timezone.utc) - timedelta(days=8)
        payload = root / "threat-payload.json"
        payload.write_text(json.dumps({
            "schema": 1, "feed_id": "synthetic-feed", "publisher": "synthetic-lab",
            "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(days=14)).isoformat(),
            "indicators": [{"id": "fictional-1", "kind": "ipv4", "value": "203.0.113.7"}],
        }))
        package = root / "threat-package.json"
        sign_payload(payload, signing_key, package)
        import_package(package, threat_store, trusted_key(trusted))
        config = root / "console-config.json"
        config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}))
        config.chmod(0o644)
        proxy = None
        _run("docker", "network", "create", "--internal", "--label",
             "sovereign.vessel.identity=true", identity_network)
        _run("docker", "network", "create", "--internal", app_network)
        _run("docker", "network", "create", "--label",
             "sovereign.vessel.browser-test=true", browser_network)
        try:
            _run("docker", "run", "-d", "--name", keycloak,
                 "--network", browser_network,
                 "--publish", "127.0.0.3:443:443",
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
            _run("docker", "network", "connect", "--alias", IDENTITY_HOST,
                 identity_network, keycloak)
            _run("docker", "run", "-d", "--name", core,
                 "--network", app_network, "--network-alias", "core",
                 "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={state},target=/state",
                 "-e", "SOVEREIGN_FIXTURE_ROOT=/state",
                 "-e", "SOVEREIGN_OIDC_ISSUER=" + ISSUER,
                 "-e", "SOVEREIGN_OIDC_CA_FILE=/state/ca.pem",
                 "-e", "SOVEREIGN_OIDC_REVOCATIONS=/state/revoked.jsonl",
                 "-e", "SOVEREIGN_THREAT_SNAPSHOT_STORE=/state/threat-intel",
                 "-e", "SOVEREIGN_THREAT_SNAPSHOT_KEY=/state/threat-intel/trusted.pem",
                 "sovereign-core:synthetic")
            _run("docker", "network", "connect", identity_network, core)
            _run("docker", "run", "-d", "--name", console,
                 "--network", browser_network,
                 "--publish", "127.0.0.1:18080:8080",
                 "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                 "--mount", f"type=bind,source={config},target=/srv/console-config.json,readonly",
                 "sovereign-console:synthetic")
            _run("docker", "network", "connect", app_network, console)
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
            console_error = "no response"
            for _ in range(30):
                try:
                    with urlopen("http://127.0.0.1:18080/", timeout=2) as response:
                        if response.status == 200:
                            break
                        console_error = f"HTTP {response.status}"
                except OSError as error:
                    console_error = str(error)
                if _run("docker", "inspect", console, "--format", "{{.State.Running}}") != "true":
                    raise AssertionError("synthetic vessel Console stopped before readiness")
                time.sleep(0.5)
            else:
                raise AssertionError(f"synthetic vessel Console did not become ready: {console_error}")
            proxy = subprocess.Popen([
                "sudo", "-n", str(Path.cwd() / ".venv/bin/python"), "-m",
                "scripts.phase8_fleet_https_proxy", "--cert", str(console_cert),
                "--key", str(console_key), "--host", CONSOLE_HOST,
            ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(50):
                if proxy.poll() is not None:
                    raise RuntimeError("synthetic vessel HTTPS bridge failed: " +
                                       proxy.stderr.read().decode()[-1000:])
                try:
                    request = Request("https://127.0.0.2/", headers={"Host": CONSOLE_HOST})
                    with urlopen(request, context=ssl._create_unverified_context(), timeout=1):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise AssertionError("synthetic vessel HTTPS bridge did not become ready")
            return _browser(password, chromedriver, mfa=mfa)
        finally:
            if proxy:
                proxy.terminate()
                proxy.wait(timeout=5)
            subprocess.run(["docker", "rm", "-f", console, core, keycloak],
                           capture_output=True, text=True)
            subprocess.run(["docker", "network", "rm", browser_network,
                            app_network, identity_network], capture_output=True, text=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chromedriver", required=True)
    parser.add_argument("--mfa", action="store_true")
    args = parser.parse_args()
    print(json.dumps(rehearse(args.chromedriver, mfa=args.mfa), sort_keys=True))
