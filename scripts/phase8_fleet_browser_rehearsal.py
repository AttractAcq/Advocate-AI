"""Synthetic HTTPS browser exercise for the built Fleet portal.

This uses ChromeDriver's W3C HTTP interface without adding a test dependency.
The identity endpoint is a deliberately small PKCE fixture; actual Keycloak
protocol interoperability is exercised by phase8_fleet_keycloak_rehearsal.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


FLEET = "fleet.example.invalid"
IDENTITY = "identity.example.invalid"
ISSUER = f"https://{IDENTITY}/realms/fleet"
TOKEN = "synthetic-browser-access-token"
ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "apps/fleet/web/dist"


def certificate(folder: Path, host: str) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = folder / f"{host}.key", folder / f"{host}.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class FixtureHandler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def send_bytes(self, status: int, body: bytes, content_type: str = "text/plain",
                   extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, target: str) -> None:
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if self.server.kind == "fleet":
            if url.path == "/fleet-config.json":
                self.send_bytes(200, json.dumps({"schema": 1, "oidc_issuer": ISSUER}).encode(),
                                "application/json")
                return
            if url.path.startswith("/api/fleet/"):
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self.send_bytes(401, b"{}", "application/json")
                elif url.path == "/api/fleet/me":
                    self.send_bytes(200, b'{"id":"admin","role":"fleet_admin","customer_codes":["*"]}',
                                    "application/json")
                else:
                    self.send_bytes(200, b"[]", "application/json")
                return
            relative = "index.html" if url.path == "/" else url.path.lstrip("/")
            path = (DIST / relative).resolve()
            if not path.is_relative_to(DIST.resolve()) or not path.is_file():
                self.send_bytes(404, b"")
                return
            self.send_bytes(200, path.read_bytes(), mimetypes.guess_type(path.name)[0] or "application/octet-stream")
            return
        if url.path.endswith("/auth"):
            query = parse_qs(url.query)
            if (query.get("client_id") != ["sovereign-fleet-portal"] or
                query.get("redirect_uri") != [f"https://{FLEET}/"] or
                query.get("code_challenge_method") != ["S256"] or
                not query.get("state") or not query.get("code_challenge")):
                self.send_bytes(400, b"invalid authorization request")
                return
            state = query["state"][0]
            self.server.states[state] = query["code_challenge"][0]
            body = ("<html><body><h1>Synthetic identity</h1>"
                    "<form method='post' action='/login'>"
                    f"<input type='hidden' name='state' value='{state}'>"
                    "<label>User <input name='username'></label>"
                    "<label>Password <input name='password' type='password'></label>"
                    "<button type='submit'>Continue</button></form></body></html>")
            self.send_bytes(200, body.encode(), "text/html; charset=utf-8")
            return
        if url.path.endswith("/logout"):
            query = parse_qs(url.query)
            if query.get("post_logout_redirect_uri") == [f"https://{FLEET}/"]:
                self.redirect(f"https://{FLEET}/")
                return
        self.send_bytes(404, b"")

    def do_OPTIONS(self) -> None:
        if self.server.kind == "identity" and self.path.endswith("/token"):
            self.send_bytes(204, b"", extra={
                "Access-Control-Allow-Origin": f"https://{FLEET}",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "content-type",
            })
            return
        self.send_bytes(404, b"")

    def do_POST(self) -> None:
        if self.server.kind != "identity":
            self.send_bytes(404, b"")
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size > 4096:
            self.send_bytes(413, b"")
            return
        form = parse_qs(self.rfile.read(size).decode())
        if self.path == "/login":
            state = form.get("state", [""])[0]
            if (form.get("username") != ["synthetic"] or form.get("password") != ["local-only"]
                    or state not in self.server.states):
                self.send_bytes(403, b"invalid synthetic credentials")
                return
            code = secrets.token_urlsafe(24)
            self.server.codes[code] = self.server.states.pop(state)
            self.redirect(f"https://{FLEET}/?" + urlencode({"code": code, "state": state}))
            return
        if self.path.endswith("/token"):
            code = form.get("code", [""])[0]
            verifier = form.get("code_verifier", [""])[0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            expected = self.server.codes.pop(code, None)
            if (expected is None or expected != challenge or
                form.get("redirect_uri") != [f"https://{FLEET}/"] or
                form.get("client_id") != ["sovereign-fleet-portal"]):
                self.send_bytes(400, b"{}", "application/json")
                return
            self.send_bytes(200, json.dumps({"access_token": TOKEN}).encode(), "application/json",
                            {"Access-Control-Allow-Origin": f"https://{FLEET}"})
            return
        self.send_bytes(404, b"")


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], kind: str, cert: Path, key: Path):
        super().__init__(address, FixtureHandler)
        self.kind = kind
        self.states: dict[str, str] = {}
        self.codes: dict[str, str] = {}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)


def serve(folder: Path) -> None:
    fleet = FixtureServer(("127.0.0.2", 443), "fleet", folder / f"{FLEET}.crt", folder / f"{FLEET}.key")
    identity = FixtureServer(("127.0.0.3", 443), "identity", folder / f"{IDENTITY}.crt",
                             folder / f"{IDENTITY}.key")
    import threading
    threading.Thread(target=fleet.serve_forever, daemon=True).start()
    identity.serve_forever()


def driver_request(method: str, path: str, payload: dict | None = None) -> object:
    raw = None if payload is None else json.dumps(payload).encode()
    request = Request(f"http://127.0.0.1:9515{path}", data=raw, method=method,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=15) as response:
        result = json.load(response)
    if isinstance(result.get("value"), dict) and result["value"].get("error"):
        raise RuntimeError(result["value"])
    return result.get("value")


def until(session: str, expression: str, timeout: float = 25) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = driver_request("POST", f"/session/{session}/execute/sync",
                               {"script": f"return ({expression})", "args": []})
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError(f"browser condition timed out: {expression}")


def run_browser(chromedriver: str) -> dict[str, str]:
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
                       "MAP identity.example.invalid 127.0.0.3"]}}
        result = driver_request("POST", "/session", {"capabilities": {"alwaysMatch": options}})
        assert isinstance(result, dict)
        session = result["sessionId"]
        driver_request("POST", f"/session/{session}/url", {"url": f"https://{FLEET}/"})
        until(session, "document.querySelector('button.primary')?.textContent?.includes('Sign in with local identity')")
        driver_request("POST", f"/session/{session}/execute/sync",
                       {"script": "document.querySelector('button.primary').click()", "args": []})
        until(session, "location.hostname === 'identity.example.invalid' && !!document.querySelector('input[name=username]')")
        driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            document.querySelector('input[name=username]').value = 'synthetic';
            document.querySelector('input[name=password]').value = 'local-only';
            document.querySelector('button[type=submit]').click();
        """, "args": []})
        until(session, "location.hostname === 'fleet.example.invalid' && document.body.textContent.includes('admin · fleet admin')")
        cleared = driver_request("POST", f"/session/{session}/execute/sync", {"script": """
            return !location.search && !sessionStorage.getItem('sovereign_fleet_oidc_state')
                && !sessionStorage.getItem('sovereign_fleet_pkce_verifier');
        """, "args": []})
        assert cleared, "PKCE callback state or code remained in the browser"
        driver_request("POST", f"/session/{session}/execute/sync",
                       {"script": "document.querySelector('.sidebar-bottom button').click()", "args": []})
        until(session, "location.hostname === 'fleet.example.invalid' && document.body.textContent.includes('Sign in with local identity')")
        assert not driver_request("POST", f"/session/{session}/execute/sync",
                                  {"script": "return document.body.textContent.includes('admin · fleet admin')", "args": []})
        return {"browser_flow": "pkce-sign-in-and-sign-out", "callback_state": "cleared",
                "api_role": "fleet_admin"}
    finally:
        if session:
            try:
                driver_request("DELETE", f"/session/{session}")
            except Exception:
                pass
        driver.terminate()
        driver.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", type=Path)
    parser.add_argument("--chromedriver", default=os.environ.get("CHROMEDRIVER", "chromedriver"))
    args = parser.parse_args()
    if args.serve:
        serve(args.serve)
        return
    if not (DIST / "index.html").is_file():
        raise SystemExit("Build the Fleet portal before running browser rehearsal")
    with tempfile.TemporaryDirectory(prefix="fleet-browser-") as name:
        folder = Path(name)
        for host in (FLEET, IDENTITY):
            certificate(folder, host)
        # Binding standard HTTPS on isolated loopback addresses requires sudo on CI.
        server = subprocess.Popen(["sudo", "-n", str(ROOT / ".venv/bin/python"), "-m",
                                   "scripts.phase8_fleet_browser_rehearsal", "--serve", str(folder)],
                                  cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(50):
                if server.poll() is not None:
                    raise RuntimeError(f"HTTPS fixture failed: {server.stderr.read().decode()}")
                try:
                    with urlopen("https://127.0.0.2/", context=ssl._create_unverified_context(), timeout=1):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("HTTPS fixture did not become ready")
            print(json.dumps(run_browser(args.chromedriver), sort_keys=True))
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
