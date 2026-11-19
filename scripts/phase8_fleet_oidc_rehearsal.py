"""Exercise signed Fleet images against an ephemeral HTTPS JWKS service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import ipaddress
from pathlib import Path
import subprocess
import sys
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import jwt

from infrastructure.deploy.fleet_installer import fleet_status, install_fleet
from infrastructure.deploy.fleet_runtime import FleetRuntime, RuntimeError, stop_runtime
import infrastructure.deploy.fleet_runtime as fleet_runtime


IDENTITY_HOST = "identity.fleet"
ISSUER = f"https://{IDENTITY_HOST}/realms/fleet"
_SERVER = '''from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path != "/realms/fleet/protocol/openid-connect/certs":
   self.send_error(404)
   return
  data=open("/idp/jwks.json","rb").read()
  self.send_response(200)
  self.send_header("Content-Type","application/json")
  self.send_header("Content-Length",str(len(data)))
  self.end_headers()
  self.wfile.write(data)
server=HTTPServer(("0.0.0.0",443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/idp/cert.pem","/idp/key.pem")
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
'''


def _run(*args: str, timeout: int = 120) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=timeout).stdout.strip()


def _private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _identity_material(root: Path, kid: str = "fleet-synthetic-https") -> tuple[Path, Path, rsa.RSAPrivateKey]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Fleet CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                   ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             IDENTITY_HOST)])
    leaf_cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
                 .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - timedelta(days=1))
                 .not_valid_after(now + timedelta(days=2))
                 .add_extension(x509.SubjectAlternativeName([
                     x509.DNSName(IDENTITY_HOST)]), critical=False)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                     ca_key.public_key()), critical=False)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                                critical=False)
                 .sign(ca_key, hashes.SHA256()))
    idp = root / "synthetic-idp"
    idp.mkdir(mode=0o700, parents=True)
    ca = root / "synthetic-ca.pem"
    _private(ca, ca_cert.public_bytes(serialization.Encoding.PEM))
    _private(idp / "cert.pem", leaf_cert.public_bytes(serialization.Encoding.PEM))
    _private(idp / "key.pem", leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    _private(idp / "jwks.json", json.dumps({"keys": [jwk]}).encode())
    return idp, ca, signing_key


def _token(key: rsa.RSAPrivateKey, *, audience: str = "sovereign-fleet",
           kid: str = "fleet-synthetic-https") -> str:
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "aud": audience,
                       "azp": "sovereign-fleet-portal", "typ": "Bearer",
                       "sub": "synthetic-company-admin", "preferred_username": "admin",
                       "realm_access": {"roles": ["fleet_admin"]},
                       "iat": now, "exp": now + 300}, key,
                      algorithm="RS256", headers={"kid": kid})


def _replace_mounted(path: Path, data: bytes) -> None:
    """Update a synthetic bind-mounted file without changing its inode."""
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _expect_token(api_id: str, token: str, allowed: bool) -> None:
    url = "http://fleet-portal:8080/api/fleet/me"
    script = ('import json,urllib.error,urllib.request\n'
              f'r=urllib.request.Request({url!r},headers={{"Authorization":"Bearer {token}"}})\n'
              'try:\n u=json.load(urllib.request.urlopen(r,timeout=5))\n'
              'except urllib.error.HTTPError as e:\n'
              + (' raise AssertionError("valid token denied")\n' if allowed else
                 ' assert e.code==401\n')
              + 'else:\n'
              + (' assert u=={"id":"admin","role":"fleet_admin","customer_codes":["*"]}\n'
                 if allowed else ' raise AssertionError("stale token accepted")\n'))
    _run("docker", "exec", api_id, "python", "-c", script)


def rehearse_oidc(bundle: Path, trusted: Path, crane: Path,
                   root: Path) -> dict[str, str]:
    """Retain only metadata about actual container and token outcomes."""
    idp, ca, signing_key = _identity_material(root)
    config = root / "fleet-https-config.json"
    config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}) + "\n")
    roles = root / "fleet-https-roles.json"
    _private(roles, json.dumps({"users": [{"id": "admin", "role": "fleet_admin",
                                           "status": "active", "customer_codes": ["*"]}]}).encode())
    suffix = uuid.uuid4().hex[:8]
    network = f"fleet-identity-{suffix}"
    server = f"fleet-idp-{suffix}"
    install_root = root / "fleet-https-install"
    _run("docker", "network", "create", "--internal", "--label",
         "sovereign.fleet.identity=true", network)
    try:
        _run("docker", "run", "-d", "--name", server,
             "--network", network, "--network-alias", IDENTITY_HOST,
             "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
             "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
             "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
             "--mount", f"type=bind,source={idp},target=/idp,readonly",
             "--entrypoint", "python", "sovereign-fleet-api:synthetic",
             "-c", _SERVER)
        for attempt in range(10):
            if _run("docker", "inspect", server, "--format", "{{.State.Running}}") != "true":
                logs = subprocess.run(["docker", "logs", "--tail", "20", server],
                                      capture_output=True, text=True)
                raise AssertionError("synthetic IdP exited: " + logs.stderr[-1000:])
            ready = subprocess.run(
                ["docker", "exec", server, "python", "-c",
                 "import socket; socket.create_connection(('127.0.0.1',443),timeout=2).close()"],
                capture_output=True, text=True, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("synthetic IdP did not open HTTPS port")
        try:
            network_settings = json.loads(_run(
                "docker", "inspect", server, "--format",
                "{{json .NetworkSettings.Networks}}"))
            server_ip = network_settings[network]["IPAddress"]
            if not ipaddress.ip_address(server_ip).is_private:
                raise AssertionError("synthetic IdP is outside the private identity network")
            original_docker = fleet_runtime._docker
            last_probe_error = ""

            def synthetic_host_docker(*args: str) -> str:
                nonlocal last_probe_error
                try:
                    if args and args[0] == "run" and "fleet-api" in args:
                        return original_docker(*args[:-1], "--add-host",
                                               f"{IDENTITY_HOST}:{server_ip}", args[-1])
                    return original_docker(*args)
                except RuntimeError as exc:
                    if args and args[0] == "exec":
                        last_probe_error = str(getattr(exc.__cause__, "stderr", ""))[-1000:]
                    raise

            fleet_runtime._docker = synthetic_host_docker
            try:
                installed = install_fleet(bundle, trusted, crane, config, install_root,
                                          roles_file=roles, identity_network=network,
                                          ca_file=ca)
            except RuntimeError as exc:
                status = subprocess.run(
                    ["docker", "inspect", server, "--format", "{{.State.Status}}"],
                    capture_output=True, text=True)
                logs = subprocess.run(["docker", "logs", "--tail", "10", server],
                                      capture_output=True, text=True)
                raise AssertionError(
                    "synthetic Fleet activation failed: " + last_probe_error +
                    f" IdP status={status.stdout.strip() or status.stderr[-200:]}" +
                    f" IdP log={logs.stderr[-500:]}") from exc
            finally:
                fleet_runtime._docker = original_docker
            if fleet_status(install_root, trusted)["active"] != installed["active"]:
                raise AssertionError("OIDC Fleet install is not healthy")
            state = json.loads((install_root / "fleet-state.json").read_text())
            handle = FleetRuntime(**state["runtime"])
            if handle.identity_network_name != network:
                raise AssertionError("OIDC identity network was not retained")
            valid = _token(signing_key)
            _expect_token(handle.api_id, valid, True)
            wrong = _token(signing_key, audience="sovereign-core")
            _expect_token(handle.api_id, wrong, False)

            # Simulate the operator's staged trust change on the actual mounted
            # files. Restarting the API clears its bounded JWKS cache at cutover.
            next_idp, next_ca, next_signing = _identity_material(
                root / "next-identity", "fleet-synthetic-next")
            installed_ca = install_root / "identity" / "ca.pem"
            old_ca = ca.read_bytes()
            new_ca = next_ca.read_bytes()
            next_jwk = json.loads((next_idp / "jwks.json").read_text())["keys"][0]
            old_jwk = json.loads((idp / "jwks.json").read_text())["keys"][0]
            rotated = _token(next_signing, kid="fleet-synthetic-next")

            _replace_mounted(installed_ca, new_ca)
            _run("docker", "restart", handle.api_id)
            try:
                fleet_status(install_root, trusted)
            except RuntimeError:
                pass
            else:
                raise AssertionError("untrusted CA rotation remained healthy")
            _replace_mounted(installed_ca, old_ca)
            _run("docker", "restart", handle.api_id)
            if fleet_status(install_root, trusted)["result"] != "healthy":
                raise AssertionError("failed CA rotation did not recover")
            _expect_token(handle.api_id, valid, True)

            _replace_mounted(installed_ca, old_ca + new_ca)
            _run("docker", "restart", handle.api_id)
            if fleet_status(install_root, trusted)["result"] != "healthy":
                raise AssertionError("CA overlap denied old issuer")
            _replace_mounted(idp / "jwks.json", json.dumps({"keys": [old_jwk, next_jwk]}).encode())
            _expect_token(handle.api_id, rotated, True)
            _expect_token(handle.api_id, valid, True)
            _replace_mounted(idp / "cert.pem", (next_idp / "cert.pem").read_bytes())
            _replace_mounted(idp / "key.pem", (next_idp / "key.pem").read_bytes())
            _run("docker", "restart", server)
            if fleet_status(install_root, trusted)["result"] != "healthy":
                raise AssertionError("CA overlap denied new issuer")
            _expect_token(handle.api_id, rotated, True)

            _replace_mounted(idp / "jwks.json", json.dumps({"keys": [next_jwk]}).encode())
            _replace_mounted(installed_ca, new_ca)
            _run("docker", "restart", handle.api_id)
            if fleet_status(install_root, trusted)["result"] != "healthy":
                raise AssertionError("new trust did not survive cutover")
            _expect_token(handle.api_id, rotated, True)
            _expect_token(handle.api_id, valid, False)
            _replace_mounted(installed_ca, old_ca)
            _run("docker", "restart", handle.api_id)
            try:
                fleet_status(install_root, trusted)
            except RuntimeError:
                pass
            else:
                raise AssertionError("stale CA trusted new issuer")
            _replace_mounted(installed_ca, new_ca)
            _run("docker", "restart", handle.api_id)
            if fleet_status(install_root, trusted)["result"] != "healthy":
                raise AssertionError("stale CA recovery failed")
            _expect_token(handle.api_id, rotated, True)
            _run("docker", "stop", server)
            try:
                fleet_status(install_root, trusted)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Fleet status passed without its identity provider")
            return {"oidc_runtime": "synthetic-https-token-authorized",
                    "wrong_audience": "denied", "idp_outage": "status-failed-closed",
                    "trust_rotation": "overlap-cutover-stale-trust-and-recovery"}
        finally:
            state_file = install_root / "fleet-state.json"
            if state_file.exists():
                state = json.loads(state_file.read_text())
                stop_runtime(FleetRuntime(**state["runtime"]))
    finally:
        subprocess.run(["docker", "rm", "-f", server], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)


def main() -> None:
    raise SystemExit("Run through the signed Fleet release rehearsal")


if __name__ == "__main__":
    main()
