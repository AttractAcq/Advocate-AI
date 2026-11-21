"""Exercise signed vessel images with a fictional local HTTPS identity service."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle, stop_runtime
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle, stop_knowledge
from infrastructure.deploy.vessel_installer import install_vessel, status_vessel, stop_vessel
from infrastructure.deploy.vessel_recovery_set import (
    activate_vessel_recovery_set, create_vessel_recovery_set,
    verify_vessel_recovery_receipt,
)
from scripts.phase8_fleet_oidc_rehearsal import (
    IDENTITY_HOST, _SERVER, _identity_material,
)
from scripts.synthetic_pg_fixture import put


ISSUER = f"https://{IDENTITY_HOST}/realms/sovereign"
_SERVER_REALM = _SERVER.replace("/realms/fleet/", "/realms/sovereign/")
_KID = "vessel-synthetic-https"


def _run(*args: str, timeout: int = 120) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"synthetic OIDC command failed: {args[:2]}: " +
                             result.stderr[-1200:])
    return result.stdout.strip()


def _token(key, user: str, role: str, *, audience: str = "sovereign-core") -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({
        "iss": ISSUER, "aud": audience, "azp": "sovereign-console", "typ": "Bearer",
        "sub": "fictional-" + user, "preferred_username": user,
        "realm_access": {"roles": [role]}, "jti": uuid.uuid4().hex,
        "iat": now, "exp": now + 300,
    }, key, algorithm="RS256", headers={"kid": _KID})


def _api(core_id: str, path: str, token: str | None = None,
         *, method: str = "GET") -> tuple[int, object]:
    code = (
        'import json,sys,httpx\n'
        'path,token,method=sys.argv[1:]\n'
        'headers={"Authorization":"Bearer "+token} if token!="-" else {}\n'
        'with httpx.Client(base_url="http://127.0.0.1:18100",'
        'trust_env=False,timeout=8) as client:\n'
        ' body={"user_id":"engineer","password":"synthetic-invalid"}'
        ' if path=="/api/login" else None\n'
        ' response=client.request(method,path,headers=headers,json=body)\n'
        ' print(json.dumps({"status":response.status_code,'
        '"body":response.json() if response.content else None}))\n')
    result = json.loads(_run("docker", "exec", core_id, "python", "-c", code,
                             path, token or "-", method, timeout=30))
    return result["status"], result["body"]


def _retire(install_root: Path) -> str | None:
    path = install_root / "vessel-state.json"
    if not path.exists():
        return None
    record = json.loads(path.read_text())
    runtime = record["runtime"]
    stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                               runtime["console_id"],
                               record["identity"]["network_id"],
                               record["identity"]["network_name"]))
    try:
        stop_knowledge(KnowledgeVolumeHandle(
            runtime["knowledge_id"], runtime["socket_volume"],
            runtime["data_volume"], runtime["knowledge_run"],
            record["installation_id"]))
    except Exception:
        pass
    return runtime["data_volume"]


def rehearse(bundle: Path, trusted: Path, crane: Path, root: Path,
             restic: Path, restic_sha256: str) -> dict[str, str]:
    """Use signed images, local TLS JWKS, encrypted Core recovery and role denial."""
    idp, ca, signing_key = _identity_material(root, kid=_KID)
    state = root / "vessel-oidc-state"
    shutil.copytree(root / "vessel-state", state)
    shutil.copy2(ca, state / "oidc-ca.pem")
    put(state / "oidc-revocations.jsonl", b"")
    config = root / "vessel-oidc-config.json"
    config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}))
    config.chmod(0o644)
    suffix = uuid.uuid4().hex[:8]
    network = "vessel-identity-" + suffix
    server = "vessel-idp-" + suffix
    install_root = root / "vessel-oidc-install"
    restored_root = root / "vessel-oidc-restored-install"
    restored_state = root / "vessel-oidc-restored-state"
    volumes: set[str] = set()
    _run("docker", "network", "create", "--internal", "--label",
         "sovereign.vessel.identity=true", network)
    try:
        _run("docker", "run", "-d", "--name", server,
             "--network", network, "--network-alias", IDENTITY_HOST,
             "--user", f"{os.getuid()}:{os.getgid()}", "--read-only",
             "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
             "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
             "--mount", f"type=bind,source={idp},target=/idp,readonly",
             "--entrypoint", "python", "sovereign-core:synthetic",
             "-c", _SERVER_REALM)
        for _ in range(20):
            ready = subprocess.run(
                ["docker", "exec", server, "python", "-c",
                 "import socket; socket.create_connection(('127.0.0.1',443),timeout=2).close()"],
                capture_output=True, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("fictional vessel IdP did not become ready")
        installed = install_vessel(bundle, trusted, crane, config, install_root,
                                   state, None, identity_network=network)
        status = status_vessel(install_root, trusted, crane)
        if installed["result"] != "activated" or status["result"] != "healthy":
            raise AssertionError("signed OIDC vessel installation is not healthy")
        record = json.loads((install_root / "vessel-state.json").read_text())
        if record["schema"] != 2 or "lab_password_file" in record:
            raise AssertionError("OIDC installation retained lab credentials")
        runtime = record["runtime"]
        volumes.add(runtime["data_volume"])
        core = runtime["core_id"]
        engineer = _token(signing_key, "engineer", "chief_engineer")
        deckhand = _token(signing_key, "deckhand", "deckhand")
        wrong_audience = _token(signing_key, "engineer", "chief_engineer",
                                audience="another-service")
        if (_api(core, "/api/me", engineer) !=
                (200, {"id": "engineer", "role": "chief_engineer"}) or
                _api(core, "/api/me", wrong_audience)[0] != 401 or
                _api(core, "/api/login", method="POST")[0] != 404):
            raise AssertionError("signed Core OIDC claim boundary failed")
        engineer_sources = _api(core, "/api/sources", engineer)
        deck_sources = _api(core, "/api/sources", deckhand)
        if (engineer_sources[0] != 200 or deck_sources[0] != 200 or
                "ENG-001" not in {row["document_id"] for row in engineer_sources[1]["sources"]} or
                "ENG-001" in {row["document_id"] for row in deck_sources[1]["sources"]}):
            raise AssertionError("signed Core leaked engineering source to deckhand")
        if (_api(core, "/api/logout", engineer, method="POST") != (200, {"ok": True}) or
                _api(core, "/api/me", engineer)[0] != 401):
            raise AssertionError("signed Core OIDC revocation failed")
        if not (state / "oidc-revocations.jsonl").read_bytes():
            raise AssertionError("OIDC revocation was not persisted")
        stop_vessel(install_root, trusted, crane)
        recovery = root / "vessel-oidc-recovery"
        recovery.mkdir(mode=0o700)
        staging = recovery / "staging"
        staging.mkdir(mode=0o700)
        password = recovery / "restic-password"
        put(password, ("synthetic-oidc-backup-" + uuid.uuid4().hex).encode())
        receipt_private = recovery / "receipt-private.pem"
        receipt_public = recovery / "receipt-public.pem"
        key = Ed25519PrivateKey.generate()
        put(receipt_private, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        receipt_public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        receipt = recovery / "receipt.json"
        captured = create_vessel_recovery_set(
            install_root, trusted, crane, recovery / "repository", password,
            restic, restic_sha256, staging, receipt_private, receipt)
        if (captured["schema"] != 3 or
                verify_vessel_recovery_receipt(receipt, receipt_public) != captured):
            raise AssertionError("signed OIDC recovery receipt is incomplete")
        _run("docker", "volume", "rm", runtime["data_volume"])
        volumes.discard(runtime["data_volume"])
        recovered = activate_vessel_recovery_set(
            bundle, trusted, crane, config, receipt, receipt_public, password,
            restic, restic_sha256, restored_root, restored_state, None,
            staging, identity_network=network)
        restored = json.loads((restored_root / "vessel-state.json").read_text())
        volumes.add(restored["runtime"]["data_volume"])
        if (recovered["result"] != "restored-and-activated" or
                status_vessel(restored_root, trusted, crane)["result"] != "healthy" or
                _api(restored["runtime"]["core_id"], "/api/me", engineer)[0] != 401 or
                _api(restored["runtime"]["core_id"], "/api/me",
                     _token(signing_key, "engineer", "chief_engineer"))[0] != 200):
            raise AssertionError("signed OIDC clean restore lost revocation or trust")
        return {"result": "pass", "identity": "fictional-local-tls-jwks",
                "lab_fallback": "denied", "role_scope": "engineering-source-denied-to-deck",
                "recovery": "encrypted-core-revocation-persisted"}
    finally:
        for candidate in (restored_root, install_root):
            volume = _retire(candidate)
            if volume is not None:
                volumes.add(volume)
        for volume in volumes:
            subprocess.run(["docker", "volume", "rm", volume],
                           capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", "-f", server],
                       capture_output=True, timeout=30)
        subprocess.run(["docker", "network", "rm", network],
                       capture_output=True, timeout=30)
