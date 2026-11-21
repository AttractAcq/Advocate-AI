"""Rehearse a stopped synthetic signed vessel plus real Keycloak recovery."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

from infrastructure.backup import generate_key
from infrastructure.deploy.vessel_identity_recovery import (
    create_identity_recovery_pair, restore_paired_realm,
)
from infrastructure.deploy.vessel_installer import install_vessel, status_vessel, stop_vessel
from infrastructure.deploy.vessel_recovery_set import (
    activate_vessel_recovery_set, create_vessel_recovery_set,
    verify_vessel_recovery_receipt,
)
from scripts.phase3_identity import KEYCLOAK_BASE64_FLAG
from scripts.phase3_vessel_keycloak_rehearsal import (
    _backup_realm, _flow, _realm,
)
from scripts.phase5_vessel_oidc_rehearsal import _api, _retire, _run, ISSUER
from scripts.phase8_fleet_oidc_rehearsal import IDENTITY_HOST, _identity_material
from scripts.synthetic_pg_fixture import put


def _wait_keycloak(network: str, ca: Path) -> None:
    probe = ("import httpx; assert httpx.get('" + ISSUER +
             "/protocol/openid-connect/certs', verify='/tmp/ca.pem', "
             "trust_env=False, timeout=3).status_code == 200")
    for _ in range(90):
        ready = subprocess.run([
            "docker", "run", "--pull", "never", "--rm", "--network", network,
            "--mount", f"type=bind,source={ca},target=/tmp/ca.pem,readonly",
            "--entrypoint", "python", "sovereign-core:synthetic",
            "-c", probe,
        ], capture_output=True, timeout=12)
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise AssertionError("synthetic Keycloak did not expose vessel JWKS")


def _keycloak(name: str, network: str, volume: str, reference: str,
              idp: Path, realm: Path, password: str | None) -> None:
    _run("docker", "run", "--pull", "never", "-d", "--name", name,
         "--network", network, "--network-alias", IDENTITY_HOST,
         "--env", KEYCLOAK_BASE64_FLAG,
         "--mount", f"type=volume,source={volume},target=/opt/keycloak/data",
         "--mount", f"type=bind,source={idp / 'cert.pem'},target=/tmp/vessel-cert.pem,readonly",
         "--mount", f"type=bind,source={idp / 'key.pem'},target=/tmp/vessel-key.pem,readonly",
         "--mount", f"type=bind,source={realm},target=/opt/keycloak/data/import,readonly",
         *(["--env", "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-admin",
            "--env", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + password]
           if password is not None else []),
         reference, "start-dev", "--import-realm", "--http-enabled=false",
         "--hostname=https://" + IDENTITY_HOST,
         "--https-port=443", "--https-certificate-file=/tmp/vessel-cert.pem",
         "--https-certificate-key-file=/tmp/vessel-key.pem")


def rehearse(bundle: Path, trusted: Path, crane: Path, root: Path,
             restic: Path, restic_sha256: str) -> dict[str, str]:
    """Use one stopped lab point for signed Core/Knowledge and realm export."""
    suffix = uuid.uuid4().hex[:8]
    network = "vessel-paired-identity-" + suffix
    keycloak = "vessel-paired-keycloak-" + suffix
    original_volume = "vessel-paired-idp-data-" + suffix
    restored_volume = "vessel-paired-idp-restored-" + suffix
    reference = json.loads(Path("infrastructure/lab/container-image.json").read_text())
    reference = reference["name"] + "@" + reference["digest"]
    idp, ca, _ = _identity_material(root / ("paired-identity-" + suffix))
    idp.chmod(0o755)
    for name in ("cert.pem", "key.pem"):
        (idp / name).chmod(0o644)
    ca.chmod(0o644)
    state = root / ("vessel-paired-state-" + suffix)
    shutil.copytree(root / "vessel-state", state)
    put(state / "oidc-ca.pem", ca.read_bytes())
    put(state / "oidc-revocations.jsonl", b"")
    config = root / ("vessel-paired-config-" + suffix + ".json")
    config.write_text(json.dumps({"schema": 1, "oidc_issuer": ISSUER}))
    config.chmod(0o644)
    password = "synthetic-" + uuid.uuid4().hex
    realm = root / ("vessel-paired-realm-" + suffix)
    realm.mkdir(mode=0o755)
    realm_value = _realm(password)
    for user, username in zip(realm_value["users"], ("engineer", "deckhand")):
        user["username"] = username
        user["email"] = username + "@synthetic.example.invalid"
    realm_value["accessTokenLifespan"] = 900
    (realm / "sovereign-realm.json").write_text(json.dumps(realm_value))
    (realm / "sovereign-realm.json").chmod(0o644)
    install_root = root / ("vessel-paired-install-" + suffix)
    restored_root = root / ("vessel-paired-restored-install-" + suffix)
    restored_state = root / ("vessel-paired-restored-state-" + suffix)
    volumes: set[str] = set()
    _run("docker", "network", "create", "--internal", "--label",
         "sovereign.vessel.identity=true", network)
    _run("docker", "volume", "create", original_volume)
    volumes.add(original_volume)
    try:
        _keycloak(keycloak, network, original_volume, reference, idp, realm,
                  password)
        _wait_keycloak(network, ca)
        installed = install_vessel(bundle, trusted, crane, config, install_root,
                                   state, None, identity_network=network)
        if (installed["result"] != "activated" or
                status_vessel(install_root, trusted, crane)["result"] != "healthy"):
            raise AssertionError("signed vessel did not activate with real Keycloak")
        runtime = json.loads((install_root / "vessel-state.json").read_text())["runtime"]
        volumes.add(runtime["data_volume"])
        core = runtime["core_id"]
        engineer = _flow(core, password, "engineer", "chief_engineer",
                         ca_path="/var/lib/sovereign/oidc-ca.pem")
        deckhand = _flow(core, password, "deckhand", "deckhand",
                         ca_path="/var/lib/sovereign/oidc-ca.pem")
        engineer_sources = _api(core, "/api/sources", engineer)
        deck_sources = _api(core, "/api/sources", deckhand)
        if (engineer_sources[0] != 200 or deck_sources[0] != 200 or
                "ENG-001" not in {row["document_id"] for row in engineer_sources[1]["sources"]} or
                "ENG-001" in {row["document_id"] for row in deck_sources[1]["sources"]}):
            raise AssertionError("signed Keycloak vessel source scope failed")
        if (_api(core, "/api/logout", engineer, method="POST") !=
                (200, {"ok": True}) or _api(core, "/api/me", engineer)[0] != 401):
            raise AssertionError("signed vessel did not revoke engineer token")
        stop_vessel(install_root, trusted, crane)
        _run("docker", "stop", keycloak)
        recovery = root / ("vessel-paired-recovery-" + suffix)
        recovery.mkdir(mode=0o700)
        staging = recovery / "staging"
        staging.mkdir(mode=0o700)
        password_file = recovery / "restic-password"
        put(password_file, ("synthetic-paired-backup-" + uuid.uuid4().hex).encode())
        receipt_private = recovery / "receipt-private.pem"
        receipt_public = recovery / "receipt-public.pem"
        key = Ed25519PrivateKey.generate()
        put(receipt_private, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        receipt_public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        receipt = recovery / "core-receipt.json"
        captured = create_vessel_recovery_set(
            install_root, trusted, crane, recovery / "repository", password_file,
            restic, restic_sha256, staging, receipt_private, receipt)
        if captured["schema"] != 3 or verify_vessel_recovery_receipt(
                receipt, receipt_public) != captured:
            raise AssertionError("signed vessel recovery receipt is incomplete")
        exported = recovery / "exported"
        exported.mkdir(mode=0o777)
        exported.chmod(0o777)
        _run("docker", "run", "--pull", "never", "--rm", "--network", "none",
             "--mount", f"type=volume,source={original_volume},target=/opt/keycloak/data",
             "--mount", f"type=bind,source={exported},target=/synthetic-export",
             reference, "export", "--realm", "sovereign", "--users", "realm_file",
             "--dir", "/synthetic-export", timeout=180)
        archive_key = recovery / "archive.key"
        generate_key(archive_key)
        archive = recovery / "realm.svbk"
        checkpoint = _backup_realm(exported / "sovereign-realm.json",
                                   recovery, archive, archive_key)
        shutil.rmtree(exported)
        pair = recovery / "pair.json"
        create_identity_recovery_pair(receipt, receipt_public, archive,
                                      archive_key, checkpoint, receipt_private,
                                      pair)
        restored_realm = recovery / "restored-realm"
        restore_paired_realm(pair, receipt_public, receipt, receipt_public,
                             archive, archive_key, restored_realm)
        restored_realm.chmod(0o755)
        (restored_realm / "sovereign-realm.json").chmod(0o644)
        _run("docker", "rm", keycloak)
        _run("docker", "volume", "rm", original_volume)
        volumes.discard(original_volume)
        _run("docker", "volume", "create", restored_volume)
        volumes.add(restored_volume)
        _keycloak(keycloak, network, restored_volume, reference, idp,
                  restored_realm, None)
        _wait_keycloak(network, ca)
        _run("docker", "volume", "rm", runtime["data_volume"])
        volumes.discard(runtime["data_volume"])
        recovered = activate_vessel_recovery_set(
            bundle, trusted, crane, config, receipt, receipt_public,
            password_file, restic, restic_sha256, restored_root,
            restored_state, None, staging, identity_network=network)
        restored = json.loads((restored_root / "vessel-state.json").read_text())
        volumes.add(restored["runtime"]["data_volume"])
        restored_core = restored["runtime"]["core_id"]
        unsigned_options = {"verify_signature": False, "verify_exp": False}
        if (recovered["result"] != "restored-and-activated" or
                status_vessel(restored_root, trusted, crane)["result"] != "healthy" or
                jwt.decode(engineer, options=unsigned_options)["exp"] <= time.time() or
                jwt.decode(deckhand, options=unsigned_options)["exp"] <= time.time() or
                _api(restored_core, "/api/me", deckhand) !=
                (200, {"id": "deckhand", "role": "deckhand"}) or
                _api(restored_core, "/api/me", engineer)[0] != 401):
            raise AssertionError("paired restore lost signing-key continuity or revocation")
        fresh = _flow(restored_core, password, "engineer", "chief_engineer",
                      ca_path="/var/lib/sovereign/oidc-ca.pem")
        fresh_deck = _flow(restored_core, password, "deckhand", "deckhand",
                           ca_path="/var/lib/sovereign/oidc-ca.pem")
        if (_api(restored_core, "/api/me", fresh) !=
                (200, {"id": "engineer", "role": "chief_engineer"}) or
                "ENG-001" in {row["document_id"] for row in
                              _api(restored_core, "/api/sources", fresh_deck)[1]["sources"]}):
            raise AssertionError("restored signed vessel lost crew role scope")
        return {"result": "pass", "identity": "real-pinned-keycloak",
                "capture": "both-services-stopped", "pair": "signed-artifact-identities",
                "recovery": "clean-keycloak-core-knowledge",
                "old_deckhand_token": "authorized-after-restore",
                "old_engineer_token": "revoked-after-restore"}
    finally:
        for candidate in (restored_root, install_root):
            volume = _retire(candidate)
            if volume is not None:
                volumes.add(volume)
        subprocess.run(["docker", "rm", "-f", keycloak],
                       capture_output=True, timeout=30)
        for volume in volumes:
            subprocess.run(["docker", "volume", "rm", volume],
                           capture_output=True, timeout=30)
        subprocess.run(["docker", "network", "rm", network],
                       capture_output=True, timeout=30)
