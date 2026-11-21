"""Synthetic three-image install and clean restore with an offline signed feed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import shutil
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle, stop_runtime
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle, stop_knowledge
from infrastructure.deploy.vessel_installer import (
    finish_vessel_stop, install_vessel, status_vessel, stop_vessel,
)
from infrastructure.deploy.vessel_recovery_set import (
    activate_vessel_recovery_set, create_vessel_recovery_set,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_runtime import ThreatFeedMount
from scripts.synthetic_pg_fixture import put
from services.intelligence.threat_snapshot import import_package, sign_payload, trusted_key


_FEED_PROBE = """\
import json
from pathlib import Path
import httpx
with httpx.Client(base_url='http://127.0.0.1:18100',trust_env=False,timeout=5) as client:
 password=Path('/run/secrets/lab-password').read_text().strip()
 login=client.post('/api/login',json={'user_id':'avit','password':password})
 assert login.status_code==200,login.text
 headers={'Authorization':'Bearer '+login.json()['access_token']}
 response=client.get('/api/security/threat-intel',headers=headers)
 assert response.status_code==200,response.text
 result=response.json()
 assert result['status']=='stale',result
 assert result['feed_id']=='synthetic-feed',result
 assert result['publisher']=='synthetic-lab',result
 assert '203.0.113.7' not in response.text,response.text
 print(json.dumps({'result':'pass','status':result['status'],'indicator_values':'withheld'}))
"""


def _run(*command: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError("feed-backed vessel command failed: " + result.stderr[-1200:])
    return result.stdout.strip()


def _retire(install: Path) -> None:
    path = install / "vessel-state.json"
    if not path.exists():
        return
    record = json.loads(path.read_text())
    runtime = record["runtime"]
    try:
        stop_runtime(RuntimeHandle(runtime["network_id"],
                                   runtime["core_id"], runtime["console_id"]))
    except Exception:
        pass
    try:
        stop_knowledge(KnowledgeVolumeHandle(
            runtime["knowledge_id"], runtime["socket_volume"],
            runtime["data_volume"], runtime["knowledge_run"],
            record["installation_id"]))
    except Exception:
        pass
    subprocess.run(["docker", "volume", "rm", runtime["data_volume"]],
                   capture_output=True, text=True, timeout=30)


def rehearse(bundle: Path, trusted: Path, crane: Path, root: Path,
             restic: Path, restic_sha256: str) -> dict[str, str]:
    scope = root / "feed-backed-vessel"
    scope.mkdir(mode=0o700)
    state = scope / "state"
    shutil.copytree(root / "vessel-state", state)
    store = scope / "feed-store"
    store.mkdir(mode=0o700)
    signer = Ed25519PrivateKey.generate()
    private = scope / "feed-signing.pem"
    public = scope / "feed-trusted.pem"
    put(private, signer.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    put(public, signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    issued = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=8)
    payload = scope / "feed-payload.json"
    payload.write_text(json.dumps({
        "schema": 1, "feed_id": "synthetic-feed", "publisher": "synthetic-lab",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=14)).isoformat(),
        "indicators": [{"id": "fictional", "kind": "ipv4",
                        "value": "203.0.113.7"}]}))
    package = scope / "feed-package.json"
    sign_payload(payload, private, package)
    imported = import_package(package, store, trusted_key(public))
    feed = ThreatFeedMount(store, public)
    installed = scope / "installed"
    restored = scope / "restored"
    recovered_state = scope / "recovered-state"
    recovery = scope / "recovery"
    recovery.mkdir(mode=0o700)
    staging = recovery / "staging"
    staging.mkdir(mode=0o700)
    password = recovery / "restic-password"
    put(password, (secrets.token_urlsafe(48) + "\n").encode())
    receipt_signer = Ed25519PrivateKey.generate()
    receipt_private = recovery / "receipt-private.pem"
    receipt_public = recovery / "receipt-public.pem"
    put(receipt_private, receipt_signer.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    put(receipt_public, receipt_signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    try:
        install_vessel(bundle, trusted, crane, root / "console-config.json",
                       installed, state, root / "lab-password", threat_feed=feed)
        if status_vessel(installed, trusted, crane)["result"] != "healthy":
            raise AssertionError("feed-backed vessel install is not healthy")
        first = json.loads((installed / "vessel-state.json").read_text())
        probe = json.loads(_run("docker", "exec", first["runtime"]["core_id"],
                                "python", "-c", _FEED_PROBE))
        if probe != {"result": "pass", "status": "stale",
                     "indicator_values": "withheld"}:
            raise AssertionError("signed Core did not withhold feed indicators")
        stop_vessel(installed, trusted, crane)
        finish_vessel_stop(installed, trusted, crane)
        receipt = recovery / "receipt.json"
        captured = create_vessel_recovery_set(
            installed, trusted, crane, recovery / "repository", password,
            restic, restic_sha256, staging, receipt_private, receipt)
        if (captured["schema"] != 4 or
                captured["feed"]["snapshot_sha256"] != imported["sha256"] or
                verify_vessel_recovery_receipt(receipt, receipt_public) != captured):
            raise AssertionError("signed feed recovery receipt did not bind snapshot")
        # Clean activation preserves the installation ID and therefore needs
        # the stopped source's data volume to be absent on this disposable host.
        _run("docker", "volume", "rm", first["runtime"]["data_volume"])
        activate_vessel_recovery_set(
            bundle, trusted, crane, root / "console-config.json", receipt,
            receipt_public, password, restic, restic_sha256, restored,
            recovered_state, root / "lab-password", staging, threat_feed=feed)
        if status_vessel(restored, trusted, crane)["result"] != "healthy":
            raise AssertionError("feed-backed clean restore is not healthy")
        second = json.loads((restored / "vessel-state.json").read_text())
        recovered_probe = json.loads(_run(
            "docker", "exec", second["runtime"]["core_id"],
            "python", "-c", _FEED_PROBE))
        if recovered_probe != probe or second.get("threat_feed") is None:
            raise AssertionError("feed binding changed during clean restore")
        return {"result": "pass", "receipt_schema": "4",
                "feed_status": "stale", "indicator_values": "withheld",
                "restore": "signed-and-healthy"}
    finally:
        _retire(restored)
        _retire(installed)
