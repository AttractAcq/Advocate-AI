"""Stage two fictional signed releases, roll back, and probe the running lab."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.installer import install, postcheck, rollback, status
from infrastructure.release.bundle import create_bundle
from scripts.diagnose import lab_config

ROOT = Path(__file__).resolve().parents[1]


def rehearse() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="sovereign-install-") as temporary:
        root = Path(temporary)
        payload = root / "payload"
        payload.mkdir()
        (payload / "core.txt").write_text("fictional release one")
        signer = root / "signer.pem"
        trusted = root / "trusted.pem"
        key = Ed25519PrivateKey.generate()
        descriptor = os.open(signer, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        trusted.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        bundle1 = root / "bundle1"
        create_bundle(payload, bundle1, signer, "0.1.0")
        config = ROOT / "infrastructure/deploy/lab-config.json"
        installation = root / "installation"
        first = install(bundle1, trusted, config, installation)
        repeat = install(bundle1, trusted, config, installation)
        (payload / "core.txt").write_text("fictional release two")
        bundle2 = root / "bundle2"
        create_bundle(payload, bundle2, signer, "0.2.0")
        second = install(bundle2, trusted, config, installation)
        rolled = rollback(installation, trusted)
        health_path = root / "health.json"
        health_path.write_text(json.dumps(lab_config()))
        checked = postcheck(installation, trusted, health_path)
        verified = status(installation, trusted)
        ok = (first["result"] == "installed" and repeat["result"] == "unchanged"
              and second["active"] != first["active"]
              and rolled["active"] == first["active"]
              and verified["active"] == first["active"]
              and checked["result"] == "passed"
              and len(checked["health"]["checks"]) == 6)
        if not ok:
            raise RuntimeError("synthetic installation rehearsal failed")
        return {"schema": 1, "mode": "synthetic-loopback", "result": "pass",
                "signed_bundle_verified": True, "idempotent_reinstall": True,
                "rollback_verified": True, "health_checks_passed": 6,
                "limitations": "Staged fictional files only; no service install, PKI provisioning, firewall change, reboot, offline media or target-host validation"}


if __name__ == "__main__":
    print(json.dumps(rehearse(), indent=2, sort_keys=True))
