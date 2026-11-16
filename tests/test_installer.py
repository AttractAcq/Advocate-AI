import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.installer import InstallError, install, postcheck, rollback, status, validate_config
from infrastructure.release.bundle import BundleError, create_bundle

ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        (self.payload / "core.txt").write_text("fictional release one")
        self.private = self.root / "signer.pem"
        self.trusted = self.root / "trusted.pem"
        key = Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.trusted.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle1"
        create_bundle(self.payload, self.bundle, self.private, "0.1.0")
        self.config = self.root / "config.json"
        self.config.write_bytes((ROOT / "infrastructure/deploy/lab-config.json").read_bytes())
        self.install_root = self.root / "install"

    def test_install_is_idempotent_and_rollback_rechecks_release(self) -> None:
        first = install(self.bundle, self.trusted, self.config, self.install_root)
        self.assertEqual(first["result"], "installed")
        self.assertEqual(install(self.bundle, self.trusted, self.config, self.install_root)["result"], "unchanged")
        self.assertEqual(status(self.install_root, self.trusted)["active"], first["active"])
        (self.payload / "core.txt").write_text("fictional release two")
        second_bundle = self.root / "bundle2"
        create_bundle(self.payload, second_bundle, self.private, "0.2.0")
        second = install(second_bundle, self.trusted, self.config, self.install_root)
        self.assertNotEqual(first["active"], second["active"])
        self.assertEqual(second["previous"], first["active"])
        rolled = rollback(self.install_root, self.trusted)
        self.assertEqual(rolled["active"], first["active"])
        self.assertEqual(status(self.install_root, self.trusted)["active"], first["active"])

    def test_invalid_config_or_bundle_never_activates(self) -> None:
        config = json.loads(self.config.read_text())
        for mutation in ({"bind": "0.0.0.0"}, {"public_egress": True},
                         {"token": "must not be accepted"}):
            with self.subTest(mutation=mutation):
                candidate = {**config, **mutation}
                with self.assertRaises(InstallError):
                    validate_config(candidate)
        self.config.write_text(json.dumps({**config, "public_egress": True}))
        with self.assertRaises(InstallError):
            install(self.bundle, self.trusted, self.config, self.install_root)
        self.assertFalse(self.install_root.exists())
        self.config.write_text(json.dumps(config))
        (self.bundle / "core.txt").write_text("tampered")
        with self.assertRaises(BundleError):
            install(self.bundle, self.trusted, self.config, self.install_root)
        self.assertFalse(self.install_root.exists())

    def test_corrupt_staged_release_blocks_status_and_reinstall(self) -> None:
        installed = install(self.bundle, self.trusted, self.config, self.install_root)
        staged = self.install_root / "releases" / installed["active"] / "bundle/core.txt"
        staged.write_text("tampered")
        with self.assertRaises(BundleError):
            status(self.install_root, self.trusted)
        with self.assertRaises(BundleError):
            install(self.bundle, self.trusted, self.config, self.install_root)

    def test_postcheck_requires_all_staged_ports(self) -> None:
        install(self.bundle, self.trusted, self.config, self.install_root)
        config = json.loads(self.config.read_text())
        health = self.root / "health.json"
        checks = [{"name": name.replace("-", "_"), "kind": "https",
                   "url": f"https://127.0.0.1:{port}/health", "ca_file": "ca.pem",
                   "expected_service": name} for name, port in config["services"].items()]
        health.write_text(json.dumps({"schema": 1, "mode": "synthetic-loopback",
                                      "allowed_cidrs": ["127.0.0.0/8"], "checks": checks}))
        with patch("infrastructure.deploy.installer.diagnose", return_value={"all_ok": True, "checks": []}):
            self.assertEqual(postcheck(self.install_root, self.trusted, health)["result"], "passed")
            checks.pop()
            health.write_text(json.dumps({"schema": 1, "mode": "synthetic-loopback",
                                          "allowed_cidrs": ["127.0.0.0/8"], "checks": checks}))
            with self.assertRaises(InstallError):
                postcheck(self.install_root, self.trusted, health)


if __name__ == "__main__":
    unittest.main()
