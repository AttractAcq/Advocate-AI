"""Synthetic offline receipt issuer and Fleet importer interoperability."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.fleet.offline_import import SignedDeploymentReceipt, verify_signed_receipt
from services.fleet.offline_issue import issue_receipt


class OfflineIssueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.record = self.root / "record.json"
        self.record.write_text(json.dumps({
            "code": "RCP-LAB01", "vessel_code": "VSL-LAB01",
            "release_code": "REL-LAB01", "source": "approved_offline_admin",
            "observed_on": "2026-11-19", "health": "healthy"}))
        self.record.chmod(0o600)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "issuer-private.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.output = self.root / "envelope.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signs_importable_envelope_without_overwrite(self) -> None:
        result = issue_receipt(self.record, self.key_path, self.output)
        envelope = SignedDeploymentReceipt.model_validate_json(
            self.output.read_bytes())
        self.assertEqual(result["key_id"], envelope.key_id)
        self.assertEqual(verify_signed_receipt(envelope, self.key.public_key()).code,
                         "RCP-LAB01")
        self.assertEqual(self.output.stat().st_mode & 0o077, 0)
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)

    def test_rejects_forbidden_and_duplicate_fields_before_signing(self) -> None:
        original = self.record.read_text()
        self.record.write_text(original[:-1] + ',"document":"private"}')
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.assertFalse(self.output.exists())
        self.record.write_text(original[:-1] + ',"health":"degraded"}')
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_weak_key_and_linked_record(self) -> None:
        self.key_path.chmod(0o644)
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.key_path.chmod(0o600)
        alias = self.root / "linked-record.json"
        alias.symlink_to(self.record)
        with self.assertRaises(OSError):
            issue_receipt(alias, self.key_path, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
