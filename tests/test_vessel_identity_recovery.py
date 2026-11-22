"""Reject mismatched identity and Core recovery artifacts before realm import."""

from __future__ import annotations

from datetime import datetime, timezone
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.backup import generate_key
from infrastructure.deploy.vessel_identity_recovery import (
    IdentityRecoveryError, create_identity_recovery_pair,
    restore_paired_realm,
)
from infrastructure.deploy.vessel_recovery_set import _sign_receipt
from scripts.phase3_vessel_keycloak_rehearsal import _backup_realm
from scripts.vesselctl import main as vesselctl


class IdentityRecoveryPairTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive_key = self.root / "archive.key"
        generate_key(self.archive_key)
        signing = Ed25519PrivateKey.generate()
        self.signing_key = self.root / "signing.pem"
        self.public_key = self.root / "public.pem"
        self.signing_key.write_bytes(signing.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.signing_key.chmod(0o600)
        self.public_key.write_bytes(signing.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        self.core_receipt = self.root / "core-receipt.json"
        self._core_receipt("c" * 64, self.core_receipt)
        self.realm = self.root / "sovereign-realm.json"
        self.realm.write_text(json.dumps({"realm": "sovereign", "users": [
            {"username": "synthetic-engineer"}]}))
        self.archive = self.root / "current.svbk"
        self.digest = _backup_realm(self.realm, self.root, self.archive,
                                    self.archive_key)
        self.pair = self.root / "pair.json"

    def _core_receipt(self, snapshot: str, destination: Path) -> None:
        identifier = "a" * 32
        _sign_receipt(destination, {
            "schema": 3, "installation_id": identifier,
            "release": "b" * 24,
            "data_volume": f"sovereign-{identifier}-knowledge-data",
            "snapshot_id": snapshot, "repository": str(self.root / "repository"),
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "schema_version": 1, "audit_count": 1,
            "audit_tail_hash": "d" * 64,
            "manifest_sha256": "e" * 64, "dump_sha256": "f" * 64,
            "knowledge_sha256": "1" * 64, "sources": 2,
            "passages": 2, "files": 9,
            "identity": {
                "issuer": "https://identity.vessel.example/realms/sovereign",
                "ca_sha256": "2" * 64,
                "revocations_sha256": "3" * 64,
            },
        }, self.signing_key)

    def _pair(self) -> None:
        create_identity_recovery_pair(
            self.core_receipt, self.public_key, self.archive,
            self.archive_key, self.digest, self.signing_key, self.pair)

    def test_exact_pair_restores_one_realm(self) -> None:
        self._pair()
        restored = self.root / "restored"
        result = restore_paired_realm(
            self.pair, self.public_key, self.core_receipt, self.public_key,
            self.archive, self.archive_key, restored)
        self.assertEqual(result["result"], "paired-realm-restored")
        self.assertEqual((restored / "sovereign-realm.json").read_bytes(),
                         self.realm.read_bytes())

    def test_operator_commands_pair_and_restore(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            vesselctl([
                "pair-identity-recovery", "--core-receipt", str(self.core_receipt),
                "--core-receipt-key", str(self.public_key), "--archive",
                str(self.archive), "--archive-key", str(self.archive_key),
                "--archive-checkpoint", self.digest, "--signing-key",
                str(self.signing_key), "--output", str(self.pair),
            ])
        self.assertEqual(json.loads(output.getvalue())["schema"], 1)
        output = io.StringIO()
        with redirect_stdout(output):
            vesselctl([
                "restore-paired-identity", "--pair", str(self.pair),
                "--pair-key", str(self.public_key), "--core-receipt",
                str(self.core_receipt), "--core-receipt-key",
                str(self.public_key), "--archive", str(self.archive),
                "--archive-key", str(self.archive_key), "--destination",
                str(self.root / "cli-restored"),
            ])
        self.assertEqual(json.loads(output.getvalue())["result"],
                         "paired-realm-restored")

    def test_stale_archive_and_swapped_core_receipt_are_denied(self) -> None:
        with self.assertRaises(IdentityRecoveryError):
            create_identity_recovery_pair(
                self.core_receipt, self.public_key, self.archive,
                self.archive_key, "0" * 64, self.signing_key, self.pair)
        self.assertFalse(self.pair.exists())
        self._pair()
        self.realm.write_text(json.dumps({"realm": "sovereign", "users": [
            {"username": "synthetic-deckhand"}]}))
        stale = self.root / "stale.svbk"
        _backup_realm(self.realm, self.root, stale, self.archive_key)
        with self.assertRaises(IdentityRecoveryError):
            restore_paired_realm(self.pair, self.public_key, self.core_receipt,
                                 self.public_key, stale, self.archive_key,
                                 self.root / "stale-restore")
        other = self.root / "other-core.json"
        self._core_receipt("4" * 64, other)
        with self.assertRaises(IdentityRecoveryError):
            restore_paired_realm(self.pair, self.public_key, other,
                                 self.public_key, self.archive, self.archive_key,
                                 self.root / "swapped-restore")
        self.assertFalse((self.root / "stale-restore").exists())
        self.assertFalse((self.root / "swapped-restore").exists())

    def test_tampered_pair_and_preexisting_destination_are_denied(self) -> None:
        self._pair()
        changed = self.root / "changed-pair.json"
        payload = bytearray(self.pair.read_bytes())
        payload[len(payload) // 2] ^= 1
        changed.write_bytes(payload)
        changed.chmod(0o600)
        with self.assertRaises(IdentityRecoveryError):
            restore_paired_realm(changed, self.public_key, self.core_receipt,
                                 self.public_key, self.archive, self.archive_key,
                                 self.root / "tampered-restore")
        existing = self.root / "existing"
        existing.mkdir()
        (existing / "keep.txt").write_text("do not remove")
        with self.assertRaises(IdentityRecoveryError):
            restore_paired_realm(self.pair, self.public_key, self.core_receipt,
                                 self.public_key, self.archive, self.archive_key,
                                 existing)
        self.assertEqual((existing / "keep.txt").read_text(), "do not remove")

    def test_oversized_realm_export_is_denied_before_json_parse(self) -> None:
        self.realm.write_bytes(b" " * (32 * 1024 * 1024 + 1))
        oversized = self.root / "oversized.svbk"
        digest = _backup_realm(self.realm, self.root, oversized, self.archive_key)
        with self.assertRaisesRegex(IdentityRecoveryError, "too large"):
            create_identity_recovery_pair(
                self.core_receipt, self.public_key, oversized,
                self.archive_key, digest, self.signing_key, self.pair)
        self.assertFalse(self.pair.exists())


if __name__ == "__main__":
    unittest.main()
