"""Boundary checks for the stopped vessel's paired recovery receipt."""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.vessel_recovery_set import (
    VesselRecoveryError, _stage_core, _sign_receipt, verify_vessel_recovery_receipt,
)
from scripts.synthetic_pg_fixture import fixture, put
from services.policy.audit import AuditLog


class VesselRecoverySetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        fixture(self.state)
        AuditLog(self.state / "audit.jsonl").append(
            actor="engineer", action="read", resource="synthetic",
            decision="allow", policy_version="1")
        with closing(sqlite3.connect(self.state / "history.db")) as database:
            database.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY)")
            database.execute("INSERT INTO conversations VALUES ('synthetic')")
            database.commit()
        (self.state / "history.db").chmod(0o600)

    def test_freezes_full_private_core_inventory(self) -> None:
        frozen = self.root / "frozen"
        count, checkpoint, digest = _stage_core(self.state, frozen)
        self.assertEqual(count, 2)
        self.assertEqual(checkpoint[0], 1)
        self.assertEqual(len(digest), 64)
        self.assertEqual((frozen / "sources/ENG-001.txt").read_bytes(),
                         (self.state / "sources/ENG-001.txt").read_bytes())
        with closing(sqlite3.connect(frozen / "history.db")) as database:
            self.assertEqual(database.execute("SELECT id FROM conversations").fetchone(),
                             ("synthetic",))

    def test_unlisted_source_denies_capture(self) -> None:
        put(self.state / "sources/unlisted.txt", b"secret")
        with self.assertRaisesRegex(VesselRecoveryError, "inventory"):
            _stage_core(self.state, self.root / "frozen")

    def test_signed_receipt_rejects_tampering(self) -> None:
        key = Ed25519PrivateKey.generate()
        private = self.root / "private.pem"
        public = self.root / "public.pem"
        put(private, key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        put(public, key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        receipt = self.root / "receipt.json"
        identifier = "a" * 32
        payload = {
            "schema": 1, "installation_id": identifier, "release": "b" * 24,
            "data_volume": f"sovereign-{identifier}-knowledge-data",
            "snapshot_id": "c" * 64, "repository": str(self.root / "repository"),
            "created_utc": "2026-11-20T12:00:00+00:00", "schema_version": 1,
            "audit_count": 1, "audit_tail_hash": "d" * 64,
            "manifest_sha256": "e" * 64, "dump_sha256": "f" * 64,
            "sources": 2, "passages": 2, "files": 7,
        }
        _sign_receipt(receipt, payload, private)
        self.assertEqual(verify_vessel_recovery_receipt(receipt, public), payload)
        envelope = json.loads(receipt.read_text())
        envelope["signature"] = "A" * len(envelope["signature"])
        receipt.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(VesselRecoveryError, "verification failed"):
            verify_vessel_recovery_receipt(receipt, public)


if __name__ == "__main__":
    unittest.main()
