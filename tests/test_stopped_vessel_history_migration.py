"""Stopped vessel state and signed evidence around legacy history migration."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_history_migration import (
    VesselHistoryMigrationError, migrate_stopped_vessel_history,
    verify_vessel_history_migration_receipt,
)
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _state_payload, _write_state,
)
from infrastructure.restic_repository import restore_snapshot


class StoppedVesselHistoryMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.parent.chmod(0o700)
        self.root = self.parent / "installation"
        self.root.mkdir(mode=0o700)
        self.state = self.parent / "state"
        self.state.mkdir(mode=0o700)
        self.staging = self.parent / "staging"
        self.staging.mkdir(mode=0o700)
        self.out = self.parent / "out"
        self.out.mkdir(mode=0o700)
        self.active = "1" * 24
        self.installation = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle(
            "d" * 64, "sovereign-knowledge-" + "e" * 12 + "-socket",
            f"sovereign-{self.installation}-knowledge-data",
            "sovereign-knowledge-" + "e" * 12, self.installation)
        _write_state(self.root, _state_payload(
            self.active, self.installation, self.state,
            self.parent / "lab-password", services, knowledge))
        self.bundle = self.root / "vessel-releases" / self.active / "bundle"
        self.bundle.mkdir(parents=True, mode=0o700)
        (self.bundle / "release-manifest.json").write_text("signed fictional release")
        self.signing = self.parent / "signing.pem"
        self.trust = self.parent / "signing.pub"
        key = Ed25519PrivateKey.generate()
        self.signing.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.signing.chmod(0o600)
        self.trust.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.receipt = self.out / "migration-receipt.json"
        self.evidence = self.out / "migration-evidence.json"
        self.backup_password = self.parent / "backup-password"
        self.backup_password.write_text(os.urandom(32).hex())
        self.backup_password.chmod(0o600)
        self.restic = Path(os.environ.get("SOVEREIGN_TEST_RESTIC", "/nonexistent/restic"))
        self.restic_hash = (hashlib.sha256(self.restic.read_bytes()).hexdigest()
                            if self.restic.is_file() else "0" * 64)

    def migrate(self) -> dict[str, object]:
        return migrate_stopped_vessel_history(
            self.root, self.trust, self.parent / "crane", self.parent / "repository",
            self.backup_password, self.restic, self.restic_hash,
            self.staging, self.evidence, self.signing, self.receipt)

    def test_live_runtime_refused_before_backup_or_mutation(self) -> None:
        with patch("infrastructure.deploy.vessel_history_migration._verify_stage"), \
             patch("infrastructure.deploy.vessel_history_migration.verify_bundle",
                   return_value={"images": {"core": {}}}), \
             patch("infrastructure.deploy.vessel_history_migration._image_id"), \
             patch("infrastructure.deploy.vessel_history_migration._recovery_inventory",
                   side_effect=VesselInstallError("runtime still present")), \
             patch("infrastructure.deploy.vessel_history_migration.migrate_history_with_backup") as backup:
            with self.assertRaisesRegex(VesselInstallError, "runtime still present"):
                self.migrate()
            backup.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_active_core_archive_mismatch_refused_before_backup(self) -> None:
        with patch("infrastructure.deploy.vessel_history_migration._verify_stage"), \
             patch("infrastructure.deploy.vessel_history_migration.verify_bundle",
                   return_value={"images": {"core": {}}}), \
             patch("infrastructure.deploy.vessel_history_migration._image_id",
                   side_effect=ValueError("image identity mismatch")), \
             patch("infrastructure.deploy.vessel_history_migration.migrate_history_with_backup") as backup:
            with self.assertRaisesRegex(ValueError, "image identity mismatch"):
                self.migrate()
            backup.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_backup_evidence_cannot_enter_installation_root(self) -> None:
        self.evidence = self.root / "migration-evidence.json"
        with self.assertRaisesRegex(VesselHistoryMigrationError, "output paths are unsafe"):
            self.migrate()
        self.assertFalse(self.evidence.exists())

    def test_stopped_migration_receipt_binds_release_and_rejects_tamper(self) -> None:
        summary = {"status": "migration-complete", "snapshot_id": "2" * 64,
                   "repository": str(self.parent / "repository"),
                   "history_sha256": "3" * 64, "conversations": 1}
        with patch("infrastructure.deploy.vessel_history_migration._verify_stage"), \
             patch("infrastructure.deploy.vessel_history_migration.verify_bundle",
                   return_value={"images": {"core": {}}}), \
             patch("infrastructure.deploy.vessel_history_migration._image_id"), \
             patch("infrastructure.deploy.vessel_history_migration._recovery_inventory") as inventory, \
             patch("infrastructure.deploy.vessel_history_migration._state_options") as options, \
             patch("infrastructure.deploy.vessel_history_migration.policy_directory_lock"), \
             patch("infrastructure.deploy.vessel_history_migration.migrate_history_with_backup",
                   return_value=summary) as backup:
            result = self.migrate()
        self.assertEqual(result["installation_id"], self.installation)
        self.assertEqual(result["release"], self.active)
        self.assertEqual(result["snapshot_id"], summary["snapshot_id"])
        self.assertEqual(verify_vessel_history_migration_receipt(self.receipt,
                                                                  self.trust), result)
        self.assertEqual(inventory.call_count, 2)
        self.assertEqual(options.call_args_list[0].kwargs,
                         {"allow_legacy_history": True})
        self.assertEqual(options.call_args_list[1].kwargs, {})
        self.assertEqual(backup.call_count, 1)
        envelope = json.loads(self.receipt.read_text())
        envelope["signature"] = "A" * len(envelope["signature"])
        self.receipt.write_text(json.dumps(envelope))
        self.receipt.chmod(0o600)
        with self.assertRaises(VesselHistoryMigrationError):
            verify_vessel_history_migration_receipt(self.receipt, self.trust)

    @unittest.skipUnless(os.environ.get("SOVEREIGN_TEST_RESTIC"),
                         "pinned restic integration binary not configured")
    def test_encrypted_stopped_migration_and_signed_receipt(self) -> None:
        history = self.state / "history.db"
        with closing(sqlite3.connect(history)) as database:
            with database:
                database.execute("""CREATE TABLE conversations (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL)""")
                database.execute("CREATE INDEX conversations_owner ON conversations(owner)")
                database.execute("INSERT INTO conversations VALUES (?,?,?)",
                                 ("old", "engineer", '[{"message":"fictional"}]'))
        history.chmod(0o600)
        with patch("infrastructure.deploy.vessel_history_migration._verify_stage"), \
             patch("infrastructure.deploy.vessel_history_migration.verify_bundle",
                   return_value={"images": {"core": {}}}), \
             patch("infrastructure.deploy.vessel_history_migration._image_id"), \
             patch("infrastructure.deploy.vessel_history_migration._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_history_migration._state_options"), \
             patch("infrastructure.deploy.vessel_history_migration.policy_directory_lock"):
            result = self.migrate()
        self.assertEqual(verify_vessel_history_migration_receipt(self.receipt,
                                                                  self.trust), result)
        self.assertEqual(json.loads(self.evidence.read_text())["status"],
                         "migration-complete")
        with closing(sqlite3.connect(history)) as database:
            self.assertEqual(database.execute("PRAGMA user_version").fetchone(), (1,))
        destination = self.parent / "clean-restore"
        restore_snapshot(result["snapshot_id"], self.parent / "repository",
                         self.backup_password, self.restic, self.restic_hash,
                         destination)
        with closing(sqlite3.connect(destination / "history.db")) as database:
            self.assertEqual(database.execute("PRAGMA user_version").fetchone(), (0,))


if __name__ == "__main__":
    unittest.main()
