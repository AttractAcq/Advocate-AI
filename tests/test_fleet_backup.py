"""Fleet encrypted recovery excludes credentials and verifies catalog audit."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infrastructure.backup import BackupError, generate_key, inspect_backup
from infrastructure.deploy.fleet_backup import (
    FleetBackupError, backup_fleet, restore_fleet,
)
from infrastructure.deploy.fleet_installer import restore_install_fleet
from infrastructure.deploy.fleet_runtime import FleetRuntime
from services.fleet.catalog import Customer, FleetCatalog, FleetIntegrityError


class FleetBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.db = self.state / "fleet.db"
        self.catalog = FleetCatalog(self.db)
        self.catalog.add("customer", Customer(code="CUST-LAB1",
                                              category="owner_manager"))
        self.token = self.state / "token"
        self.token.write_text("synthetic-fleet-admin-token-0123456789\n")
        self.token.chmod(0o600)
        self.key = self.root / "backup.key"
        generate_key(self.key)
        self.archive = self.root / "fleet.svb"

    def test_encrypted_roundtrip_excludes_token_and_preserves_audit(self) -> None:
        result = backup_fleet(self.db, self.archive, self.key)
        self.assertEqual(result["files"], 1)
        manifest = inspect_backup(self.archive, self.key)
        self.assertEqual([item["name"] for item in manifest["files"]], ["fleet.db"])
        restored = self.root / "restored"
        restore_fleet(self.archive, self.key, restored)
        self.assertEqual(FleetCatalog(restored / "fleet.db").list("customer")[0]["code"],
                         "CUST-LAB1")
        self.assertFalse((restored / "token").exists())

    def test_low_archive_volume_space_rejects_before_snapshot(self) -> None:
        with patch("infrastructure.deploy.fleet_backup.os.statvfs",
                   return_value=SimpleNamespace(f_bavail=1, f_frsize=4096)):
            with self.assertRaisesRegex(FleetBackupError, "insufficient Fleet backup"):
                backup_fleet(self.db, self.archive, self.key)
        self.assertFalse(self.archive.exists())
        self.assertFalse(any(path.name.startswith(".fleet-backup-spec-") or
                             path.name.startswith(".svbk-snapshot-")
                             for path in self.root.iterdir()))

    def test_wrong_key_tamper_and_corrupt_catalog_fail_cleanly(self) -> None:
        backup_fleet(self.db, self.archive, self.key)
        wrong = self.root / "wrong.key"
        generate_key(wrong)
        destination = self.root / "wrong-restore"
        with self.assertRaises(BackupError):
            restore_fleet(self.archive, wrong, destination)
        self.assertFalse(destination.exists())
        data = bytearray(self.archive.read_bytes())
        data[-20] ^= 0x01
        self.archive.write_bytes(data)
        with self.assertRaises(BackupError):
            restore_fleet(self.archive, self.key, destination)
        self.assertFalse(destination.exists())
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE records SET payload=? WHERE kind='customer'",
                               ('{"code":"CUST-LAB1","category":"service_partner"}',))
        with self.assertRaises(FleetIntegrityError):
            backup_fleet(self.db, self.root / "corrupt.svb", self.key)
        self.assertFalse((self.root / "corrupt.svb").exists())

    def test_clean_restore_precedes_signed_runtime(self) -> None:
        backup_fleet(self.db, self.archive, self.key)
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / "release-manifest.json").write_text("synthetic-bundle")
        config = self.root / "fleet-config.json"
        config.write_text('{"schema":1,"oidc_issuer":null}\n')
        destination = self.root / "new-install"
        with patch("infrastructure.deploy.fleet_installer.verify_bundle",
                   return_value={"schema": 5, "target": "fleet"}), \
             patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                   return_value=FleetRuntime("a" * 64, "b" * 64, "c" * 64)):
            result = restore_install_fleet(bundle, self.root / "trust.pem",
                                           self.root / "crane", config, destination,
                                           self.token, self.archive, self.key)
        self.assertEqual(result["restored_files"], 1)
        self.assertEqual(FleetCatalog(destination / "state" / "fleet.db")
                         .list("customer")[0]["code"], "CUST-LAB1")
        self.assertEqual((destination / "state" / "token").read_bytes(),
                         self.token.read_bytes())


if __name__ == "__main__":
    unittest.main()
