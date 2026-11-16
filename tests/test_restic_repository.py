from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from infrastructure.restic_repository import ResticError, create_snapshot, restore_snapshot


class ResticRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        binary = os.environ.get("SOVEREIGN_TEST_RESTIC")
        if not binary:
            self.skipTest("pinned restic integration binary not configured")
        self.restic = Path(binary)
        self.restic_sha256 = hashlib.sha256(self.restic.read_bytes()).hexdigest()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.password = self.root / "password"
        self.password.write_text(os.urandom(32).hex())
        self.password.chmod(0o600)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        self.live = self.root / "live"
        self.live.mkdir()
        (self.live / "config.json").write_text('{"fictional":true}\n')
        self.database = self.live / "knowledge.db"
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE records (value TEXT)")
            connection.execute("INSERT INTO records VALUES ('fictional entry')")
            connection.commit()
        self.spec = self.root / "spec.json"
        self.spec.write_text(json.dumps({"schema": 1, "files": [
            {"name": "config.json", "kind": "file", "source": "live/config.json"},
            {"name": "knowledge.db", "kind": "sqlite", "source": "live/knowledge.db"},
        ]}))
        self.repository = self.root / "repository"

    def test_consistent_snapshot_full_check_and_clean_restore(self) -> None:
        created = create_snapshot(self.spec, self.repository, self.password,
                                  self.restic, self.restic_sha256, self.staging)
        self.assertEqual(created["status"], "snapshot-verified")
        self.assertEqual(created["files"], 2)
        self.assertEqual(list(self.staging.iterdir()), [])
        (self.live / "config.json").write_text("changed")
        restored = self.root / "restored"
        result = restore_snapshot(created["snapshot_id"], self.repository, self.password,
                                  self.restic, self.restic_sha256, restored)
        self.assertEqual(result["status"], "restored")
        self.assertEqual((restored / "config.json").read_text(), '{"fictional":true}\n')
        with sqlite3.connect(restored / "knowledge.db") as connection:
            self.assertEqual(connection.execute("SELECT value FROM records").fetchone(),
                             ("fictional entry",))

    def test_wrong_key_or_unapproved_binary_rejected_without_restore(self) -> None:
        created = create_snapshot(self.spec, self.repository, self.password,
                                  self.restic, self.restic_sha256, self.staging)
        destination = self.root / "denied"
        wrong = self.root / "wrong-password"
        wrong.write_text(os.urandom(32).hex())
        wrong.chmod(0o600)
        with self.assertRaises(ResticError):
            restore_snapshot(created["snapshot_id"], self.repository, wrong,
                             self.restic, self.restic_sha256, destination)
        self.assertFalse(destination.exists())
        with self.assertRaises(ResticError):
            restore_snapshot(created["snapshot_id"], self.repository, self.password,
                             self.restic, "0" * 64, destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
