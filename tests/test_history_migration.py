"""Encrypted, clean-restore gate before changing legacy Core history."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.history_migration import (
    HistoryMigrationError, migrate_history_with_backup,
)
from infrastructure.restic_repository import restore_snapshot


class HistoryMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.live = self.root / "live"
        self.staging = self.root / "staging"
        self.evidence_dir = self.root / "evidence"
        for directory in (self.live, self.staging, self.evidence_dir):
            directory.mkdir(mode=0o700)
        self.history = self.live / "history.db"
        with closing(sqlite3.connect(self.history)) as db:
            with db:
                db.execute("""CREATE TABLE conversations (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL)""")
                db.execute("CREATE INDEX conversations_owner ON conversations(owner)")
                db.execute("INSERT INTO conversations VALUES (?,?,?)",
                           ("old", "engineer", '[{"message":"fictional"}]'))
        self.history.chmod(0o600)
        self.password = self.root / "password"
        self.password.write_text(os.urandom(32).hex())
        self.password.chmod(0o600)
        self.repository = self.root / "repository"
        self.evidence = self.evidence_dir / "history-migration.json"
        self.restic = Path(os.environ.get("SOVEREIGN_TEST_RESTIC", "/nonexistent/restic"))
        self.restic_hash = (hashlib.sha256(self.restic.read_bytes()).hexdigest()
                            if self.restic.is_file() else "0" * 64)

    def migrate(self) -> dict[str, object]:
        return migrate_history_with_backup(
            self.history, self.repository, self.password, self.restic,
            self.restic_hash, self.staging, self.evidence)

    def test_mismatched_clean_restore_cannot_change_live_history(self) -> None:
        def wrong_restore(snapshot_id, repository, password, binary, digest, destination):
            destination.mkdir()
            restored = destination / "history.db"
            shutil.copyfile(self.history, restored)
            restored.chmod(0o600)
            with closing(sqlite3.connect(restored)) as db:
                with db:
                    db.execute("UPDATE conversations SET turns_json='[]'")
            return {"files": 1, "snapshot_id": snapshot_id}

        with patch("infrastructure.deploy.history_migration.create_snapshot",
                   return_value={"status": "snapshot-verified", "files": 1,
                                 "snapshot_id": "a" * 64}), \
             patch("infrastructure.deploy.history_migration.restore_snapshot",
                   side_effect=wrong_restore):
            with self.assertRaisesRegex(HistoryMigrationError, "differs"):
                self.migrate()
        with closing(sqlite3.connect(self.history)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
        self.assertFalse(self.evidence.exists())

    @unittest.skipUnless(os.environ.get("SOVEREIGN_TEST_RESTIC"),
                         "pinned restic integration binary not configured")
    def test_encrypted_backup_restores_legacy_before_migration(self) -> None:
        result = self.migrate()
        self.assertEqual(result["status"], "migration-complete")
        self.assertEqual(result["conversations"], 1)
        self.assertEqual(json.loads(self.evidence.read_text()), result)
        with closing(sqlite3.connect(self.history)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(db.execute("SELECT owner FROM conversations").fetchone(),
                             ("engineer",))
        destination = self.root / "clean-restore"
        restore_snapshot(result["snapshot_id"], self.repository, self.password,
                         self.restic, self.restic_hash, destination)
        with closing(sqlite3.connect(destination / "history.db")) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
            self.assertEqual(db.execute("SELECT owner FROM conversations").fetchone(),
                             ("engineer",))
        with self.assertRaises(ValueError):
            self.migrate()
