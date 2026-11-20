"""Version boundary for persistent synthetic Core conversation history."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from apps.api.auth import LabSessions, migrate_legacy_history


class CoreHistorySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "history.db"

    def sessions(self) -> LabSessions:
        return LabSessions(self.path.parent / "roles.json", "synthetic-password", self.path)

    def legacy(self, *, turns: str = "[]") -> None:
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute("""CREATE TABLE conversations (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL)""")
                db.execute("CREATE INDEX conversations_owner ON conversations(owner)")
                db.execute("INSERT INTO conversations VALUES (?,?,?)", ("old", "engineer", turns))
        self.path.chmod(0o600)

    def test_fresh_history_is_versioned_and_reopens(self) -> None:
        self.sessions()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))
        self.sessions()

    def test_legacy_requires_explicit_verified_migration(self) -> None:
        self.legacy()
        with self.assertRaisesRegex(ValueError, "schema version"):
            self.sessions()
        self.assertEqual(migrate_legacy_history(self.path), 1)
        self.assertEqual(self.sessions().conversation("old", "engineer").turns, [])
        with self.assertRaisesRegex(ValueError, "already versioned"):
            migrate_legacy_history(self.path)

    def test_corrupt_legacy_rows_and_future_version_refuse_start(self) -> None:
        self.legacy(turns='{"not":"turns"}')
        with self.assertRaisesRegex(ValueError, "legacy conversation turns"):
            migrate_legacy_history(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
            with db:
                db.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "schema version"):
            self.sessions()

    def test_unknown_history_shape_and_symlink_refuse_start(self) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY)")
                db.execute("PRAGMA user_version=1")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "shape"):
            self.sessions()
        self.path.unlink()
        self.path.symlink_to(self.path.parent / "roles.json")
        with self.assertRaises(OSError):
            self.sessions()
