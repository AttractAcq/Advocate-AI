import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from infrastructure.backup import BackupError, create_backup, generate_key, inspect_backup


class BackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.live = self.root / "live"
        self.live.mkdir()
        self.key = self.root / "backup.key"
        generate_key(self.key)
        self.db = self.live / "history.db"
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE history (message TEXT)")
            connection.execute("INSERT INTO history VALUES ('fictional secret phrase')")
        (self.live / "config.json").write_text('{"mode":"synthetic"}')
        self.spec = self.root / "spec.json"
        self.spec.write_text(json.dumps({"schema": 1, "files": [
            {"name": "history.db", "kind": "sqlite", "source": "live/history.db"},
            {"name": "config/config.json", "kind": "file", "source": "live/config.json"},
        ]}))
        self.backup = self.root / "copy.svb"
        self.restored = self.root / "restored"

    def test_encrypted_round_trip_and_clean_restore(self) -> None:
        manifest = create_backup(self.spec, self.backup, self.key)
        self.assertEqual(len(manifest["files"]), 2)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"fictional secret phrase", self.backup.read_bytes())
        self.assertEqual(len(inspect_backup(self.backup, self.key)["files"]), 2)
        inspect_backup(self.backup, self.key, self.restored)
        with sqlite3.connect(self.restored / "history.db") as connection:
            self.assertEqual(connection.execute("SELECT message FROM history").fetchone()[0],
                             "fictional secret phrase")
        self.assertEqual((self.restored / "config/config.json").read_text(), '{"mode":"synthetic"}')
        with self.assertRaises(BackupError):
            inspect_backup(self.backup, self.key, self.restored)

    def test_tamper_and_wrong_key_fail_without_destination(self) -> None:
        create_backup(self.spec, self.backup, self.key)
        wrong = self.root / "wrong.key"
        generate_key(wrong)
        with self.assertRaisesRegex(BackupError, "authentication failed"):
            inspect_backup(self.backup, wrong, self.restored)
        self.assertFalse(self.restored.exists())
        with self.backup.open("r+b") as stream:
            stream.seek(30)
            old = stream.read(1)
            stream.seek(30)
            stream.write(bytes([old[0] ^ 1]))
        with self.assertRaisesRegex(BackupError, "authentication failed"):
            inspect_backup(self.backup, self.key, self.restored)
        self.assertFalse(self.restored.exists())

    def test_duplicate_path_symlink_and_key_entry_rejected(self) -> None:
        spec = json.loads(self.spec.read_text())
        spec["files"].append(spec["files"][0])
        self.spec.write_text(json.dumps(spec))
        with self.assertRaises(BackupError):
            create_backup(self.spec, self.backup, self.key)
        self.assertFalse(self.backup.exists())
        spec["files"] = [{"name": "../escape", "kind": "file", "source": "live/config.json"}]
        self.spec.write_text(json.dumps(spec))
        with self.assertRaises(BackupError):
            create_backup(self.spec, self.backup, self.key)
        spec["files"] = [{"name": "copy.key", "kind": "file", "source": "backup.key"}]
        self.spec.write_text(json.dumps(spec))
        with self.assertRaises(BackupError):
            create_backup(self.spec, self.backup, self.key)
        (self.live / "link.txt").symlink_to(self.live / "config.json")
        spec["files"] = [{"name": "link.txt", "kind": "file", "source": "live/link.txt"}]
        self.spec.write_text(json.dumps(spec))
        with self.assertRaises(BackupError):
            create_backup(self.spec, self.backup, self.key)

    def test_live_wal_database_is_snapshotted_consistently(self) -> None:
        with sqlite3.connect(self.db) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO history VALUES ('second row')")
        create_backup(self.spec, self.backup, self.key)
        inspect_backup(self.backup, self.key, self.restored)
        with sqlite3.connect(self.restored / "history.db") as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM history").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
