from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from infrastructure.restic_repository import ResticError, create_snapshot, restore_snapshot
from infrastructure.restic_retention import apply_plan, create_plan


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

    def test_retention_plan_applies_only_exact_sovereign_snapshots(self) -> None:
        ids = []
        for number in range(3):
            (self.live / "config.json").write_text(json.dumps({"revision": number}))
            created = create_snapshot(self.spec, self.repository, self.password,
                                      self.restic, self.restic_sha256, self.staging)
            ids.append(created["snapshot_id"])
        foreign = self.root / "foreign.txt"
        foreign.write_text("separate repository content")
        subprocess.run([str(self.restic), "--no-cache", "-r", str(self.repository),
                        "--password-file", str(self.password), "backup", str(foreign),
                        "--tag", "unrelated", "--host", "other-host"],
                       check=True, capture_output=True, timeout=60)
        policy = self.root / "policy.json"
        policy.write_text('{"schema":1,"keep_last":2,"keep_within_days":null}')
        plan_path = self.root / "plan.json"
        preview = create_plan(policy, self.repository, self.password,
                              self.restic, self.restic_sha256, plan_path)
        plan = json.loads(plan_path.read_text())
        self.assertEqual(preview["remove"], 1)
        self.assertEqual(plan["remove_ids"], [ids[0]])
        with self.assertRaises(ResticError):
            apply_plan(plan_path, "0" * 64, self.repository, self.password,
                       self.restic, self.restic_sha256)
        result = apply_plan(plan_path, preview["plan_sha256"], self.repository,
                            self.password, self.restic, self.restic_sha256)
        self.assertEqual(result, {"status": "applied", "removed": 1, "kept": 2})
        all_rows = json.loads(subprocess.run(
            [str(self.restic), "--no-cache", "-r", str(self.repository),
             "--password-file", str(self.password), "snapshots", "--json"],
            check=True, capture_output=True, text=True, timeout=60).stdout)
        self.assertEqual(len(all_rows), 3)
        self.assertIn(ids[-1], [row["id"] for row in all_rows])
        self.assertIn("unrelated", [tag for row in all_rows for tag in row.get("tags", [])])

    def test_retention_plan_rejects_changed_repository(self) -> None:
        for number in range(3):
            (self.live / "config.json").write_text(json.dumps({"revision": number}))
            create_snapshot(self.spec, self.repository, self.password,
                            self.restic, self.restic_sha256, self.staging)
        policy = self.root / "policy.json"
        policy.write_text('{"schema":1,"keep_last":2,"keep_within_days":null}')
        plan_path = self.root / "plan.json"
        preview = create_plan(policy, self.repository, self.password,
                              self.restic, self.restic_sha256, plan_path)
        (self.live / "config.json").write_text('{"revision":3}')
        create_snapshot(self.spec, self.repository, self.password,
                        self.restic, self.restic_sha256, self.staging)
        with self.assertRaises(ResticError):
            apply_plan(plan_path, preview["plan_sha256"], self.repository,
                       self.password, self.restic, self.restic_sha256)


if __name__ == "__main__":
    unittest.main()
