from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.phase5_postgres_rehearsal import _dump, _restore, rehearse


class PostgresRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_rejects_tag_without_exact_digest_before_docker(self) -> None:
        with patch("scripts.phase5_postgres_rehearsal._docker") as docker:
            with self.assertRaises(ValueError):
                rehearse("postgres:18-alpine", self.root / "restic", "0" * 64)
            docker.assert_not_called()

    def test_failed_dump_leaves_no_partial_archive(self) -> None:
        output = self.root / "postgres.dump"

        def fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
            kwargs["stdout"].write(b"partial")
            return subprocess.CompletedProcess(args[0], 1, b"", b"synthetic failure")

        with patch("scripts.phase5_postgres_rehearsal.subprocess.run", side_effect=fail):
            with self.assertRaises(RuntimeError):
                _dump("synthetic-container", output)
        self.assertFalse(output.exists())

    def test_refuses_restore_to_database_with_existing_tables(self) -> None:
        archive = self.root / "postgres.dump"
        archive.write_bytes(b"PGDMPtest")
        with patch("scripts.phase5_postgres_rehearsal._sql", return_value="1"), \
             patch("scripts.phase5_postgres_rehearsal.subprocess.run") as run:
            with self.assertRaises(RuntimeError):
                _restore("synthetic-container", archive)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
