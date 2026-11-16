from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from infrastructure.deploy.backup_service import (
    BackupServiceError, render_backup_units, write_backup_units,
)


class BackupServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.values = (Path("/srv/sovereign/spec.json"),
                       Path("/srv/sovereign/repository"),
                       Path("/etc/sovereign/backup-password"),
                       Path("/usr/local/bin/restic"), "a" * 64,
                       Path("/usr/bin/python3"), Path("/opt/sovereign"),
                       Path("/srv/sovereign/staging"), 2, 24)

    def test_renders_isolated_daily_backup_then_full_verification(self) -> None:
        service, timer = render_backup_units(*self.values)
        self.assertIn("User=sovereign-backup", service)
        self.assertIn("PrivateNetwork=yes", service)
        self.assertIn("LoadCredential=restic-password:/etc/sovereign/backup-password", service)
        self.assertIn("${CREDENTIALS_DIRECTORY}/restic-password", service)
        self.assertLess(service.index("restic_repository create"),
                        service.index("restic_repository verify"))
        self.assertIn("--max-age-hours 24", service)
        self.assertIn("OnCalendar=*-*-* 02:00:00 UTC", timer)
        self.assertIn("Persistent=true", timer)
        service_output = self.root / "sovereign-backup.service"
        timer_output = self.root / "sovereign-backup.timer"
        write_backup_units(service_output, timer_output, *self.values)
        self.assertEqual(service_output.read_text(), service)
        self.assertEqual(timer_output.read_text(), timer)
        self.assertEqual(service_output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(BackupServiceError):
            write_backup_units(service_output, self.root / "another.timer", *self.values)
        self.assertFalse((self.root / "another.timer").exists())

    def test_rejects_ambiguous_paths_digest_and_schedule(self) -> None:
        cases = [
            {0: Path("/srv/sovereign/spec with space.json")},
            {2: Path("/srv/sovereign/repository/password")},
            {3: Path("/usr/local/bin/restic\nExecStart=/bin/sh")},
            {4: "0" * 63},
            {8: 24},
            {9: 0},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                arguments = list(self.values)
                for index, value in changes.items():
                    arguments[index] = value
                with self.assertRaises(BackupServiceError):
                    render_backup_units(*arguments)


if __name__ == "__main__":
    unittest.main()
