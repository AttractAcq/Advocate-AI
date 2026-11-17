from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.backup import BackupError, generate_key
from infrastructure.deploy.fleet_backup_service import (
    FleetScheduleError, create_scheduled, render_fleet_backup_units,
    verify_latest, write_fleet_backup_units,
)
from services.fleet.catalog import Customer, FleetCatalog


class FleetBackupServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.db = self.state / "fleet.db"
        FleetCatalog(self.db).add("customer", Customer(code="CUST-LAB1",
                                                       category="owner_manager"))
        self.key = self.root / "key"
        generate_key(self.key)
        self.archives = self.root / "archives"
        self.archives.mkdir(mode=0o700)

    def test_daily_archive_clean_restore_and_capacity_stop(self) -> None:
        created = create_scheduled(self.db, self.archives, self.key, 1)
        self.assertEqual(created["files"], 1)
        checked = verify_latest(self.archives, self.key, 24, 1)
        self.assertEqual(checked["clean_restore"], "verified")
        self.assertEqual(checked["archive_count"], 1)
        self.assertEqual(list(self.archives.iterdir()), [Path(created["archive"])])
        with self.assertRaisesRegex(FleetScheduleError, "capacity reached"):
            create_scheduled(self.db, self.archives, self.key, 1)

    def test_missing_tampered_and_stale_archive_fail(self) -> None:
        with self.assertRaisesRegex(FleetScheduleError, "no Fleet backup"):
            verify_latest(self.archives, self.key, 24, 2)
        archive = Path(create_scheduled(self.db, self.archives, self.key, 2)["archive"])

        class Later(datetime):
            @classmethod
            def now(cls, tz: timezone | None = None) -> datetime:
                return datetime.now(tz) + timedelta(hours=2)

        with patch("infrastructure.deploy.fleet_backup_service.datetime", Later):
            with self.assertRaisesRegex(FleetScheduleError, "freshness limit"):
                verify_latest(self.archives, self.key, 1, 2)
        data = bytearray(archive.read_bytes())
        data[-20] ^= 1
        archive.write_bytes(data)
        with self.assertRaises(BackupError):
            verify_latest(self.archives, self.key, 24, 2)
        self.assertEqual(list(self.archives.iterdir()), [archive])

    def test_timer_is_private_and_rejects_unsafe_paths(self) -> None:
        values = (Path("/srv/fleet/state/fleet.db"), Path("/srv/fleet/backups"),
                  Path("/etc/fleet/backup-key"), Path("/usr/bin/python3"),
                  Path("/opt/sovereign"), 3, 24, 30)
        service, timer = render_fleet_backup_units(*values)
        self.assertIn("PrivateNetwork=yes", service)
        self.assertIn("LoadCredential=fleet-backup-key:/etc/fleet/backup-key", service)
        self.assertIn("ReadWritePaths=/srv/fleet/backups", service)
        self.assertLess(service.index("fleet_backup_service create"),
                        service.index("fleet_backup_service verify"))
        self.assertIn("OnCalendar=*-*-* 03:00:00 UTC", timer)
        self.assertIn("User=sovereign-fleet", service)
        first = self.root / "sovereign-fleet-backup.service"
        second = self.root / "sovereign-fleet-backup.timer"
        write_fleet_backup_units(first, second, *values)
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        self.assertEqual(second.read_text(), timer)
        with self.assertRaises(FleetScheduleError):
            render_fleet_backup_units(*values[:1], Path("/srv/fleet/state"),
                                      *values[2:])


if __name__ == "__main__":
    unittest.main()
