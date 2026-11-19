from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.backup import BackupError, generate_key
from infrastructure.deploy.fleet_backup_service import create_scheduled
from infrastructure.deploy.fleet_backup_retention import (
    FleetRetentionError, apply_retention, plan_retention,
)
from infrastructure.deploy.fleet_backup import restore_fleet
from services.fleet.catalog import Customer, FleetCatalog


class FleetBackupRetentionTests(unittest.TestCase):
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
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": 1, "keep_last": 2,
                                           "max_age_hours": 24}))
        self.policy.chmod(0o600)
        self.plan = self.root / "plan.json"
        self.created = [Path(create_scheduled(self.db, self.archives, self.key, 5)["archive"])
                        for _ in range(3)]

    def test_plan_and_apply_clean_restore_exact_retention(self) -> None:
        preview = plan_retention(self.archives, self.policy, self.plan)
        self.assertEqual(preview["remove"], [self.created[0].name])
        self.assertEqual(preview["retain"], [p.name for p in self.created[1:]])
        self.assertEqual(self.plan.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.created[0].exists())
        result = apply_retention(self.archives, self.policy, self.plan,
                                 str(preview["plan_sha256"]), self.key)
        self.assertEqual(result["clean_restore"], "verified")
        self.assertFalse(self.created[0].exists())
        self.assertTrue(all(path.exists() for path in self.created[1:]))

    def test_changed_inventory_policy_or_plan_denies_deletion(self) -> None:
        preview = plan_retention(self.archives, self.policy, self.plan)
        self.created[0].write_bytes(self.created[0].read_bytes() + b"tampered")
        with self.assertRaisesRegex(FleetRetentionError, "inventory changed"):
            apply_retention(self.archives, self.policy, self.plan,
                            str(preview["plan_sha256"]), self.key)
        self.assertTrue(all(path.exists() for path in self.created))

        self.created[0].write_bytes(self.created[0].read_bytes()[:-8])
        self.policy.write_text(json.dumps({"schema": 1, "keep_last": 3,
                                           "max_age_hours": 24}))
        with self.assertRaisesRegex(FleetRetentionError, "policy or directory changed"):
            apply_retention(self.archives, self.policy, self.plan,
                            str(preview["plan_sha256"]), self.key)
        self.assertTrue(all(path.exists() for path in self.created))

        self.plan.write_text(self.plan.read_text() + " ")
        with self.assertRaisesRegex(FleetRetentionError, "plan mismatch"):
            apply_retention(self.archives, self.policy, self.plan,
                            str(preview["plan_sha256"]), self.key)

    def test_bad_retained_archive_denies_deletion(self) -> None:
        self.created[-1].write_bytes(self.created[-1].read_bytes() + b"tampered")
        preview = plan_retention(self.archives, self.policy, self.plan)
        with self.assertRaises(BackupError):
            apply_retention(self.archives, self.policy, self.plan,
                            str(preview["plan_sha256"]), self.key)
        self.assertTrue(all(path.exists() for path in self.created))

    def test_policy_requires_two_retained_archives(self) -> None:
        self.policy.write_text(json.dumps({"schema": 1, "keep_last": 1,
                                           "max_age_hours": 24}))
        with self.assertRaisesRegex(FleetRetentionError, "invalid Fleet retention policy"):
            plan_retention(self.archives, self.policy, self.plan)

    def test_policy_change_during_restore_denies_deletion(self) -> None:
        preview = plan_retention(self.archives, self.policy, self.plan)

        def changed_policy(*args: object) -> dict[str, object]:
            result = restore_fleet(*args)
            self.policy.write_text(json.dumps({"schema": 1, "keep_last": 3,
                                               "max_age_hours": 24}))
            return result

        with patch("infrastructure.deploy.fleet_backup_retention.restore_fleet",
                   side_effect=changed_policy):
            with self.assertRaisesRegex(FleetRetentionError, "changed during verification"):
                apply_retention(self.archives, self.policy, self.plan,
                                str(preview["plan_sha256"]), self.key)
        self.assertTrue(all(path.exists() for path in self.created))


if __name__ == "__main__":
    unittest.main()
