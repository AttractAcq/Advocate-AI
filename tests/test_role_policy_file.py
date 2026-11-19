"""Role policy files must be bounded and must not follow symlinks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from services.policy.policy_file import PolicyUnavailable, active_user, load_policy


class RolePolicyFileTests(unittest.TestCase):
    def test_regular_file_only_and_size_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "roles.json"
            policy.write_text('{"users": []}', encoding="utf-8")
            self.assertEqual(load_policy(policy), {"users": []})
            with patch("services.policy.policy_file.MAX_POLICY_BYTES", 8):
                with self.assertRaises(PolicyUnavailable):
                    load_policy(policy)
            linked = root / "linked.json"
            linked.symlink_to(policy)
            with self.assertRaises(PolicyUnavailable):
                load_policy(linked)
            policy.write_text('{"allow": {}, "allow": {}}', encoding="utf-8")
            with self.assertRaisesRegex(PolicyUnavailable, "duplicate"):
                load_policy(policy)
            policy.write_text('{"ignored": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(PolicyUnavailable, "constant"):
                load_policy(policy)

    def test_duplicate_and_expired_identity_is_never_active(self) -> None:
        now = datetime.now(timezone.utc)
        user = {"id": "fictional-emergency", "role": "emergency_recovery",
                "status": "active", "expires_at": (now + timedelta(minutes=5)).isoformat()}
        policy = {"users": [user], "allow": {"emergency_recovery": []}}
        self.assertEqual(active_user(policy, user["id"], now=now), user)
        self.assertIsNone(active_user(policy, user["id"], now=now + timedelta(minutes=5)))
        self.assertIsNone(active_user({**policy, "users": [user, user]}, user["id"], now=now))
        self.assertIsNone(active_user({**policy, "users": [{**user, "expires_at": "2030-01-01"}]},
                                      user["id"], now=now))


if __name__ == "__main__":
    unittest.main()
