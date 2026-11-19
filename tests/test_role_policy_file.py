"""Role policy files must be bounded and must not follow symlinks."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from services.policy.policy_file import PolicyUnavailable, load_policy


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


if __name__ == "__main__":
    unittest.main()
