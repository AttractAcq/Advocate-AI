from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from apps.api.main import Settings


class CoreRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "restored-state"
        self.state.mkdir()
        self.secret = self.root / "lab-password"
        self.secret.write_text("synthetic-restored-state-passphrase\n")
        self.secret.chmod(0o600)

    def test_reads_restored_fixture_root_and_private_password_file(self) -> None:
        with patch.dict(os.environ, {
                "SOVEREIGN_FIXTURE_ROOT": str(self.state),
                "SOVEREIGN_LAB_PASSWORD_FILE": str(self.secret)}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.fixture_root, self.state)
        self.assertEqual(settings.lab_password, "synthetic-restored-state-passphrase")

    def test_rejects_ambiguous_or_exposed_credential_and_linked_fixture(self) -> None:
        with patch.dict(os.environ, {
                "SOVEREIGN_LAB_PASSWORD": "synthetic-direct-passphrase",
                "SOVEREIGN_LAB_PASSWORD_FILE": str(self.secret)}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()
        self.secret.chmod(0o644)
        with patch.dict(os.environ, {"SOVEREIGN_LAB_PASSWORD_FILE": str(self.secret)}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()
        linked = self.root / "linked-state"
        linked.symlink_to(self.state, target_is_directory=True)
        with patch.dict(os.environ, {"SOVEREIGN_FIXTURE_ROOT": str(linked)}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()


if __name__ == "__main__":
    unittest.main()
