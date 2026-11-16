"""Fail closed before Docker receives untrusted restored-state mount paths."""

from pathlib import Path
import tempfile
import unittest

from infrastructure.deploy.container_runtime import RuntimeError, _core_state_options


class SignedCoreStateMountTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        (self.state / "sources").mkdir()
        for name in ("roles.json", "manifest.csv", "history.db"):
            path = self.state / name
            path.write_bytes(b"synthetic")
            path.chmod(0o600)
        self.credential = self.root / "credential"
        self.credential.write_text("synthetic-passphrase\n")
        self.credential.chmod(0o600)

    def test_separate_owner_only_paths_produce_runtime_mounts(self) -> None:
        options = _core_state_options(self.state, self.credential)
        self.assertIn("SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign", options)
        self.assertIn("SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password", options)
        self.assertTrue(any("target=/var/lib/sovereign" in item for item in options))
        self.assertTrue(any("target=/run/secrets/lab-password,readonly" in item
                            for item in options))

    def test_missing_or_linked_state_and_credential_fail(self) -> None:
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, None)
        linked = self.root / "linked-state"
        linked.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            _core_state_options(linked, self.credential)
        linked_credential = self.root / "linked-credential"
        linked_credential.symlink_to(self.credential)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, linked_credential)

    def test_secret_in_snapshot_and_writable_policy_fail(self) -> None:
        nested_credential = self.state / "snapshot-secret"
        nested_credential.write_text("synthetic-passphrase\n")
        nested_credential.chmod(0o600)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, nested_credential)
        (self.state / "roles.json").chmod(0o666)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential)


if __name__ == "__main__":
    unittest.main()
