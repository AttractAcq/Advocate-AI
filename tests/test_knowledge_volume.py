from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeError, KnowledgeVolumeHandle, _credentials,
    start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.postgres_socket import (
    HBA, PostgresSocketError, verify_login, verify_security,
)
from infrastructure.release.bundle import BundleError


class KnowledgeVolumeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)

    def test_credentials_are_private_and_restart_reuses_them(self) -> None:
        first = _credentials(self.root, initialize=True)
        second = _credentials(self.root, initialize=False)
        self.assertEqual(first, second)
        self.assertNotEqual(first[3], first[4])
        for path in first[:3]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        first[2].chmod(0o644)
        with self.assertRaises(KnowledgeVolumeError):
            _credentials(self.root, initialize=False)

    def test_wrong_target_cannot_load_or_start_image(self) -> None:
        with patch("infrastructure.deploy.knowledge_volume.verify_bundle",
                   return_value={"schema": 6, "target": "fleet"}), \
             patch("infrastructure.deploy.knowledge_volume._image_id") as load:
            with self.assertRaises(BundleError):
                start_signed_knowledge(self.root, self.root / "key", self.root / "crane",
                                       self.root, "a" * 32, initialize=True)
            load.assert_not_called()

    def test_forged_stop_handle_cannot_remove_volume(self) -> None:
        handle = KnowledgeVolumeHandle("a" * 64, "unscoped-volume",
                                       "sovereign-" + "b" * 32 + "-knowledge-data",
                                       "sovereign-knowledge-" + "c" * 12, "b" * 32)
        with patch("infrastructure.deploy.knowledge_volume.docker") as docker:
            with self.assertRaises(KnowledgeVolumeError):
                stop_knowledge(handle)
            docker.assert_not_called()

    def test_role_privilege_change_fails_runtime_check(self) -> None:
        def sql(_identifier: str, statement: str) -> str:
            if "pg_hba_file_rules" in statement:
                return "0"
            if "rolname ||" in statement:
                return "sovereign_ingest:0:0:0:0:0\nsovereign_read:1:0:0:0:0"
            return "f"

        with patch("infrastructure.deploy.postgres_socket.sql", side_effect=sql), \
             patch("infrastructure.deploy.postgres_socket.docker",
                   return_value=HBA.rstrip("\n")):
            with self.assertRaises(PostgresSocketError):
                verify_security("a" * 64)

    def test_login_probe_keeps_secret_out_of_docker_arguments(self) -> None:
        secret = "a" * 64
        with patch("infrastructure.deploy.postgres_socket.pg_input",
                   return_value="sovereign_read") as input_call:
            verify_login("b" * 64, "sovereign_read", secret)
            self.assertEqual(input_call.call_args.args[2], secret + "\n")
            self.assertNotIn(secret, input_call.call_args.args[1])
            with self.assertRaises(PostgresSocketError):
                verify_login("b" * 64, "postgres", secret)


if __name__ == "__main__":
    unittest.main()
