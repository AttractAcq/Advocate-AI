from __future__ import annotations

from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeError, KnowledgeVolumeHandle, _credentials, _migration_credential, _volume,
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
        migration, migration_secret = _migration_credential(self.root)
        self.assertEqual(migration.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(migration_secret, (first[3], first[4]))
        for path in first[:3]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        first[2].chmod(0o644)
        with self.assertRaises(KnowledgeVolumeError):
            _credentials(self.root, initialize=False)

    def test_migration_credential_must_be_private_and_bound_to_role(self) -> None:
        _credentials(self.root, initialize=True)
        path, secret = _migration_credential(self.root)
        path.write_text(f"/run/postgresql:5432:postgres:sovereign_ingest:{secret}\n")
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

    def test_writer_schema_creation_is_rejected(self) -> None:
        def sql(_identifier: str, statement: str) -> str:
            if "pg_hba_file_rules" in statement:
                return "0"
            if "rolname ||" in statement:
                return ("sovereign_ingest:0:0:0:0:0\n"
                        "sovereign_migrate:0:0:0:0:0\n"
                        "sovereign_read:0:0:0:0:0")
            if "sovereign_migrate','public','CREATE" in statement:
                return "t"
            if "sovereign_ingest','public','CREATE" in statement:
                return "t"
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

    def test_volume_creation_distinguishes_absence_from_daemon_failure(self) -> None:
        name, installation = "sovereign-test-volume", "a" * 32
        metadata = {"Name": name, "Driver": "local",
                    "Labels": {"sovereign.synthetic.install": installation,
                               "sovereign.synthetic.role": "knowledge-data"}}
        missing = subprocess.CompletedProcess([], 1, b"", b"Error: no such volume")
        with patch("infrastructure.deploy.knowledge_volume.subprocess.run",
                   return_value=missing), \
             patch("infrastructure.deploy.knowledge_volume.docker",
                   side_effect=[name, json.dumps(metadata)]) as docker:
            _volume(name, installation, "knowledge-data", create=True)
            self.assertEqual(docker.call_count, 2)
        denied = subprocess.CompletedProcess([], 1, b"", b"permission denied")
        with patch("infrastructure.deploy.knowledge_volume.subprocess.run",
                   return_value=denied), \
             patch("infrastructure.deploy.knowledge_volume.docker") as docker:
            with self.assertRaises(KnowledgeVolumeError):
                _volume(name, installation, "knowledge-data", create=True)
            docker.assert_not_called()

    def test_restore_attempt_must_match_exact_volume_label(self) -> None:
        name, installation = "sovereign-test-volume", "a" * 32
        metadata = {"Name": name, "Driver": "local",
                    "Labels": {"sovereign.synthetic.install": installation,
                               "sovereign.synthetic.role": "knowledge-data",
                               "sovereign.synthetic.restore_attempt": "b" * 32}}
        with patch("infrastructure.deploy.knowledge_volume.docker",
                   return_value=json.dumps(metadata)):
            _volume(name, installation, "knowledge-data", create=False,
                    restore_attempt="b" * 32)
            with self.assertRaisesRegex(KnowledgeVolumeError, "identity mismatch"):
                _volume(name, installation, "knowledge-data", create=False,
                        restore_attempt="c" * 32)


if __name__ == "__main__":
    unittest.main()
