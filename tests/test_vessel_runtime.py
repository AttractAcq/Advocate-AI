from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle, _credentials
from infrastructure.deploy.vessel_runtime import (
    VesselRuntimeError, _state_options, start_signed_vessel_services,
)
from infrastructure.release.bundle import BundleError
from scripts.synthetic_pg_fixture import fixture, put


class VesselRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        fixture(self.state)
        self.knowledge_root = self.root / "knowledge"
        self.knowledge_root.mkdir(mode=0o700)
        _credentials(self.knowledge_root, initialize=True)
        self.lab_password = self.root / "lab-password"
        put(self.lab_password, b"synthetic-lab-password-for-test\n")

    def test_pg_socket_options_bind_separate_reader_credential(self) -> None:
        options, reader = _state_options(self.state, self.lab_password,
                                         self.knowledge_root)
        self.assertEqual(reader, self.knowledge_root / "knowledge-secrets/reader.pgpass")
        self.assertIn("PGPASSFILE=/run/secrets/pgpass", options)
        self.assertIn("SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
                      options)
        self.assertNotIn("SOVEREIGN_KNOWLEDGE_DB=/var/lib/sovereign/knowledge.db",
                         options)

    def test_state_and_credentials_cannot_overlap(self) -> None:
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.state / "roles.json", self.knowledge_root)
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.lab_password, self.state)

    def test_non_vessel_bundle_never_loads_images(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        with patch("infrastructure.deploy.vessel_runtime.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.vessel_runtime._image_id") as load:
            with self.assertRaises(BundleError):
                start_signed_vessel_services(self.root, self.root / "key",
                                             self.root / "crane", self.root / "config",
                                             self.state, self.lab_password,
                                             self.knowledge_root, knowledge, "b" * 32)
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
