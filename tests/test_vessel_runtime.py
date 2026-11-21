from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle, _credentials
from infrastructure.deploy.vessel_identity import VesselIdentity
from infrastructure.deploy.vessel_runtime import (
    VesselRuntimeError, _state_options, probe_signed_vessel_services,
    start_signed_vessel_services,
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
        self.assertIn("SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl", options)
        self.assertIn("SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db", options)
        self.assertNotIn("SOVEREIGN_KNOWLEDGE_DB=/var/lib/sovereign/knowledge.db",
                         options)

    def test_signed_model_name_is_bound_to_local_core_requests(self) -> None:
        options, _ = _state_options(self.state, self.lab_password,
                                    self.knowledge_root,
                                    model_id="synthetic-lab-model")
        self.assertIn("SOVEREIGN_MODEL_NAME=synthetic-lab-model", options)
        self.assertIn("SOVEREIGN_MODEL_ENDPOINT=http://127.0.0.1:11434/v1", options)
        with self.assertRaisesRegex(VesselRuntimeError, "model request name"):
            _state_options(self.state, self.lab_password, self.knowledge_root,
                           model_id="untrusted/model")

    def test_oidc_core_options_exclude_lab_password(self) -> None:
        identity = VesselIdentity(
            "https://identity.vessel.example/realms/sovereign",
            self.state / "oidc-ca.pem", self.state / "oidc-revocations.jsonl",
            "vessel-identity", "a" * 64)
        options, _ = _state_options(self.state, None, self.knowledge_root,
                                    identity=identity)
        self.assertIn(f"SOVEREIGN_OIDC_ISSUER={identity.issuer}", options)
        self.assertIn("SOVEREIGN_OIDC_CA_FILE=/var/lib/sovereign/oidc-ca.pem", options)
        self.assertIn("SOVEREIGN_OIDC_REVOCATIONS=/var/lib/sovereign/oidc-revocations.jsonl",
                      options)
        self.assertFalse(any("lab-password" in option for option in options))
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.lab_password, self.knowledge_root,
                           identity=identity)

    def test_status_probe_refuses_model_environment_mismatch(self) -> None:
        reader = self.knowledge_root / "knowledge-secrets/reader.pgpass"
        knowledge = KnowledgeVolumeHandle("d" * 64, "socket", "data", "run", "f" * 32)
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        mounts = [
            {"Destination": "/var/lib/sovereign", "Type": "bind",
             "Source": str(self.state.resolve()), "RW": True},
            {"Destination": "/run/secrets/lab-password", "Type": "bind",
             "Source": str(self.lab_password.resolve()), "RW": False},
            {"Destination": "/run/secrets/pgpass", "Type": "bind",
             "Source": str(reader.resolve()), "RW": False},
            {"Destination": "/run/postgresql", "Type": "volume",
             "Name": "socket", "RW": False},
        ]
        environment = [
            "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
            "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
            "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
            "SOVEREIGN_KNOWLEDGE_DB=postgresql://sovereign_read@/postgres?host=/run/postgresql",
            "SOVEREIGN_AUDIT_PATH=/var/lib/sovereign/audit.jsonl",
            "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
            "PGPASSFILE=/run/secrets/pgpass",
            "SOVEREIGN_MODEL_NAME=wrong-model",
            "SOVEREIGN_MODEL_ENDPOINT=http://127.0.0.1:11434/v1",
        ]

        def docker(*args: str) -> str:
            template = args[-1]
            if template == "{{.State.Running}}":
                return "true"
            if template == "{{json .HostConfig.PortBindings}}":
                return "null"
            if template == "{{json .Mounts}}":
                return json.dumps(mounts)
            if template == "{{json .Config.Env}}":
                return json.dumps(environment)
            raise AssertionError(args)

        with patch("infrastructure.deploy.vessel_runtime.verify_runtime_identity"), \
             patch("infrastructure.deploy.vessel_runtime.probe_knowledge"), \
             patch("infrastructure.deploy.vessel_runtime._docker", side_effect=docker), \
             patch("infrastructure.deploy.vessel_runtime._health") as health:
            with self.assertRaisesRegex(VesselRuntimeError, "environment changed"):
                probe_signed_vessel_services(handle, knowledge, self.state,
                                             self.lab_password, reader,
                                             model_id="synthetic-lab-model")
            health.assert_not_called()

    def test_oidc_probe_refuses_lab_credential_mount(self) -> None:
        identity = VesselIdentity(
            "https://identity.vessel.example/realms/sovereign",
            self.state / "oidc-ca.pem", self.state / "oidc-revocations.jsonl",
            "vessel-identity", "e" * 64)
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64,
                               identity.network_id, identity.network_name)
        knowledge = KnowledgeVolumeHandle("d" * 64, "socket", "data", "run", "f" * 32)

        def docker(*args: str) -> str:
            if args[-1] == "{{.State.Running}}":
                return "true"
            if args[-1] == "{{json .HostConfig.PortBindings}}":
                return "null"
            if args[-1] == "{{json .Mounts}}":
                return json.dumps([{"Destination": "/run/secrets/lab-password",
                                    "Type": "bind", "Source": str(self.lab_password),
                                    "RW": False}])
            if args[-1] == "{{json .Config.Env}}":
                return "[]"
            raise AssertionError(args)

        with patch("infrastructure.deploy.vessel_runtime.verify_runtime_identity"), \
             patch("infrastructure.deploy.vessel_runtime.probe_knowledge"), \
             patch("infrastructure.deploy.vessel_runtime._docker", side_effect=docker), \
             patch("infrastructure.deploy.vessel_runtime._health") as health:
            with self.assertRaisesRegex(VesselRuntimeError, "lab credential mount"):
                probe_signed_vessel_services(handle, knowledge, self.state, None,
                                             self.knowledge_root / "reader.pgpass",
                                             identity=identity)
            health.assert_not_called()

    def test_state_and_credentials_cannot_overlap(self) -> None:
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.state / "roles.json", self.knowledge_root)
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.lab_password, self.state)

    def test_exposed_source_directory_and_boolean_manifest_schema_fail(self) -> None:
        sources = self.state / "sources"
        sources.chmod(0o755)
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.lab_password, self.knowledge_root)
        sources.chmod(0o700)
        manifest = self.state / "approved.json"
        payload = json.loads(manifest.read_text())
        payload["schema"] = True
        manifest.write_text(json.dumps(payload))
        with self.assertRaises(VesselRuntimeError):
            _state_options(self.state, self.lab_password, self.knowledge_root)

    def test_invalid_persistent_state_denies_core_start(self) -> None:
        audit = self.state / "audit.jsonl"
        audit.write_text('{"sequence":1}\n')
        audit.chmod(0o600)
        with self.assertRaisesRegex(VesselRuntimeError, "audit trail"):
            _state_options(self.state, self.lab_password, self.knowledge_root)
        audit.unlink()
        (self.state / "history.db").symlink_to(self.state / "roles.json")
        with self.assertRaisesRegex(VesselRuntimeError, "persistent"):
            _state_options(self.state, self.lab_password, self.knowledge_root)

    def test_future_history_format_denies_before_runtime_start(self) -> None:
        history = self.state / "history.db"
        with sqlite3.connect(history) as database:
            database.execute("PRAGMA user_version=2")
        history.chmod(0o600)
        with self.assertRaisesRegex(VesselRuntimeError, "history format"):
            _state_options(self.state, self.lab_password, self.knowledge_root)

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
