from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _cleanup_failed_install, _ingest, _read_intent, _read_state,
    _verify_knowledge_schema,
    _scoped_list,
    _state_payload, _write_intent, _write_state, finish_vessel_stop, install_vessel,
    reconcile_first_install, reconcile_vessel, recover_vessel,
    reset_first_install, resume_first_install,
)
from infrastructure.release.bundle import BundleError, SUPPORTED_VESSEL_COMPATIBILITY


class VesselInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.parent.chmod(0o700)
        self.root = self.parent / "new-install"

    def test_restore_intent_blocks_generic_first_install_recovery(self) -> None:
        self.root.mkdir(mode=0o700)
        (self.root / "vessel-restore-intent.json").write_text('{"schema":1}')
        for operation in (reconcile_first_install, reset_first_install,
                          resume_first_install):
            with self.subTest(operation=operation.__name__), \
                 self.assertRaisesRegex(VesselInstallError, "restore candidate"):
                operation(self.root, self.parent / "key", self.parent / "crane")

    def test_wrong_release_target_cannot_create_install_root(self) -> None:
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "fleet"}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge") as start:
            with self.assertRaises(BundleError):
                install_vessel(self.parent, self.parent / "key", self.parent / "crane",
                               self.parent / "config", self.root,
                               self.parent / "state", self.parent / "password")
            self.assertFalse(self.root.exists())
            start.assert_not_called()

    def test_future_signed_contract_cannot_create_install_root(self) -> None:
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": {"knowledge_schema": 2,
                                                   "core_state_schema": 1}}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge") as start:
            with self.assertRaisesRegex(BundleError, "unsupported vessel compatibility"):
                install_vessel(self.parent, self.parent / "key", self.parent / "crane",
                               self.parent / "config", self.root,
                               self.parent / "state", self.parent / "password")
            self.assertFalse(self.root.exists())
            start.assert_not_called()

    def test_signed_schema_task_precedes_restricted_ingestion(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        writer = self.parent / "writer.pgpass"
        migrate = self.parent / "migrate.pgpass"
        completed = [subprocess.CompletedProcess([], 0, stdout=""),
                     subprocess.CompletedProcess([], 0,
                                                 stdout='{"indexed":1,"unchanged":0}')]
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"images": {"core": "archive"}}), \
             patch("infrastructure.deploy.vessel_installer._image_id",
                   return_value="signed-core"), \
             patch("infrastructure.deploy.vessel_installer._credentials",
                   return_value=(self.parent, writer, self.parent, "w", "r")), \
             patch("infrastructure.deploy.vessel_installer._migration_credential",
                   return_value=(migrate, "m")), \
             patch("infrastructure.deploy.vessel_installer.subprocess.run",
                   side_effect=completed) as run:
            result = _ingest(self.parent, self.parent / "key", self.parent / "crane",
                             self.parent / "state", self.parent, knowledge)
        self.assertEqual(result, {"indexed": 1, "unchanged": 0})
        self.assertEqual(run.call_count, 2)
        schema, ingest = (call.args[0] for call in run.call_args_list)
        self.assertIn("SOVEREIGN_KNOWLEDGE_DB=postgresql://sovereign_migrate@/postgres?host=/run/postgresql", schema)
        self.assertIn("SOVEREIGN_KNOWLEDGE_DB=postgresql://sovereign_ingest@/postgres?host=/run/postgresql", ingest)
        self.assertIn(f"type=bind,source={migrate.resolve()},target=/run/secrets/pgpass,readonly", schema)
        self.assertIn(f"type=bind,source={writer.resolve()},target=/run/secrets/pgpass,readonly", ingest)
        self.assertFalse(any("target=/var/lib/sovereign" in argument for argument in schema))
        self.assertTrue(any("target=/var/lib/sovereign" in argument for argument in ingest))

    def test_unknown_knowledge_schema_denies_runtime(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        with patch("infrastructure.deploy.vessel_installer.postgres_sql",
                   return_value="1:2") as query:
            with self.assertRaisesRegex(VesselInstallError, "schema version"):
                _verify_knowledge_schema(knowledge)
            self.assertEqual(query.call_args.args[0], knowledge.container_id)

    def test_failed_activation_has_no_active_record(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_installer._stage",
                   return_value=("c" * 24, self.parent)), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=knowledge), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._ingest",
                   return_value={"indexed": 1, "unchanged": 0}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   side_effect=VesselInstallError("unhealthy")), \
             patch("infrastructure.deploy.vessel_installer.stop_knowledge") as stopped, \
             patch("infrastructure.deploy.vessel_installer._docker", return_value=""):
            with self.assertRaises(VesselInstallError):
                install_vessel(self.parent, self.parent / "key", self.parent / "crane",
                               self.parent / "config", self.root,
                               self.parent / "state", self.parent / "password")
            self.assertFalse((self.root / "vessel-state.json").exists())
            self.assertFalse(self.root.exists())
            stopped.assert_called_once_with(knowledge)

    def test_incomplete_cleanup_retains_private_root_and_no_active_record(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_installer._stage",
                   return_value=("c" * 24, self.parent)), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=knowledge), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._ingest",
                   return_value={"indexed": 1, "unchanged": 0}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   side_effect=VesselInstallError("unhealthy")), \
             patch("infrastructure.deploy.vessel_installer.stop_knowledge"), \
             patch("infrastructure.deploy.vessel_installer._docker",
                   return_value="a" * 64) as docker:
            with self.assertRaisesRegex(VesselInstallError, "cleanup incomplete"):
                install_vessel(self.parent, self.parent / "key", self.parent / "crane",
                               self.parent / "config", self.root,
                               self.parent / "state", self.parent / "password")
            self.assertTrue(self.root.is_dir())
            self.assertFalse((self.root / "vessel-state.json").exists())
            self.assertEqual(_read_intent(self.root)["release"], "c" * 24)
            self.assertFalse(any(call.args[:2] == ("volume", "rm")
                                 for call in docker.call_args_list))

    def test_successful_first_install_clears_private_intent(self) -> None:
        installation_id = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          f"sovereign-{installation_id}-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        with patch("infrastructure.deploy.vessel_installer.secrets.token_hex",
                   return_value=installation_id), \
             patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_installer._stage",
                   return_value=("6" * 24, self.parent)), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=knowledge), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._ingest",
                   return_value={"indexed": 1, "unchanged": 0}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   return_value=services):
            result = install_vessel(self.parent, self.parent / "key",
                                    self.parent / "crane", self.parent / "config",
                                    self.root, self.parent / "state",
                                    self.parent / "password")
        self.assertEqual(result["result"], "activated")
        self.assertFalse((self.root / "vessel-intent.json").exists())
        self.assertEqual(_read_state(self.root)["installation_id"], installation_id)

    def test_install_intent_rejects_duplicate_fields(self) -> None:
        self.root.mkdir(mode=0o700)
        _write_intent(self.root, "6" * 24, "f" * 32,
                      self.parent / "state", self.parent / "password")
        path = self.root / "vessel-intent.json"
        path.write_text(path.read_text().replace('"schema":1', '"schema":1,"schema":1'))
        with self.assertRaises(VesselInstallError):
            _read_intent(self.root)

    def test_reconcile_early_install_resets_unbound_credentials(self) -> None:
        self.root.mkdir(mode=0o700)
        _write_intent(self.root, "6" * 24, "f" * 32,
                      self.parent / "state", self.parent / "password")
        credentials = self.root / "knowledge-secrets"
        credentials.mkdir(mode=0o700)
        secret = credentials / "admin-password"
        secret.write_text("synthetic")
        secret.chmod(0o600)
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._scoped_list",
                   side_effect=[[], [], []]), \
             patch("infrastructure.deploy.vessel_installer._assert_missing"):
            result = reconcile_first_install(self.root, self.parent / "key",
                                             self.parent / "crane")
        self.assertEqual(result["result"], "reconciled")
        self.assertFalse(credentials.exists())
        self.assertEqual(_read_intent(self.root)["release"], "6" * 24)

    def test_explicit_bootstrap_reset_keeps_intent_and_clears_data_credentials(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        data_volume = f"sovereign-{installation_id}-knowledge-data"
        _write_intent(self.root, "6" * 24, installation_id,
                      self.parent / "state", self.parent / "password")
        credentials = self.root / "knowledge-secrets"
        credentials.mkdir(mode=0o700)
        secret = credentials / "admin-password"
        secret.write_text("synthetic")
        secret.chmod(0o600)
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._scoped_list",
                   side_effect=[[], [], [data_volume]]), \
             patch("infrastructure.deploy.vessel_installer._volume"), \
             patch("infrastructure.deploy.vessel_installer._docker") as docker, \
             patch("infrastructure.deploy.vessel_installer._assert_missing"):
            result = reset_first_install(self.root, self.parent / "key",
                                         self.parent / "crane")
        self.assertEqual(result, {"result": "bootstrap-reset", "data_volume": "removed"})
        docker.assert_called_once_with("volume", "rm", data_volume)
        self.assertFalse(credentials.exists())
        self.assertEqual(_read_intent(self.root)["installation_id"], installation_id)

    def test_bootstrap_reset_rejects_other_scoped_resources_before_deletion(self) -> None:
        self.root.mkdir(mode=0o700)
        _write_intent(self.root, "6" * 24, "f" * 32,
                      self.parent / "state", self.parent / "password")
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._scoped_list",
                   side_effect=[["a" * 64], [],
                                ["sovereign-" + "f" * 32 + "-knowledge-data"]]), \
             patch("infrastructure.deploy.vessel_installer._docker") as docker:
            with self.assertRaisesRegex(VesselInstallError, "only the data volume"):
                reset_first_install(self.root, self.parent / "key",
                                    self.parent / "crane")
        docker.assert_not_called()

    def test_resume_clean_first_install_preserves_installation_id(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        data_volume = f"sovereign-{installation_id}-knowledge-data"
        _write_intent(self.root, "6" * 24, installation_id,
                      self.parent / "state", self.parent / "password")
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          data_volume, "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._scoped_list",
                   side_effect=[[], [], [data_volume]]), \
             patch("infrastructure.deploy.vessel_installer._volume"), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=knowledge) as start, \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._ingest",
                   return_value={"indexed": 1, "unchanged": 0}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   return_value=services):
            result = resume_first_install(self.root, self.parent / "key",
                                          self.parent / "crane")
        self.assertEqual(result["result"], "activated")
        self.assertFalse(start.call_args.kwargs["initialize"])
        self.assertFalse((self.root / "vessel-intent.json").exists())
        self.assertEqual(_read_state(self.root)["installation_id"], installation_id)

    def test_resume_clears_stale_intent_only_for_matching_healthy_state(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          f"sovereign-{installation_id}-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        _write_intent(self.root, "6" * 24, installation_id,
                      self.parent / "state", self.parent / "password")
        _write_state(self.root, _state_payload("6" * 24, installation_id,
                                               self.parent / "state",
                                               self.parent / "password",
                                               services, knowledge))
        with patch("infrastructure.deploy.vessel_installer.status_vessel",
                   return_value={"result": "healthy", "active": "6" * 24}), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge") as start:
            result = resume_first_install(self.root, self.parent / "key",
                                          self.parent / "crane")
        self.assertEqual(result["result"], "already-activated")
        self.assertFalse((self.root / "vessel-intent.json").exists())
        start.assert_not_called()

    def test_resume_preserves_intent_when_active_state_differs(self) -> None:
        self.root.mkdir(mode=0o700)
        _write_intent(self.root, "6" * 24, "f" * 32,
                      self.parent / "state", self.parent / "password")
        (self.root / "vessel-state.json").write_text("synthetic")
        with patch("infrastructure.deploy.vessel_installer.status_vessel",
                   return_value={"result": "healthy"}), \
             patch("infrastructure.deploy.vessel_installer._read_state",
                   return_value={"active": "7" * 24, "installation_id": "f" * 32,
                                 "core_state": str(self.parent / "state"),
                                 "lab_password_file": str(self.parent / "password"),
                                 "runtime": {"data_volume": "unmatched"}}):
            with self.assertRaisesRegex(VesselInstallError, "does not match"):
                resume_first_install(self.root, self.parent / "key",
                                     self.parent / "crane")
        self.assertTrue((self.root / "vessel-intent.json").exists())

    def test_cleanup_requires_empty_scoped_inventory_after_volume_removal(self) -> None:
        installation_id = "b" * 32
        data_volume = f"sovereign-{installation_id}-knowledge-data"
        with patch("infrastructure.deploy.vessel_installer._docker",
                   side_effect=["", "", data_volume, "", ""]) as docker:
            self.assertTrue(_cleanup_failed_install(installation_id, None, None,
                                                    data_volume))
            docker.assert_any_call("volume", "rm", data_volume)
        with patch("infrastructure.deploy.vessel_installer._docker",
                   side_effect=RuntimeError("daemon unavailable")):
            self.assertFalse(_cleanup_failed_install(installation_id, None, None,
                                                     data_volume))

    def test_active_state_rejects_duplicate_and_tampered_runtime(self) -> None:
        self.root.mkdir(mode=0o700)
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          "sovereign-" + "f" * 32 + "-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12, "f" * 32)
        payload = _state_payload("1" * 24, "f" * 32,
                                 self.parent / "state", self.parent / "password",
                                 services, knowledge)
        _write_state(self.root, payload)
        self.assertEqual(_read_state(self.root)["active"], "1" * 24)
        with_previous = _state_payload("1" * 24, "f" * 32,
                                       self.parent / "state", self.parent / "password",
                                       services, knowledge, previous="2" * 24)
        _write_state(self.root, with_previous)
        self.assertEqual(_read_state(self.root)["previous"], "2" * 24)
        for invalid in ("1" * 24, "z" * 24):
            path = self.root / "vessel-state.json"
            path.write_text(json.dumps({**with_previous, "previous": invalid}))
            with self.assertRaises(VesselInstallError):
                _read_state(self.root)
        _write_state(self.root, payload)
        path = self.root / "vessel-state.json"
        path.write_text(path.read_text().replace('"schema":1', '"schema":1,"schema":1'))
        with self.assertRaises(VesselInstallError):
            _read_state(self.root)
        path.write_text(json.dumps({**payload, "runtime": {**payload["runtime"],
                                                       "data_volume": "other"}}))
        with self.assertRaises(VesselInstallError):
            _read_state(self.root)

    def test_recovery_uses_signed_stage_and_retains_installation_identity(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        old_services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        old_knowledge = KnowledgeVolumeHandle("d" * 64,
                                              "sovereign-knowledge-" + "e" * 12 + "-socket",
                                              f"sovereign-{installation_id}-knowledge-data",
                                              "sovereign-knowledge-" + "e" * 12,
                                              installation_id)
        new_services = RuntimeHandle("1" * 64, "2" * 64, "3" * 64)
        new_knowledge = KnowledgeVolumeHandle("4" * 64,
                                              "sovereign-knowledge-" + "5" * 12 + "-socket",
                                              old_knowledge.data_volume,
                                              "sovereign-knowledge-" + "5" * 12,
                                              installation_id)
        initial = _state_payload("6" * 24, installation_id,
                                 self.parent / "state", self.parent / "password",
                                 old_services, old_knowledge)
        _write_state(self.root, initial)
        with patch("infrastructure.deploy.vessel_installer._verify_stage") as verify, \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._recovery_inventory") as inventory, \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=new_knowledge) as start_knowledge, \
             patch("infrastructure.deploy.vessel_installer._verify_knowledge_schema") as schema, \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   return_value=new_services):
            result = recover_vessel(self.root, self.parent / "key", self.parent / "crane")
        self.assertEqual(result, {"result": "recovered", "active": "6" * 24})
        verify.assert_called_once_with(self.root / "vessel-releases" / ("6" * 24),
                                       self.parent / "key", "6" * 24)
        inventory.assert_called_once_with(installation_id, initial["runtime"])
        self.assertFalse(start_knowledge.call_args.kwargs["initialize"])
        schema.assert_called_once_with(new_knowledge)
        self.assertEqual(_read_state(self.root)["runtime"]["data_volume"],
                         old_knowledge.data_volume)
        self.assertEqual(_read_state(self.root)["runtime"]["knowledge_id"],
                         new_knowledge.container_id)

    def test_recovery_rejects_old_resource_without_starting(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          f"sovereign-{installation_id}-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        initial = _state_payload("6" * 24, installation_id,
                                 self.parent / "state", self.parent / "password",
                                 services, knowledge)
        _write_state(self.root, initial)
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._docker",
                   return_value="b" * 64), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge") as start:
            with self.assertRaisesRegex(VesselInstallError, "only the persistent"):
                recover_vessel(self.root, self.parent / "key", self.parent / "crane")
        start.assert_not_called()
        self.assertEqual(_read_state(self.root), initial)

    def test_recovery_write_failure_preserves_old_record_and_data(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        old_services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        old_knowledge = KnowledgeVolumeHandle("d" * 64,
                                              "sovereign-knowledge-" + "e" * 12 + "-socket",
                                              f"sovereign-{installation_id}-knowledge-data",
                                              "sovereign-knowledge-" + "e" * 12,
                                              installation_id)
        new_services = RuntimeHandle("1" * 64, "2" * 64, "3" * 64)
        new_knowledge = KnowledgeVolumeHandle("4" * 64,
                                              "sovereign-knowledge-" + "5" * 12 + "-socket",
                                              old_knowledge.data_volume,
                                              "sovereign-knowledge-" + "5" * 12,
                                              installation_id)
        initial = _state_payload("6" * 24, installation_id,
                                 self.parent / "state", self.parent / "password",
                                 old_services, old_knowledge)
        _write_state(self.root, initial)
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_installer.start_signed_knowledge",
                   return_value=new_knowledge), \
             patch("infrastructure.deploy.vessel_installer._verify_knowledge_schema"), \
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   return_value=new_services), \
             patch("infrastructure.deploy.vessel_installer._write_state",
                   side_effect=OSError("disk unavailable")), \
             patch("infrastructure.deploy.vessel_installer._cleanup_failed_install",
                   return_value=True) as cleanup:
            with self.assertRaises(OSError):
                recover_vessel(self.root, self.parent / "key", self.parent / "crane")
        cleanup.assert_called_once_with(installation_id, new_services,
                                        new_knowledge, old_knowledge.data_volume,
                                        retain_data=True)
        self.assertEqual(_read_state(self.root), initial)

    def test_recovery_rejects_concurrent_operator_command(self) -> None:
        self.root.mkdir(mode=0o700)
        descriptor = os.open(self.root / ".vessel-operation.lock",
                             os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("infrastructure.deploy.vessel_installer._read_state") as read:
                with self.assertRaisesRegex(VesselInstallError, "another vessel operation"):
                    recover_vessel(self.root, self.parent / "key",
                                   self.parent / "crane")
                read.assert_not_called()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def test_reconcile_rejects_unexpected_scoped_resource_before_removal(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          f"sovereign-{installation_id}-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        _write_state(self.root, _state_payload(
            "6" * 24, installation_id, self.parent / "state",
            self.parent / "password", services, knowledge))
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._assert_missing"), \
             patch("infrastructure.deploy.vessel_installer._volume"), \
             patch("infrastructure.deploy.vessel_installer._docker",
                   side_effect=["", "", knowledge.data_volume + "\nunexpected-volume"]) as docker:
            with self.assertRaises(VesselInstallError):
                reconcile_vessel(self.root, self.parent / "key", self.parent / "crane")
            self.assertFalse(any(call.args[:1] == ("rm",)
                                 for call in docker.call_args_list))

    def test_scoped_inventory_rejects_duplicate_docker_ids(self) -> None:
        identifier = "a" * 64
        with patch("infrastructure.deploy.vessel_installer._docker",
                   return_value=f"{identifier}\n{identifier}"):
            with self.assertRaisesRegex(VesselInstallError, "invalid scoped"):
                _scoped_list("ps", "-a")

    def test_finish_stop_rejects_unrecorded_container_before_removal(self) -> None:
        self.root.mkdir(mode=0o700)
        installation_id = "f" * 32
        services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        knowledge = KnowledgeVolumeHandle("d" * 64,
                                          "sovereign-knowledge-" + "e" * 12 + "-socket",
                                          f"sovereign-{installation_id}-knowledge-data",
                                          "sovereign-knowledge-" + "e" * 12,
                                          installation_id)
        _write_state(self.root, _state_payload(
            "6" * 24, installation_id, self.parent / "state",
            self.parent / "password", services, knowledge))
        with patch("infrastructure.deploy.vessel_installer._verify_stage"), \
             patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6}), \
             patch("infrastructure.deploy.vessel_installer._state_options"), \
             patch("infrastructure.deploy.vessel_installer._scoped_list",
                   side_effect=[["9" * 64], [], [knowledge.data_volume]]), \
             patch("infrastructure.deploy.vessel_installer._docker") as docker:
            with self.assertRaisesRegex(VesselInstallError, "unrecorded resources"):
                finish_vessel_stop(self.root, self.parent / "key",
                                   self.parent / "crane")
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
