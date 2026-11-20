from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _cleanup_failed_install, _read_state, _state_payload,
    _write_state, install_vessel, recover_vessel,
)
from infrastructure.release.bundle import BundleError


class VesselInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.parent.chmod(0o700)
        self.root = self.parent / "new-install"

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

    def test_failed_activation_has_no_active_record(self) -> None:
        knowledge = KnowledgeVolumeHandle("a" * 64, "socket", "data", "run", "b" * 32)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel"}), \
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
                   return_value={"schema": 6, "target": "vessel"}), \
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
            self.assertFalse(any(call.args[:2] == ("volume", "rm")
                                 for call in docker.call_args_list))

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
             patch("infrastructure.deploy.vessel_installer.start_signed_vessel_services",
                   return_value=new_services):
            result = recover_vessel(self.root, self.parent / "key", self.parent / "crane")
        self.assertEqual(result, {"result": "recovered", "active": "6" * 24})
        verify.assert_called_once_with(self.root / "vessel-releases" / ("6" * 24),
                                       self.parent / "key", "6" * 24)
        inventory.assert_called_once_with(installation_id, initial["runtime"])
        self.assertFalse(start_knowledge.call_args.kwargs["initialize"])
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


if __name__ == "__main__":
    unittest.main()
