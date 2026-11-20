from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _read_state, _stage, _state_payload, _write_state,
)
from infrastructure.deploy.vessel_release_switch import (
    rollback_stopped_vessel_release, switch_stopped_vessel_release,
)


class VesselReleaseSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.parent.chmod(0o700)
        self.root = self.parent / "installation"
        self.root.mkdir(mode=0o700)
        self.services = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        self.knowledge = KnowledgeVolumeHandle(
            "d" * 64, "sovereign-knowledge-" + "e" * 12 + "-socket",
            "sovereign-" + "f" * 32 + "-knowledge-data",
            "sovereign-knowledge-" + "e" * 12, "f" * 32)
        self.current = _state_payload(
            "1" * 24, "f" * 32, self.parent / "state",
            self.parent / "password", self.services, self.knowledge)
        _write_state(self.root, self.current)
        self.key, self.crane = self.parent / "key", self.parent / "crane"

    def test_staging_second_release_accepts_existing_private_directory(self) -> None:
        bundle = self.parent / "bundle"
        bundle.mkdir()
        (bundle / "release-manifest.json").write_text("{}")
        config = self.parent / "config"
        config.write_text("{}")
        config.chmod(0o644)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel"}), \
             patch("infrastructure.deploy.vessel_installer._validate_console_config"), \
             patch("infrastructure.deploy.vessel_installer._release_id",
                   side_effect=["1" * 24, "2" * 24]), \
             patch("infrastructure.deploy.vessel_installer._verify_stage"):
            first, _ = _stage(self.root, bundle, self.key, config)
            second, _ = _stage(self.root, bundle, self.key, config)
        self.assertNotEqual(first, second)
        self.assertTrue((self.root / "vessel-releases" / second / "bundle").is_dir())

    def test_switch_requires_clean_stopped_inventory_before_stage(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory",
                   side_effect=VesselInstallError("runtime still present")), \
             patch("infrastructure.deploy.vessel_release_switch._stage") as stage:
            with self.assertRaisesRegex(VesselInstallError, "runtime still present"):
                switch_stopped_vessel_release(
                    self.root, self.key, self.crane,
                    self.parent / "bundle", self.parent / "config")
            stage.assert_not_called()
        self.assertEqual(_read_state(self.root), self.current)

    def test_rollback_requires_recorded_predecessor(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage") as verify:
            with self.assertRaisesRegex(VesselInstallError, "no previous"):
                rollback_stopped_vessel_release(self.root, self.key, self.crane)
            verify.assert_not_called()

    def test_candidate_failure_keeps_prior_state_and_data(self) -> None:
        new_knowledge = KnowledgeVolumeHandle(
            "4" * 64, "sovereign-knowledge-" + "5" * 12 + "-socket",
            self.knowledge.data_volume, "sovereign-knowledge-" + "5" * 12,
            "f" * 32)
        stage = self.root / "vessel-releases" / ("2" * 24)
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_release_switch._stage",
                   return_value=("2" * 24, stage)), \
             patch("infrastructure.deploy.vessel_release_switch.policy_directory_lock"), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_knowledge",
                   return_value=new_knowledge), \
             patch("infrastructure.deploy.vessel_release_switch._verify_knowledge_schema"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_database",
                   side_effect=ValueError("index mismatch")), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_vessel_services") as start, \
             patch("infrastructure.deploy.vessel_release_switch._cleanup_failed_install",
                   return_value=True) as cleanup:
            with self.assertRaisesRegex(ValueError, "index mismatch"):
                switch_stopped_vessel_release(
                    self.root, self.key, self.crane,
                    self.parent / "bundle", self.parent / "config")
            start.assert_not_called()
            self.assertTrue(cleanup.call_args.kwargs["retain_data"])
            self.assertEqual(cleanup.call_args.args[3], self.knowledge.data_volume)
        self.assertEqual(_read_state(self.root), self.current)


if __name__ == "__main__":
    unittest.main()
