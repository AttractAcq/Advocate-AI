from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _read_state, _stage, _state_payload, _write_state,
)
from infrastructure.deploy.vessel_release_switch import (
    _verify_preupdate_recovery,
    discard_stopped_vessel_stage, rollback_stopped_vessel_release,
    switch_stopped_vessel_release,
)
from infrastructure.release.bundle import BundleError, SUPPORTED_VESSEL_COMPATIBILITY
from infrastructure.restic_repository import MANIFEST


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
        recovery = self.parent / "recovery"
        recovery.mkdir(mode=0o700)
        self.receipt_args = (recovery / "receipt", recovery / "receipt-key",
                             self.parent / "backup-password", self.parent / "restic",
                             "0" * 64, self.parent / "staging")

    def switch(self, bundle: Path, config: Path) -> dict[str, object]:
        return switch_stopped_vessel_release(
            self.root, self.key, self.crane, bundle, config,
            *self.receipt_args)

    def test_staging_second_release_accepts_existing_private_directory(self) -> None:
        bundle = self.parent / "bundle"
        bundle.mkdir()
        (bundle / "release-manifest.json").write_text("{}")
        config = self.parent / "config"
        config.write_text("{}")
        config.chmod(0o644)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_installer._validate_console_config"), \
             patch("infrastructure.deploy.vessel_installer._release_id",
                   side_effect=["1" * 24, "2" * 24, "2" * 24]), \
             patch("infrastructure.deploy.vessel_installer._verify_stage"):
            first, _ = _stage(self.root, bundle, self.key, config)
            second, staged = _stage(self.root, bundle, self.key, config)
            retry, reused = _stage(self.root, bundle, self.key, config)
        self.assertNotEqual(first, second)
        self.assertEqual(retry, second)
        self.assertEqual(reused, staged)
        self.assertTrue((self.root / "vessel-releases" / second / "bundle").is_dir())

    def test_retry_rejects_unverified_existing_stage(self) -> None:
        bundle = self.parent / "bundle"
        bundle.mkdir()
        (bundle / "release-manifest.json").write_text("{}")
        config = self.parent / "config"
        config.write_text("{}")
        config.chmod(0o644)
        candidate = self.root / "vessel-releases" / ("2" * 24)
        candidate.mkdir(parents=True)
        candidate.parent.chmod(0o700)
        with patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_installer._validate_console_config"), \
             patch("infrastructure.deploy.vessel_installer._release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_installer._verify_stage",
                   side_effect=VesselInstallError("invalid staged vessel release")):
            with self.assertRaisesRegex(VesselInstallError, "invalid staged"):
                _stage(self.root, bundle, self.key, config)
        self.assertEqual(list(candidate.iterdir()), [])

    def test_new_stage_refuses_insufficient_space_before_copy(self) -> None:
        bundle = self.parent / "large-bundle"
        (bundle / "model").mkdir(parents=True)
        (bundle / "model" / "weights.bin").write_bytes(b"fictional weights")
        config = self.parent / "config"
        config.write_text("{}")
        with patch("infrastructure.deploy.vessel_installer._candidate_release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_installer.shutil.disk_usage",
                   return_value=SimpleNamespace(free=128 * 1024 * 1024)), \
             patch("infrastructure.deploy.vessel_installer.shutil.copytree") as copy:
            with self.assertRaisesRegex(VesselInstallError, "insufficient space"):
                _stage(self.root, bundle, self.key, config)
            copy.assert_not_called()
        self.assertFalse((self.root / "vessel-releases" / ("2" * 24)).exists())

    def test_switch_requires_clean_stopped_inventory_before_stage(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory",
                   side_effect=VesselInstallError("runtime still present")), \
             patch("infrastructure.deploy.vessel_release_switch._stage") as stage:
            with self.assertRaisesRegex(VesselInstallError, "runtime still present"):
                self.switch(self.parent / "bundle", self.parent / "config")
            stage.assert_not_called()
        self.assertEqual(_read_state(self.root), self.current)

    def test_switch_requires_matching_recovery_before_stage(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   side_effect=VesselInstallError("live Core differs")), \
             patch("infrastructure.deploy.vessel_release_switch._stage") as stage:
            with self.assertRaisesRegex(VesselInstallError, "live Core differs"):
                self.switch(self.parent / "bundle", self.parent / "config")
            stage.assert_not_called()
        self.assertEqual(_read_state(self.root), self.current)

    def test_preupdate_receipt_must_name_active_installation(self) -> None:
        payload = {"installation_id": self.current["installation_id"],
                   "release": "2" * 24,
                   "data_volume": self.current["runtime"]["data_volume"]}
        with patch("infrastructure.deploy.vessel_release_switch.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_release_switch.restore_vessel_recovery_files") as restore:
            with self.assertRaisesRegex(VesselInstallError, "another installation"):
                _verify_preupdate_recovery(
                    self.current, self.receipt_args[0], self.receipt_args[1],
                    self.receipt_args[2], self.receipt_args[3],
                    self.receipt_args[4], self.receipt_args[5], self.root)
            restore.assert_not_called()

    def test_legacy_receipt_cannot_authorize_release_switch(self) -> None:
        payload = {"installation_id": self.current["installation_id"],
                   "release": self.current["active"], "schema": 1,
                   "data_volume": self.current["runtime"]["data_volume"]}
        with patch("infrastructure.deploy.vessel_release_switch.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_release_switch.restore_vessel_recovery_files") as restore:
            with self.assertRaisesRegex(VesselInstallError, "lacks Knowledge row digest"):
                _verify_preupdate_recovery(
                    self.current, self.receipt_args[0], self.receipt_args[1],
                    self.receipt_args[2], self.receipt_args[3],
                    self.receipt_args[4], self.receipt_args[5], self.root)
            restore.assert_not_called()

    def test_changed_live_core_file_refuses_verified_recovery(self) -> None:
        staging = self.parent / "staging"
        staging.mkdir(mode=0o700)
        payload = {"installation_id": self.current["installation_id"],
                   "release": self.current["active"],
                   "schema": 2, "knowledge_sha256": "d" * 64,
                   "data_volume": self.current["runtime"]["data_volume"],
                   "repository": str(self.parent / "repository"),
                   "sources": 1, "audit_count": 1,
                   "audit_tail_hash": "a" * 64,
                   "manifest_sha256": "b" * 64}

        def restored(receipt, key, password, restic, digest, destination):
            destination.mkdir()
            (destination / "roles.json").write_text("old policy")

        def live(state, destination):
            destination.mkdir()
            (destination / "roles.json").write_text("changed policy")
            return 1, (1, "a" * 64), "b" * 64

        with patch("infrastructure.deploy.vessel_release_switch.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_release_switch.restore_vessel_recovery_files",
                   side_effect=restored), \
             patch("infrastructure.deploy.vessel_release_switch._stage_core",
                   side_effect=live), \
             patch("infrastructure.deploy.vessel_release_switch.policy_directory_lock"):
            with self.assertRaisesRegex(VesselInstallError, "live Core differs"):
                _verify_preupdate_recovery(
                    self.current, self.receipt_args[0], self.receipt_args[1],
                    self.receipt_args[2], self.receipt_args[3],
                    self.receipt_args[4], staging, self.root)

    def test_matching_live_core_accepts_restic_metadata_exclusion(self) -> None:
        staging = self.parent / "staging"
        staging.mkdir(mode=0o700)
        payload = {"installation_id": self.current["installation_id"],
                   "release": self.current["active"],
                   "schema": 2, "knowledge_sha256": "d" * 64,
                   "data_volume": self.current["runtime"]["data_volume"],
                   "repository": str(self.parent / "repository"),
                   "sources": 1, "audit_count": 1,
                   "audit_tail_hash": "a" * 64,
                   "manifest_sha256": "b" * 64}

        def restored(receipt, key, password, restic, digest, destination):
            destination.mkdir()
            (destination / "roles.json").write_text("same policy")
            (destination / "postgres.dump").write_text("database")
            (destination / MANIFEST).write_text("restic metadata")

        def live(state, destination):
            destination.mkdir()
            (destination / "roles.json").write_text("same policy")
            return 1, (1, "a" * 64), "b" * 64

        with patch("infrastructure.deploy.vessel_release_switch.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_release_switch.restore_vessel_recovery_files",
                   side_effect=restored), \
             patch("infrastructure.deploy.vessel_release_switch._stage_core",
                   side_effect=live), \
             patch("infrastructure.deploy.vessel_release_switch.policy_directory_lock"):
            self.assertEqual(_verify_preupdate_recovery(
                self.current, self.receipt_args[0], self.receipt_args[1],
                self.receipt_args[2], self.receipt_args[3],
                self.receipt_args[4], staging, self.root), payload)

    def test_future_signed_contract_denies_switch_before_candidate_stage(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   return_value={"sources": 1, "passages": 1,
                                 "knowledge_sha256": "d" * 64}), \
             patch("infrastructure.deploy.vessel_installer.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": {"knowledge_schema": 2,
                                                   "core_state_schema": 1}}), \
             patch("infrastructure.deploy.vessel_installer._validate_console_config"), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_knowledge") as start:
            with self.assertRaisesRegex(BundleError, "unsupported vessel compatibility"):
                self.switch(self.parent / "bundle", self.parent / "config")
            start.assert_not_called()
        self.assertFalse((self.root / "vessel-releases" / ("2" * 24)).exists())
        self.assertEqual(_read_state(self.root), self.current)

    def test_rollback_requires_recorded_predecessor(self) -> None:
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage") as verify:
            with self.assertRaisesRegex(VesselInstallError, "no previous"):
                rollback_stopped_vessel_release(
                    self.root, self.key, self.crane, *self.receipt_args)
            verify.assert_not_called()

    def test_rollback_requires_current_recovery_before_activation(self) -> None:
        current = dict(self.current, previous="2" * 24)
        _write_state(self.root, current)
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   side_effect=VesselInstallError("live Core differs")), \
             patch("infrastructure.deploy.vessel_release_switch._activate_stopped") as activate:
            with self.assertRaisesRegex(VesselInstallError, "live Core differs"):
                rollback_stopped_vessel_release(
                    self.root, self.key, self.crane, *self.receipt_args)
            activate.assert_not_called()
        self.assertEqual(_read_state(self.root), current)

    def test_rollback_passes_verified_knowledge_digest_to_activation(self) -> None:
        current = dict(self.current, previous="2" * 24)
        _write_state(self.root, current)
        recovery = {"sources": 1, "passages": 2,
                    "knowledge_sha256": "d" * 64}
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory") as inventory, \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   return_value=recovery) as verify, \
             patch("infrastructure.deploy.vessel_release_switch._activate_stopped",
                   return_value={"result": "rolled-back"}) as activate:
            self.assertEqual(rollback_stopped_vessel_release(
                self.root, self.key, self.crane, *self.receipt_args),
                {"result": "rolled-back"})
        verify.assert_called_once_with(current, *self.receipt_args, self.root)
        self.assertEqual(inventory.call_count, 2)
        activate.assert_called_once_with(
            self.root, self.key, self.crane, current, "2" * 24,
            self.root / "vessel-releases" / ("2" * 24), "rolled-back", recovery)

    def test_partial_stage_discard_requires_signed_identity_and_clean_stop(self) -> None:
        candidate = self.root / "vessel-releases" / ("2" * 24)
        candidate.mkdir(parents=True, mode=0o700)
        candidate.parent.chmod(0o700)
        (candidate / "interrupted.tmp").write_text("partial")
        arguments = (self.root, self.key, self.parent / "bundle",
                     self.parent / "config")
        with self.assertRaisesRegex(VesselInstallError, "explicit"):
            discard_stopped_vessel_stage(*arguments)
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory",
                   side_effect=VesselInstallError("runtime still present")), \
             patch("infrastructure.deploy.vessel_release_switch._candidate_release_id") as identity:
            with self.assertRaisesRegex(VesselInstallError, "runtime still present"):
                discard_stopped_vessel_stage(*arguments, discard_stage=True)
            identity.assert_not_called()
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._candidate_release_id",
                   side_effect=VesselInstallError("unsigned candidate")):
            with self.assertRaisesRegex(VesselInstallError, "unsigned candidate"):
                discard_stopped_vessel_stage(*arguments, discard_stage=True)
        self.assertTrue(candidate.exists())
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._candidate_release_id",
                   return_value="2" * 24):
            result = discard_stopped_vessel_stage(*arguments, discard_stage=True)
        self.assertEqual(result["result"], "staged-candidate-discarded")
        self.assertFalse(candidate.exists())
        self.assertEqual(_read_state(self.root), self.current)

    def test_discard_protects_rollback_stage_and_rejects_symlink(self) -> None:
        self.current["previous"] = "2" * 24
        _write_state(self.root, self.current)
        candidate = self.root / "vessel-releases" / ("2" * 24)
        candidate.mkdir(parents=True, mode=0o700)
        candidate.parent.chmod(0o700)
        arguments = (self.root, self.key, self.parent / "bundle",
                     self.parent / "config")
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._candidate_release_id",
                   return_value="2" * 24):
            with self.assertRaisesRegex(VesselInstallError, "rollback"):
                discard_stopped_vessel_stage(*arguments, discard_stage=True)
        self.assertTrue(candidate.exists())
        self.current.pop("previous")
        _write_state(self.root, self.current)
        (candidate / "linked").symlink_to(self.parent / "outside")
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._candidate_release_id",
                   return_value="2" * 24):
            with self.assertRaisesRegex(VesselInstallError, "unsafe entry"):
                discard_stopped_vessel_stage(*arguments, discard_stage=True)
        self.assertTrue(candidate.exists())

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
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   return_value={"sources": 1, "passages": 1,
                                 "knowledge_sha256": "d" * 64}), \
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
                self.switch(self.parent / "bundle", self.parent / "config")
            start.assert_not_called()
            self.assertTrue(cleanup.call_args.kwargs["retain_data"])
            self.assertEqual(cleanup.call_args.args[3], self.knowledge.data_volume)
        self.assertEqual(_read_state(self.root), self.current)

    def test_knowledge_inventory_change_refuses_candidate_start(self) -> None:
        new_knowledge = KnowledgeVolumeHandle(
            "4" * 64, "sovereign-knowledge-" + "5" * 12 + "-socket",
            self.knowledge.data_volume, "sovereign-knowledge-" + "5" * 12,
            "f" * 32)
        stage = self.root / "vessel-releases" / ("2" * 24)
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   return_value={"sources": 1, "passages": 1,
                                 "knowledge_sha256": "d" * 64}), \
             patch("infrastructure.deploy.vessel_release_switch._release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_release_switch._stage",
                   return_value=("2" * 24, stage)), \
             patch("infrastructure.deploy.vessel_release_switch.policy_directory_lock"), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_knowledge",
                   return_value=new_knowledge), \
             patch("infrastructure.deploy.vessel_release_switch._verify_knowledge_schema"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_database",
                   return_value={"sources": 2, "passages": 1,
                                 "knowledge_sha256": "d" * 64}), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_vessel_services") as start, \
             patch("infrastructure.deploy.vessel_release_switch._cleanup_failed_install",
                   return_value=True):
            with self.assertRaisesRegex(VesselInstallError, "Knowledge differs"):
                self.switch(self.parent / "bundle", self.parent / "config")
            start.assert_not_called()
        self.assertEqual(_read_state(self.root), self.current)

    def test_same_count_knowledge_row_change_refuses_candidate_start(self) -> None:
        new_knowledge = KnowledgeVolumeHandle(
            "4" * 64, "sovereign-knowledge-" + "5" * 12 + "-socket",
            self.knowledge.data_volume, "sovereign-knowledge-" + "5" * 12,
            "f" * 32)
        stage = self.root / "vessel-releases" / ("2" * 24)
        with patch("infrastructure.deploy.vessel_release_switch._verify_stage"), \
             patch("infrastructure.deploy.vessel_release_switch._state_options"), \
             patch("infrastructure.deploy.vessel_release_switch._recovery_inventory"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_preupdate_recovery",
                   return_value={"sources": 1, "passages": 1,
                                 "knowledge_sha256": "d" * 64}), \
             patch("infrastructure.deploy.vessel_release_switch._release_id",
                   return_value="2" * 24), \
             patch("infrastructure.deploy.vessel_release_switch._stage",
                   return_value=("2" * 24, stage)), \
             patch("infrastructure.deploy.vessel_release_switch.policy_directory_lock"), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_knowledge",
                   return_value=new_knowledge), \
             patch("infrastructure.deploy.vessel_release_switch._verify_knowledge_schema"), \
             patch("infrastructure.deploy.vessel_release_switch._verify_database",
                   return_value={"sources": 1, "passages": 1,
                                 "knowledge_sha256": "e" * 64}), \
             patch("infrastructure.deploy.vessel_release_switch.start_signed_vessel_services") as start, \
             patch("infrastructure.deploy.vessel_release_switch._cleanup_failed_install",
                   return_value=True):
            with self.assertRaisesRegex(VesselInstallError, "Knowledge differs"):
                self.switch(self.parent / "bundle", self.parent / "config")
            start.assert_not_called()
        self.assertEqual(_read_state(self.root), self.current)


if __name__ == "__main__":
    unittest.main()
