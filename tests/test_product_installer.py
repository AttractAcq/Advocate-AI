from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import RuntimeError as ContainerRuntimeError, RuntimeHandle
from infrastructure.deploy.product_installer import (
    ProductInstallError, install_product, product_status, recover_product,
    refresh_emergency_product, restore_install_product, rollback_product,
)
from services.knowledge.upload_staging import stage_upload
from services.policy.audit import AuditLog, verify as verify_audit


class ProductInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "install"
        self.key = self.base / "trusted.pem"
        self.crane = self.base / "crane"
        self.config = self.base / "console-config.json"
        self.config.write_text('{"schema":1,"oidc_issuer":null}')
        self.first = self.base / "first"
        self.second = self.base / "second"
        for bundle, version in ((self.first, b"first"), (self.second, b"second")):
            bundle.mkdir()
            (bundle / "release-manifest.json").write_bytes(version)
        self.old = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        self.new = RuntimeHandle("d" * 64, "e" * 64, "f" * 64)

    def _external_state(self) -> tuple[Path, Path]:
        state = self.base / "restored-state"
        state.mkdir(mode=0o700)
        (state / "sources").mkdir()
        for name in ("roles.json", "manifest.csv", "history.db"):
            item = state / name
            item.write_text("synthetic")
            item.chmod(0o600)
        credential = self.base / "lab-password"
        credential.write_text("synthetic-passphrase\n")
        credential.chmod(0o600)
        return state, credential

    def test_external_state_persists_through_upgrade_and_recovery(self) -> None:
        state, credential = self._external_state()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new, self.old, self.new]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.verify_runtime_identity"), \
             patch("infrastructure.deploy.product_installer.stop_runtime"):
            first = install_product(self.first, self.key, self.crane, self.config,
                                    self.root, state, credential)
            mount_record = json.loads((self.root / "product-core-mount.json").read_text())
            self.assertEqual(mount_record["state"], str(state.resolve()))
            self.assertEqual(mount_record["credential"], str(credential.resolve()))
            self.assertEqual((self.root / "product-core-mount.json").stat().st_mode & 0o077, 0)
            self.assertEqual(verify_audit(state / "audit.jsonl")[0], 1)
            install_product(self.second, self.key, self.crane, self.config, self.root)
            self.assertEqual(rollback_product(self.root, self.key, self.crane)["active"],
                             first["active"])
            probe.side_effect = ContainerRuntimeError("stopped")
            self.assertEqual(recover_product(self.root, self.key, self.crane)["result"],
                             "recovered")
            self.assertEqual(start.call_count, 4)
            for call in start.call_args_list:
                self.assertEqual(call.kwargs["core_state"], state.resolve())
                self.assertEqual(call.kwargs["lab_password_file"], credential.resolve())
            self.assertEqual(probe.call_args.args[1:],
                             (state.resolve(), credential.resolve(), None))
            (state / "audit.jsonl").unlink()
            with self.assertRaisesRegex(ProductInstallError, "audit trail"):
                product_status(self.root, self.key)

    def test_upload_quarantine_is_pinned_across_release_changes(self) -> None:
        state, credential = self._external_state()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new, self.old, self.new]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.verify_runtime_identity"), \
             patch("infrastructure.deploy.product_installer.stop_runtime"):
            first = install_product(self.first, self.key, self.crane, self.config,
                                    self.root, state, credential, enable_uploads=True)
            upload_root = (self.root / "product-uploads").resolve()
            record = json.loads((self.root / "product-core-mount.json").read_text())
            self.assertEqual(record["schema"], 3)
            self.assertEqual(record["upload_root"], str(upload_root))
            self.assertEqual(upload_root.stat().st_mode & 0o777, 0o700)
            install_product(self.second, self.key, self.crane, self.config, self.root)
            self.assertEqual(rollback_product(self.root, self.key, self.crane)["active"], first["active"])
            probe.side_effect = ContainerRuntimeError("stopped")
            self.assertEqual(recover_product(self.root, self.key, self.crane)["result"], "recovered")
            for call in start.call_args_list:
                self.assertEqual(call.kwargs["upload_root"], upload_root)
            self.assertEqual(probe.call_args.kwargs["upload_root"], upload_root)
            upload_root.rename(self.root / "moved-uploads")
            with self.assertRaises(ProductInstallError):
                product_status(self.root, self.key)

    def test_uploads_cannot_be_attached_to_existing_legacy_install(self) -> None:
        state, credential = self._external_state()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime"):
            install_product(self.first, self.key, self.crane, self.config,
                            self.root, state, credential)
            with self.assertRaises(ProductInstallError):
                install_product(self.second, self.key, self.crane, self.config,
                                self.root, enable_uploads=True)
            self.assertEqual(start.call_count, 1)
            self.assertFalse((self.root / "product-uploads").exists())

    def test_emergency_secret_persists_and_mount_record_rejects_tampering(self) -> None:
        state, credential = self._external_state()
        emergency = self.base / "emergency-password"
        emergency.write_text(secrets.token_urlsafe(24) + "\n")
        emergency.chmod(0o600)
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.stop_runtime"):
            install_product(self.first, self.key, self.crane, self.config,
                            self.root, state, credential, emergency)
            record = self.root / "product-core-mount.json"
            self.assertEqual(json.loads(record.read_text())["emergency_credential"],
                             str(emergency.resolve()))
            install_product(self.second, self.key, self.crane, self.config, self.root)
            self.assertEqual(start.call_args.kwargs["emergency_password_file"],
                             emergency.resolve())
            self.assertEqual(probe.call_args.args[3], emergency.resolve())
            tampered = json.loads(record.read_text())
            tampered["emergency_credential"] = str(self.base / "missing")
            record.write_text(json.dumps(tampered))
            with self.assertRaises(ProductInstallError):
                product_status(self.root, self.key)

    def test_refresh_rebinds_emergency_credential_and_preserves_failed_candidate(self) -> None:
        state, credential = self._external_state()
        emergency = self.base / "emergency-password"
        emergency.write_text(secrets.token_urlsafe(24) + "\n")
        emergency.chmod(0o600)
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new, self.old]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.stop_runtime") as stop:
            first = install_product(self.first, self.key, self.crane, self.config,
                                    self.root, state, credential, emergency)
            rotated = secrets.token_urlsafe(24)
            replacement = self.base / "replacement"
            replacement.write_text(rotated + "\n")
            replacement.chmod(0o600)
            replacement.replace(emergency)
            result = refresh_emergency_product(self.root, self.key, self.crane)
            self.assertEqual(result["result"], "emergency_credential_refreshed")
            self.assertEqual(result["active"], first["active"])
            self.assertEqual(start.call_args.kwargs["emergency_password_file"],
                             emergency.resolve())
            self.assertEqual(probe.call_args.args[0], self.new)
            stop.assert_called_once_with(self.old)
            active = (self.root / "product-state.json").read_bytes()
            probe.reset_mock()
            probe.side_effect = [None, ContainerRuntimeError("candidate invalid")]
            with self.assertRaises(ContainerRuntimeError):
                refresh_emergency_product(self.root, self.key, self.crane)
            self.assertEqual((self.root / "product-state.json").read_bytes(), active)
            self.assertEqual(stop.call_args.args[0], self.old)

    def test_refresh_requires_preconfigured_emergency_credential(self) -> None:
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old) as start:
            install_product(self.first, self.key, self.crane, self.config, self.root)
            with self.assertRaisesRegex(ProductInstallError, "no emergency credential"):
                refresh_emergency_product(self.root, self.key, self.crane)
            start.assert_called_once()

    def test_late_mount_change_and_tampered_mount_record_fail_closed(self) -> None:
        state, credential = self._external_state()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old), \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe:
            install_product(self.first, self.key, self.crane, self.config, self.root)
            with self.assertRaises(ProductInstallError):
                install_product(self.second, self.key, self.crane, self.config,
                                self.root, state, credential)
            self.assertFalse((self.root / "product-core-mount.json").exists())
            probe.assert_not_called()
        record = self.root / "product-core-mount.json"
        record.symlink_to(credential)
        with patch("infrastructure.deploy.product_installer.probe_runtime") as probe:
            with self.assertRaises(ProductInstallError):
                product_status(self.root, self.key)
            probe.assert_not_called()

    def test_restore_install_activates_only_after_clean_state(self) -> None:
        _, credential = self._external_state()
        repository = self.base / "repository"
        password = self.base / "restic-password"
        restic = self.base / "restic"
        snapshot_id = "a" * 64

        def restore(_snapshot, _repository, _password, _restic, _digest,
                    destination: Path) -> dict[str, object]:
            destination.mkdir(mode=0o700)
            (destination / "sources").mkdir()
            for name in ("roles.json", "manifest.csv", "history.db"):
                item = destination / name
                item.write_text("synthetic")
                item.chmod(0o600)
            return {"files": 4}

        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.restore_snapshot",
                   side_effect=restore) as restored, \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old) as started:
            with self.assertRaisesRegex(ProductInstallError, "snapshot contents"):
                restore_install_product(self.first, self.key, self.crane,
                    self.config, self.root, snapshot_id, repository, password, restic,
                    "b" * 64, credential, require_audit=True)
            self.assertFalse(self.root.exists())
            started.assert_not_called()
            result = restore_install_product(self.first, self.key, self.crane,
                self.config, self.root, snapshot_id, repository, password, restic,
                "b" * 64, credential)
            self.assertEqual(result["snapshot_id"], snapshot_id)
            self.assertEqual(result["restored_files"], 4)
            self.assertEqual(restored.call_count, 2)
            self.assertEqual(started.call_args.kwargs["core_state"],
                             (self.root / "core-state").resolve())

    def test_audit_checkpoint_is_checked_before_runtime_activation(self) -> None:
        _, credential = self._external_state()
        seed = self.base / "audit-seed.jsonl"
        AuditLog(seed).append(actor="synthetic-installer", action="install",
                              resource="core-state", decision="allow",
                              policy_version="a" * 64)
        checkpoint = verify_audit(seed)

        def restore(_snapshot, _repository, _password, _restic, _digest,
                    destination: Path) -> dict[str, object]:
            destination.mkdir(mode=0o700)
            (destination / "sources").mkdir()
            for name in ("roles.json", "manifest.csv", "history.db"):
                item = destination / name
                item.write_text("synthetic")
                item.chmod(0o600)
            shutil.copyfile(seed, destination / "audit.jsonl")
            (destination / "audit.jsonl").chmod(0o600)
            (destination / "sources" / "ENG-001.txt").write_bytes(b"fictional")
            with (destination / "manifest.csv").open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(("document_id", "relative_path", "collection", "classification",
                                 "version", "sha256", "owner", "source_type"))
                writer.writerow(("ENG-001", "sources/ENG-001.txt", "engineering",
                                 "C0_SYNTHETIC", "1", hashlib.sha256(b"fictional").hexdigest(),
                                 "fictional", "synthetic-local"))
            (destination / "manifest.csv").chmod(0o600)
            return {"files": 5}

        args = (self.first, self.key, self.crane, self.config, self.root,
                "a" * 64, self.base / "repository", self.base / "password",
                self.base / "restic", "b" * 64, credential)
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.restore_snapshot",
                   side_effect=restore), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old) as started:
            with self.assertRaisesRegex(ProductInstallError, "checkpoint mismatch"):
                restore_install_product(*args, require_audit=True,
                                        audit_checkpoint=(1, "0" * 64))
            started.assert_not_called()
            self.assertFalse(self.root.exists())
            result = restore_install_product(*args, require_audit=True,
                                             audit_checkpoint=checkpoint)
            self.assertEqual(result["restored_files"], 5)
            started.assert_called_once()

    def test_restore_install_rejects_existing_root_and_failed_restore(self) -> None:
        _, credential = self._external_state()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.restore_snapshot",
                   side_effect=ValueError("corrupt snapshot")) as restored, \
             patch("infrastructure.deploy.product_installer.start_verified_bundle") as started:
            with self.assertRaises(ValueError):
                restore_install_product(self.first, self.key, self.crane, self.config,
                    self.root, "a" * 64, self.base / "repository", self.base / "password",
                    self.base / "restic", "b" * 64, credential)
            self.assertFalse(self.root.exists())
            started.assert_not_called()
            self.root.mkdir(mode=0o700)
            with self.assertRaises(ProductInstallError):
                restore_install_product(self.first, self.key, self.crane, self.config,
                    self.root, "a" * 64, self.base / "repository", self.base / "password",
                    self.base / "restic", "b" * 64, credential)
            self.assertEqual(restored.call_count, 1)

    def test_restore_install_mounts_checked_upload_snapshot_before_start(self) -> None:
        _, credential = self._external_state()
        snapshot_id = "a" * 64
        upload_id = "c" * 64
        core_repository = self.base / "core-repository"
        upload_repository = self.base / "upload-repository"

        def core_restore(_snapshot, _repository, _password, _restic, _digest,
                         destination: Path) -> dict[str, object]:
            destination.mkdir(mode=0o700)
            (destination / "sources").mkdir()
            for name in ("roles.json", "manifest.csv", "history.db"):
                item = destination / name
                item.write_text("synthetic")
                item.chmod(0o600)
            return {"files": 4}

        def upload_restore(_snapshot, _repository, _password, _restic, _digest,
                           destination: Path) -> dict[str, object]:
            self.assertEqual(_snapshot, upload_id)
            self.assertEqual(_repository, upload_repository)
            destination.mkdir(mode=0o700)
            stage_upload(destination, "lab-engineer", "fictional.txt", b"fictional document")
            return {"quarantine_files": 2}

        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.restore_snapshot",
                   side_effect=core_restore), \
             patch("infrastructure.deploy.product_installer.restore_upload_snapshot",
                   side_effect=upload_restore) as uploads_restored, \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old) as started:
            result = restore_install_product(self.first, self.key, self.crane,
                self.config, self.root, snapshot_id, core_repository,
                self.base / "password", self.base / "restic", "b" * 64,
                credential, enable_uploads=True, upload_snapshot_id=upload_id,
                upload_repository=upload_repository,
                upload_password_file=self.base / "upload-password")
        self.assertEqual(result["upload_snapshot_id"], upload_id)
        self.assertEqual(result["restored_upload_files"], 2)
        uploads_restored.assert_called_once()
        self.assertEqual(started.call_args.kwargs["upload_root"],
                         (self.root / "product-uploads").resolve())
        self.assertEqual(len(list((self.root / "product-uploads").glob("*.blob"))), 1)

    def test_restore_install_refuses_partial_or_failed_upload_restore(self) -> None:
        _, credential = self._external_state()
        base_args = (self.first, self.key, self.crane, self.config, self.root,
                     "a" * 64, self.base / "core-repository",
                     self.base / "password", self.base / "restic", "b" * 64,
                     credential)
        with self.assertRaisesRegex(ProductInstallError, "upload restore requires"):
            restore_install_product(*base_args, enable_uploads=True,
                                    upload_snapshot_id="c" * 64)
        self.assertFalse(self.root.exists())
        with self.assertRaisesRegex(ProductInstallError, "separate repository"):
            restore_install_product(*base_args, enable_uploads=True,
                upload_snapshot_id="c" * 64,
                upload_repository=self.base / "core-repository",
                upload_password_file=self.base / "password")
        self.assertFalse(self.root.exists())
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.restore_snapshot",
                   return_value={"files": 4}), \
             patch("infrastructure.deploy.product_installer.restore_upload_snapshot",
                   side_effect=ValueError("corrupt quarantine")), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle") as started:
            with self.assertRaisesRegex(ValueError, "corrupt quarantine"):
                restore_install_product(*base_args, enable_uploads=True,
                    upload_snapshot_id="c" * 64,
                    upload_repository=self.base / "upload-repository",
                    upload_password_file=self.base / "upload-password")
            self.assertFalse(self.root.exists())
            started.assert_not_called()

    def test_activate_then_rollback_and_idempotence(self) -> None:
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new, self.old]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.stop_runtime") as stop:
            first = install_product(self.first, self.key, self.crane, self.config, self.root)
            self.assertEqual(first["result"], "activated")
            self.assertEqual(product_status(self.root, self.key)["active"], first["active"])
            self.assertEqual(install_product(self.first, self.key, self.crane,
                                             self.config, self.root)["result"], "unchanged")
            second = install_product(self.second, self.key, self.crane,
                                     self.config, self.root)
            self.assertEqual(second["previous"], first["active"])
            self.assertEqual(stop.call_args.args[0], self.old)
            rolled = rollback_product(self.root, self.key, self.crane)
            self.assertEqual(rolled["active"], first["active"])
            self.assertEqual(rolled["previous"], second["active"])
            self.assertEqual(stop.call_args.args[0], self.new)
            self.assertEqual(start.call_count, 3)
            self.assertGreaterEqual(probe.call_count, 3)

    def test_failed_candidate_and_state_write_preserve_previous(self) -> None:
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.probe_runtime"), \
             patch("infrastructure.deploy.product_installer.stop_runtime") as stop:
            with patch("infrastructure.deploy.product_installer.start_verified_bundle",
                       return_value=self.old):
                first = install_product(self.first, self.key, self.crane,
                                        self.config, self.root)
            with patch("infrastructure.deploy.product_installer.start_verified_bundle",
                       side_effect=ValueError("candidate failed")):
                with self.assertRaises(ValueError):
                    install_product(self.second, self.key, self.crane,
                                    self.config, self.root)
            self.assertEqual(product_status(self.root, self.key)["active"], first["active"])
            stop.assert_not_called()
            with patch("infrastructure.deploy.product_installer.start_verified_bundle",
                       return_value=self.new), \
                 patch("infrastructure.deploy.product_installer._write_state",
                       side_effect=OSError("state write failed")):
                with self.assertRaises(OSError):
                    install_product(self.second, self.key, self.crane,
                                    self.config, self.root)
            self.assertEqual(product_status(self.root, self.key)["active"], first["active"])
            stop.assert_called_once_with(self.new)

    def test_rejects_tampered_state_before_using_docker_ids(self) -> None:
        self.root.mkdir(mode=0o700)
        state = self.root / "product-state.json"
        state.write_text(json.dumps({"schema": 1, "active": "a" * 24,
                                     "previous": None,
                                     "runtime": {"network_id": "../other",
                                                 "core_id": "b" * 64,
                                                 "console_id": "c" * 64}}))
        state.chmod(0o600)
        with patch("infrastructure.deploy.product_installer.probe_runtime") as probe:
            with self.assertRaises(ProductInstallError):
                product_status(self.root, self.key)
            probe.assert_not_called()

    def test_recover_unhealthy_runtime_from_signed_staged_release(self) -> None:
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=[self.old, self.new]) as start, \
             patch("infrastructure.deploy.product_installer.probe_runtime") as probe, \
             patch("infrastructure.deploy.product_installer.verify_runtime_identity"), \
             patch("infrastructure.deploy.product_installer.stop_runtime") as stop:
            first = install_product(self.first, self.key, self.crane, self.config,
                                    self.root)
            self.assertEqual(recover_product(self.root, self.key, self.crane)["result"],
                             "already_healthy")
            self.assertEqual(start.call_count, 1)
            probe.side_effect = ContainerRuntimeError("stopped")
            restored = recover_product(self.root, self.key, self.crane)
            self.assertEqual(restored["result"], "recovered")
            self.assertEqual(restored["active"], first["active"])
            self.assertEqual(start.call_count, 2)
            self.assertEqual(json.loads((self.root / "product-state.json").read_text())
                             ["runtime"]["core_id"], self.new.core_id)
            stop.assert_called_once_with(self.old)

    def test_failed_recovery_keeps_original_record(self) -> None:
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   return_value=self.old):
            install_product(self.first, self.key, self.crane, self.config, self.root)
        original = (self.root / "product-state.json").read_bytes()
        with patch("infrastructure.deploy.product_installer.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_installer.probe_runtime",
                   side_effect=ContainerRuntimeError("stopped")), \
             patch("infrastructure.deploy.product_installer.verify_runtime_identity"), \
             patch("infrastructure.deploy.product_installer.start_verified_bundle",
                   side_effect=ContainerRuntimeError("candidate failed")), \
             patch("infrastructure.deploy.product_installer.stop_runtime") as stop:
            with self.assertRaises(ContainerRuntimeError):
                recover_product(self.root, self.key, self.crane)
            self.assertEqual((self.root / "product-state.json").read_bytes(), original)
            stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
