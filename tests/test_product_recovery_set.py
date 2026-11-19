from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.product_recovery_set import (
    RecoverySetError, _require_stopped, create_product_recovery_set,
    verify_product_recovery_set,
)
from services.knowledge.upload_staging import stage_upload


class ProductRecoverySetTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.install = self.base / "product-install"
        self.install.mkdir(mode=0o700)
        state = self.install / "core-state"
        state.mkdir(mode=0o700)
        (state / "sources").mkdir()
        for name in ("roles.json", "manifest.csv", "history.db"):
            (state / name).write_text("synthetic")
        (state / "sources" / "ENG-001.txt").write_text("fictional")
        password = self.base / "lab-password"
        password.write_text("fictional-lab-password\n")
        password.chmod(0o600)
        uploads = self.install / "product-uploads"
        uploads.mkdir(mode=0o700)
        stage_upload(uploads, "lab-engineer", "fictional.txt", b"fictional upload")
        mount = self.install / "product-core-mount.json"
        mount.write_text(json.dumps({"schema": 3, "state": str(state),
                                     "credential": str(password),
                                     "emergency_credential": None,
                                     "upload_root": str(uploads)}))
        mount.chmod(0o600)
        (self.install / "product-state.json").write_text(json.dumps({
            "schema": 1, "active": "a" * 24, "previous": None,
            "runtime": {"network_id": "b" * 64, "core_id": "c" * 64,
                        "console_id": "d" * 64}}))
        (self.install / "product-state.json").chmod(0o600)
        self.staging = self.base / "staging"
        self.staging.mkdir(mode=0o700)
        self.private_key = self.base / "signing.pem"
        self.public_key = self.base / "trusted.pem"
        key = Ed25519PrivateKey.generate()
        self.private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.private_key.chmod(0o600)
        self.public_key.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.receipt = self.base / "recovery-set.json"

    def _create(self) -> dict[str, object]:
        return create_product_recovery_set(
            self.install, self.base / "core-repo", self.base / "upload-repo",
            self.base / "core-password", self.base / "upload-password",
            self.base / "restic", "e" * 64, self.staging,
            self.private_key, self.receipt)

    def test_signed_receipt_binds_two_snapshots_under_stopped_window(self) -> None:
        def core(spec: Path, *_args) -> dict[str, object]:
            names = [row["name"] for row in json.loads(spec.read_text())["files"]]
            self.assertEqual(set(names), {"roles.json", "manifest.csv",
                                          "history.db", "sources/ENG-001.txt"})
            return {"snapshot_id": "1" * 64}

        with patch("infrastructure.deploy.product_recovery_set._require_stopped") as stopped, \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   side_effect=core) as core_backup, \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}) as upload_backup:
            result = self._create()
        self.assertEqual(stopped.call_count, 3)
        core_backup.assert_called_once()
        upload_backup.assert_called_once()
        self.assertEqual(result["core_snapshot_id"], "1" * 64)
        self.assertEqual(result["upload_snapshot_id"], "2" * 64)
        self.assertEqual(verify_product_recovery_set(self.receipt, self.public_key), result)
        self.assertEqual(self.receipt.stat().st_mode & 0o077, 0)

    def test_running_product_or_second_backup_failure_leaves_no_receipt(self) -> None:
        with patch("infrastructure.deploy.product_recovery_set._require_stopped",
                   side_effect=RecoverySetError("runtime running")), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot") as backup:
            with self.assertRaisesRegex(RecoverySetError, "runtime running"):
                self._create()
        backup.assert_not_called()
        self.assertFalse(self.receipt.exists())
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   return_value={"snapshot_id": "1" * 64}), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   side_effect=ValueError("upload backup failed")):
            with self.assertRaisesRegex(ValueError, "upload backup failed"):
                self._create()
        self.assertFalse(self.receipt.exists())

    def test_tampered_receipt_is_rejected(self) -> None:
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   return_value={"snapshot_id": "1" * 64}), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            self._create()
        signed = json.loads(self.receipt.read_text())
        signed["signature"] = "A" * len(signed["signature"])
        self.receipt.write_text(json.dumps(signed))
        with self.assertRaisesRegex(RecoverySetError, "verification failed"):
            verify_product_recovery_set(self.receipt, self.public_key)

    def test_runtime_preflight_rejects_running_or_unavailable_daemon(self) -> None:
        runtime = {"core_id": "c" * 64, "console_id": "d" * 64}
        completed = lambda code, out="", err="": subprocess.CompletedProcess(
            [], code, stdout=out, stderr=err)
        with patch("infrastructure.deploy.product_recovery_set.subprocess.run",
                   side_effect=[completed(0, "daemon"), completed(0, "true")]):
            with self.assertRaisesRegex(RecoverySetError, "must be stopped"):
                _require_stopped(runtime)
        with patch("infrastructure.deploy.product_recovery_set.subprocess.run",
                   return_value=completed(1, err="daemon unavailable")):
            with self.assertRaisesRegex(RecoverySetError, "state unavailable"):
                _require_stopped(runtime)
        with patch("infrastructure.deploy.product_recovery_set.subprocess.run",
                   side_effect=[completed(0, "daemon"),
                                completed(1, err="No such object"),
                                completed(0, "false")]):
            _require_stopped(runtime)


if __name__ == "__main__":
    unittest.main()
