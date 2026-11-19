from __future__ import annotations

import json
import csv
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.product_recovery_set import (
    RecoverySetError, _require_stopped, create_product_recovery_set,
    restore_product_recovery_set, verify_product_recovery_set,
)
from services.policy.audit import AuditLog, verify as verify_audit
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
        for name in ("roles.json", "history.db"):
            (state / name).write_text("synthetic")
        AuditLog(state / "audit.jsonl").append(
            actor="synthetic-installer", action="install", resource="core-state",
            decision="allow", policy_version="a" * 64)
        (state / "sources" / "ENG-001.txt").write_text("fictional")
        with (state / "manifest.csv").open("w", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("document_id", "relative_path", "collection", "classification",
                             "version", "sha256", "owner", "source_type"))
            writer.writerow(("ENG-001", "sources/ENG-001.txt", "engineering", "C0_SYNTHETIC",
                             "1", hashlib.sha256(b"fictional").hexdigest(), "fictional", "synthetic-local"))
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
                                          "history.db", "audit.jsonl",
                                          "sources/ENG-001.txt"})
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
        self.assertEqual((result["audit_count"], result["audit_tail_hash"]),
                         verify_audit(self.install / "core-state" / "audit.jsonl"))
        self.assertEqual(verify_product_recovery_set(self.receipt, self.public_key), result)
        self.assertEqual(self.receipt.stat().st_mode & 0o077, 0)

    def test_indexed_knowledge_pair_is_included_in_core_snapshot(self) -> None:
        state = self.install / "core-state"
        (state / "knowledge-manifest.json").write_text('{"schema":1,"sources":[]}')
        (state / "knowledge.db").write_bytes(b"synthetic")
        def core(spec: Path, *_args) -> dict[str, object]:
            names = {row["name"] for row in json.loads(spec.read_text())["files"]}
            self.assertEqual(names, {"roles.json", "manifest.csv", "history.db",
                                     "audit.jsonl", "sources/ENG-001.txt",
                                     "knowledge-manifest.json", "knowledge.db"})
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   side_effect=core), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            self._create()

    def test_manifest_inventory_captures_all_sources(self) -> None:
        state = self.install / "core-state"
        with (state / "manifest.csv").open("a", newline="") as stream:
            writer = csv.writer(stream)
            for index in range(2, 101):
                name = f"ENG-{index:03d}.txt"
                payload = f"fictional source {index}".encode()
                (state / "sources" / name).write_bytes(payload)
                writer.writerow((f"ENG-{index:03d}", f"sources/{name}", "engineering",
                                 "C0_SYNTHETIC", "1", hashlib.sha256(payload).hexdigest(),
                                 "fictional", "synthetic-local"))
        def core(spec: Path, *_args) -> dict[str, object]:
            names = {row["name"] for row in json.loads(spec.read_text())["files"]}
            self.assertEqual(len(names), 104)
            self.assertIn("sources/ENG-100.txt", names)
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot", side_effect=core), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            self._create()

    def test_manifest_inventory_rejects_changed_missing_and_extra_sources(self) -> None:
        state = self.install / "core-state"
        source = state / "sources" / "ENG-001.txt"
        for mutation in (lambda: source.write_text("changed"), source.unlink,
                         lambda: (state / "sources" / "EXTRA.txt").write_text("extra")):
            source.write_text("fictional")
            mutation()
            with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
                 patch("infrastructure.deploy.product_recovery_set.create_snapshot") as backup:
                with self.assertRaises(ValueError):
                    self._create()
            backup.assert_not_called()
            (state / "sources" / "EXTRA.txt").unlink(missing_ok=True)

    def test_capture_uses_private_frozen_manifest_and_source(self) -> None:
        state = self.install / "core-state"
        def core(spec: Path, *_args) -> dict[str, object]:
            rows = {row["name"]: Path(row["source"])
                    for row in json.loads(spec.read_text())["files"]}
            for name in ("manifest.csv", "sources/ENG-001.txt"):
                self.assertNotEqual(rows[name], state / name)
                self.assertEqual(rows[name].read_bytes(), (state / name).read_bytes())
                self.assertEqual(rows[name].stat().st_mode & 0o077, 0)
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot", side_effect=core), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            self._create()
        self.assertTrue(self.receipt.is_file())

    def test_live_source_change_during_capture_leaves_no_receipt(self) -> None:
        state = self.install / "core-state"
        def core(spec: Path, *_args) -> dict[str, object]:
            rows = {row["name"]: Path(row["source"])
                    for row in json.loads(spec.read_text())["files"]}
            (state / "sources" / "ENG-001.txt").write_text("changed during capture")
            self.assertEqual(rows["sources/ENG-001.txt"].read_bytes(), b"fictional")
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot", side_effect=core), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                self._create()
        self.assertFalse(self.receipt.exists())

    def test_live_manifest_change_during_capture_leaves_no_receipt(self) -> None:
        state = self.install / "core-state"
        def core(spec: Path, *_args) -> dict[str, object]:
            rows = {row["name"]: Path(row["source"])
                    for row in json.loads(spec.read_text())["files"]}
            with (state / "manifest.csv").open("a") as stream:
                stream.write("\n")
            self.assertNotEqual(rows["manifest.csv"].read_bytes(),
                                (state / "manifest.csv").read_bytes())
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot", side_effect=core), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            with self.assertRaisesRegex(RecoverySetError, "manifest changed"):
                self._create()
        self.assertFalse(self.receipt.exists())

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

    def test_missing_or_tampered_audit_prevents_capture(self) -> None:
        audit = self.install / "core-state" / "audit.jsonl"
        for mutation in (lambda: audit.unlink(),
                         lambda: audit.write_text("tampered\n")):
            if not audit.exists():
                AuditLog(audit).append(actor="synthetic-installer", action="install",
                                       resource="core-state", decision="allow",
                                       policy_version="a" * 64)
            mutation()
            with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
                 patch("infrastructure.deploy.product_recovery_set.create_snapshot") as backup:
                with self.assertRaisesRegex(ValueError, "audit"):
                    self._create()
            backup.assert_not_called()
            self.assertFalse(self.receipt.exists())

    def test_audit_change_during_capture_leaves_no_signed_receipt(self) -> None:
        audit = self.install / "core-state" / "audit.jsonl"
        def change_audit(*_args) -> dict[str, object]:
            AuditLog(audit).append(actor="synthetic-installer", action="changed",
                                   resource="core-state", decision="allow",
                                   policy_version="a" * 64)
            return {"snapshot_id": "1" * 64}
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   side_effect=change_audit), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            with self.assertRaisesRegex(RecoverySetError, "changed during capture"):
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
                                completed(1, err="not found"),
                                completed(0),
                                completed(0, "false")]):
            _require_stopped(runtime)
        with patch("infrastructure.deploy.product_recovery_set.subprocess.run",
                   side_effect=[completed(0, "daemon"), completed(1),
                                completed(1, err="daemon lost")]):
            with self.assertRaisesRegex(RecoverySetError, "state unavailable"):
                _require_stopped(runtime)

    def test_restore_uses_only_signed_pair_and_matching_release(self) -> None:
        with patch("infrastructure.deploy.product_recovery_set._require_stopped"), \
             patch("infrastructure.deploy.product_recovery_set.create_snapshot",
                   return_value={"snapshot_id": "1" * 64}), \
             patch("infrastructure.deploy.product_recovery_set.create_upload_snapshot",
                   return_value={"snapshot_id": "2" * 64}):
            self._create()
        args = (self.receipt, self.public_key, self.base / "bundle",
                self.public_key, self.base / "crane", self.base / "config",
                self.base / "fresh-install", self.base / "core-password",
                self.base / "upload-password", self.base / "restic",
                "e" * 64, self.base / "lab-password")
        with patch("infrastructure.deploy.product_recovery_set.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_recovery_set._identifier",
                   return_value="f" * 24), \
             patch("infrastructure.deploy.product_recovery_set.restore_install_product") as install:
            with self.assertRaisesRegex(RecoverySetError, "does not match"):
                restore_product_recovery_set(*args)
            install.assert_not_called()
        with patch("infrastructure.deploy.product_recovery_set.verify_bundle",
                   return_value={"schema": 4}), \
             patch("infrastructure.deploy.product_recovery_set._identifier",
                   return_value="a" * 24), \
             patch("infrastructure.deploy.product_recovery_set.restore_install_product",
                   return_value={"active": "a" * 24}) as install:
            result = restore_product_recovery_set(*args)
            self.assertEqual(result["recovery_set"], "signed-pair-verified")
            self.assertEqual(install.call_args.args[5], "1" * 64)
            self.assertEqual(install.call_args.kwargs["upload_snapshot_id"], "2" * 64)
            self.assertEqual(install.call_args.kwargs["audit_checkpoint"],
                             verify_audit(self.install / "core-state" / "audit.jsonl"))


if __name__ == "__main__":
    unittest.main()
