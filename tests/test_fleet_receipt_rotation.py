"""Synthetic signed Fleet receipt-trust rotation and interruption recovery."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.fleet_installer import (
    FleetInstallError, _provision_receipt_trust, _read_receipt_journal,
    _state, _write_receipt_journal, _write_state, fleet_status,
    recover_fleet, rotate_fleet_receipt_trust,
)
from infrastructure.deploy.fleet_runtime import FleetRuntime, _trust_digest


class FleetReceiptRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o700)
        self.root = self.base / "install"
        self.root.mkdir(mode=0o700)
        self.old = self._trust("old")
        self.new = self._trust("new")
        _provision_receipt_trust(self.root, self.old)
        self.old_digest = _trust_digest(self.root / "receipt-import")
        self.new_digest = _trust_digest(self.new)
        self.original = FleetRuntime("1" * 64, "2" * 64, "3" * 64)
        self.candidate = FleetRuntime("4" * 64, "5" * 64, "6" * 64)
        self.release = "a" * 24
        _write_state(self.root, self.release, None, self.original)

    def _trust(self, name: str) -> Path:
        root = self.base / name
        root.mkdir(mode=0o700)
        public = Ed25519PrivateKey.generate().public_key()
        key = root / "issuer-1.pem"
        key.write_bytes(public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        key.chmod(0o600)
        manifest = root / "trusted-issuers.json"
        manifest.write_text('["/etc/fleet-import/issuer-1.pem"]')
        manifest.chmod(0o600)
        return root

    def _journal_swap(self, *, committed: bool) -> None:
        current = _state(self.root)
        _write_receipt_journal(self.root, current,
                               self.old_digest, self.new_digest)
        os.rename(self.root / "receipt-import",
                  self.root / ".receipt-trust-previous")
        shutil.copytree(self.new, self.root / "receipt-import")
        if committed:
            _write_state(self.root, self.release, None, self.candidate)

    def test_rotates_signed_candidate_and_retires_previous_trust(self) -> None:
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                   return_value=self.candidate), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime") as stop:
            result = rotate_fleet_receipt_trust(
                self.root, self.base / "release.pem", self.base / "crane", self.new)
        self.assertEqual(result["result"], "receipt_trust_rotated")
        self.assertEqual(_state(self.root)["runtime"]["api_id"], self.candidate.api_id)
        self.assertEqual(_trust_digest(self.root / "receipt-import"), self.new_digest)
        self.assertFalse((self.root / ".receipt-trust-previous").exists())
        self.assertIsNone(_read_receipt_journal(self.root))
        stop.assert_called_once_with(self.original)

    def test_failed_candidate_restores_old_trust_and_state(self) -> None:
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                   side_effect=ValueError("candidate failed")):
            with self.assertRaisesRegex(ValueError, "candidate failed"):
                rotate_fleet_receipt_trust(
                    self.root, self.base / "release.pem", self.base / "crane", self.new)
        self.assertEqual(_state(self.root)["runtime"]["api_id"], self.original.api_id)
        self.assertEqual(_trust_digest(self.root / "receipt-import"), self.old_digest)
        self.assertIsNone(_read_receipt_journal(self.root))

    def test_changed_source_copy_is_rejected_before_rotation(self) -> None:
        original_copy = shutil.copytree

        def changed_copy(source, target, **options):
            result = original_copy(source, target, **options)
            replacement = Ed25519PrivateKey.generate().public_key()
            key = Path(target) / "issuer-1.pem"
            key.write_bytes(replacement.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            return result

        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.shutil.copytree",
                   side_effect=changed_copy):
            with self.assertRaisesRegex(FleetInstallError, "changed during staging"):
                rotate_fleet_receipt_trust(
                    self.root, self.base / "release.pem", self.base / "crane", self.new)
            fresh = self.base / "fresh-install"
            fresh.mkdir(mode=0o700)
            with self.assertRaisesRegex(FleetInstallError, "changed during provisioning"):
                _provision_receipt_trust(fresh, self.new)
            self.assertFalse((fresh / "receipt-import").exists())
        self.assertEqual(_trust_digest(self.root / "receipt-import"), self.old_digest)
        self.assertIsNone(_read_receipt_journal(self.root))

    def test_recover_precommit_restores_old_trust(self) -> None:
        self._journal_swap(committed=False)
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"):
            with self.assertRaises(FleetInstallError):
                fleet_status(self.root, self.base / "release.pem")
            result = recover_fleet(self.root, self.base / "release.pem",
                                   self.base / "crane")
        self.assertEqual(result["result"], "already_healthy")
        self.assertEqual(_trust_digest(self.root / "receipt-import"), self.old_digest)
        self.assertIsNone(_read_receipt_journal(self.root))

    def test_recover_postcommit_verifies_candidate_then_retires_old(self) -> None:
        self._journal_swap(committed=True)
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime") as stop:
            result = recover_fleet(self.root, self.base / "release.pem",
                                   self.base / "crane")
        self.assertEqual(result["result"], "already_healthy")
        self.assertEqual(_trust_digest(self.root / "receipt-import"), self.new_digest)
        self.assertFalse((self.root / ".receipt-trust-previous").exists())
        self.assertIsNone(_read_receipt_journal(self.root))
        stop.assert_called_once_with(self.original)

    def test_postcommit_cleanup_interruption_is_recoverable(self) -> None:
        self._journal_swap(committed=True)
        shutil.rmtree(self.root / ".receipt-trust-previous")
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime") as stop:
            recover_fleet(self.root, self.base / "release.pem", self.base / "crane")
        self.assertIsNone(_read_receipt_journal(self.root))
        stop.assert_called_once_with(self.original)

    def test_unhealthy_postcommit_candidate_keeps_journal(self) -> None:
        self._journal_swap(committed=True)
        with patch("infrastructure.deploy.fleet_installer._verify_stage"), \
             patch("infrastructure.deploy.fleet_installer.probe_runtime",
                   side_effect=ValueError("candidate unhealthy")), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime") as stop:
            with self.assertRaisesRegex(ValueError, "candidate unhealthy"):
                recover_fleet(self.root, self.base / "release.pem",
                              self.base / "crane")
        self.assertIsNotNone(_read_receipt_journal(self.root))
        self.assertTrue((self.root / ".receipt-trust-previous").exists())
        stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
