"""Separate company-side release signatures cannot become vessel releases."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import BundleError, create_fleet_bundle, verify_bundle
from infrastructure.release.intake import IntakeError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FleetBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        (self.payload / "images").mkdir(parents=True)
        (self.payload / "evidence").mkdir()
        key = Ed25519PrivateKey.generate()
        self.private = self.root / "signing.pem"
        self.trusted = self.root / "trusted.pem"
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.trusted.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle"
        self.images: dict[str, dict[str, str]] = {}
        for role in ("fleet-api", "fleet-portal"):
            archive = self.payload / "images" / f"{role}.tar"
            scan = self.payload / "evidence" / f"{role}-scan.json"
            sbom = self.payload / "evidence" / f"{role}-sbom.json"
            archive.write_bytes((role + " archive").encode())
            scan.write_bytes((role + " scan").encode())
            sbom.write_bytes((role + " sbom").encode())
            self.images[role] = {
                "image_ref": f"registry.example.invalid/sovereign/{role}@sha256:{digest(archive.read_bytes())}",
                "archive_path": f"images/{role}.tar", "archive_sha256": digest(archive.read_bytes()),
                "crane_sha256": "a" * 64, "scan_path": f"evidence/{role}-scan.json",
                "scan_sha256": digest(scan.read_bytes()), "sbom_path": f"evidence/{role}-sbom.json",
                "sbom_sha256": digest(sbom.read_bytes()),
            }

    def intake(self, scan: Path, *args: object, **kwargs: object) -> dict[str, str]:
        role = scan.name.removesuffix("-scan.json")
        return {"archive_sha256": self.images[role]["archive_sha256"]}

    def identity(self, archive: Path, *args: object) -> dict[str, str]:
        return {"archive_sha256": digest(archive.read_bytes())}

    def test_sign_verify_and_reject_tamper(self) -> None:
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake), \
             patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            manifest = create_fleet_bundle(self.payload, self.bundle, self.private,
                                           "0.1.0", self.images, crane=self.root / "crane")
            self.assertEqual(manifest["schema"], 5)
            self.assertEqual(manifest["target"], "fleet")
            self.assertEqual(set(verify_bundle(self.bundle, self.trusted)["images"]),
                             {"fleet-api", "fleet-portal"})
        (self.bundle / "images" / "fleet-api.tar").write_bytes(b"tampered")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.trusted)

    def test_wrong_roles_extra_archive_and_denied_scan(self) -> None:
        with self.assertRaises(BundleError):
            create_fleet_bundle(self.payload, self.bundle, self.private,
                                "0.1.0", {"fleet-api": self.images["fleet-api"]},
                                crane=self.root / "crane")
        (self.payload / "images" / "core.tar").write_bytes(b"vessel")
        with self.assertRaises(BundleError):
            create_fleet_bundle(self.payload, self.bundle, self.private,
                                "0.1.0", self.images, crane=self.root / "crane")
        (self.payload / "images" / "core.tar").unlink()

        def deny_portal(scan: Path, *args: object, **kwargs: object):
            if scan.name.startswith("fleet-portal"):
                raise IntakeError("unresolved high finding")
            return self.intake(scan)

        with patch("infrastructure.release.bundle.verify_intake", side_effect=deny_portal), \
             patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            with self.assertRaises(IntakeError):
                create_fleet_bundle(self.payload, self.bundle, self.private,
                                    "0.1.0", self.images, crane=self.root / "crane")
        self.assertFalse(self.bundle.exists())


if __name__ == "__main__":
    unittest.main()
