from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import BundleError, create_product_bundle, verify_bundle
from infrastructure.release.intake import IntakeError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ProductBundleTests(unittest.TestCase):
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
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        self.trusted.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle"
        self.images: dict[str, dict[str, str]] = {}
        for role in ("core", "console"):
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

    def intake(self, scan: Path, sbom: Path, *args: object, **kwargs: object) -> dict[str, str]:
        role = scan.name.split("-", 1)[0]
        return {"archive_sha256": self.images[role]["archive_sha256"]}

    def identity(self, archive: Path, *args: object) -> dict[str, str]:
        return {"archive_sha256": digest(archive.read_bytes())}

    def test_signs_and_verifies_both_evidenced_images(self) -> None:
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake), \
             patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            manifest = create_product_bundle(self.payload, self.bundle, self.private,
                                             "0.1.0", self.images, crane=self.root / "crane")
            self.assertEqual(manifest["schema"], 4)
            self.assertEqual(set(verify_bundle(self.bundle, self.trusted)["images"]),
                             {"core", "console"})
        (self.bundle / "images" / "console.tar").write_bytes(b"tampered")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.trusted)

    def test_missing_extra_or_denied_image_prevents_bundle(self) -> None:
        with self.assertRaises(BundleError):
            create_product_bundle(self.payload, self.bundle, self.private,
                                  "0.1.0", {"core": self.images["core"]},
                                  crane=self.root / "crane")
        (self.payload / "images" / "extra.tar").write_bytes(b"unreviewed")
        with self.assertRaises(BundleError):
            create_product_bundle(self.payload, self.bundle, self.private,
                                  "0.1.0", self.images, crane=self.root / "crane")
        (self.payload / "images" / "extra.tar").unlink()

        def deny_console(scan: Path, sbom: Path, *args: object, **kwargs: object) -> dict[str, str]:
            if scan.name.startswith("console-"):
                raise IntakeError("unresolved high, critical or unknown findings: 1")
            return self.intake(scan, sbom, *args, **kwargs)

        with patch("infrastructure.release.bundle.verify_intake", side_effect=deny_console), \
             patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            with self.assertRaises(IntakeError):
                create_product_bundle(self.payload, self.bundle, self.private,
                                      "0.1.0", self.images, crane=self.root / "crane")
        self.assertFalse(self.bundle.exists())


if __name__ == "__main__":
    unittest.main()
