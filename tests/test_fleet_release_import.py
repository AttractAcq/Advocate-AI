"""Fleet records only a verified signed Core and Console product candidate."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import (
    BundleError, create_bundle, create_product_bundle,
)
from services.fleet.catalog import Customer, Deployment, FleetCatalog, FleetError, Release
from services.fleet.release_import import import_product_release


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class FleetReleaseImportTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = FleetCatalog(self.root / "fleet.db")
        key = Ed25519PrivateKey.generate()
        self.private = self.root / "signing.pem"
        self.trusted = self.root / "trusted.pem"
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.trusted.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.trusted.chmod(0o600)
        self.payload = self.root / "payload"
        (self.payload / "images").mkdir(parents=True)
        (self.payload / "evidence").mkdir()
        self.images: dict[str, dict[str, str]] = {}
        for role in ("core", "console"):
            archive = self.payload / "images" / f"{role}.tar"
            scan = self.payload / "evidence" / f"{role}-scan.json"
            sbom = self.payload / "evidence" / f"{role}-sbom.json"
            archive.write_bytes((role + " synthetic archive").encode())
            scan.write_bytes((role + " synthetic scan").encode())
            sbom.write_bytes((role + " synthetic sbom").encode())
            self.images[role] = {
                "image_ref": f"registry.example.invalid/sovereign/{role}@sha256:{digest(archive.read_bytes())}",
                "archive_path": f"images/{role}.tar",
                "archive_sha256": digest(archive.read_bytes()),
                "crane_sha256": "a" * 64,
                "scan_path": f"evidence/{role}-scan.json",
                "scan_sha256": digest(scan.read_bytes()),
                "sbom_path": f"evidence/{role}-sbom.json",
                "sbom_sha256": digest(sbom.read_bytes()),
            }
        self.bundle = self.root / "product"

    def intake(self, scan: Path, *args: object, **kwargs: object) -> dict[str, str]:
        role = scan.name.split("-", 1)[0]
        return {"archive_sha256": self.images[role]["archive_sha256"]}

    def identity(self, archive: Path, *args: object) -> dict[str, str]:
        return {"archive_sha256": digest(archive.read_bytes())}

    def product_bundle(self) -> None:
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake), \
             patch("infrastructure.release.bundle.validate_image_archive",
                   side_effect=self.identity):
            create_product_bundle(self.payload, self.bundle, self.private,
                                  "1.2.3", self.images, crane=self.root / "crane")

    def test_signed_product_import_records_manifest_and_issuer(self) -> None:
        self.product_bundle()
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            record = import_product_release(self.catalog, "REL-PROD1", self.bundle,
                                            self.trusted)
            self.assertEqual(record["version"], "1.2.3")
            self.assertEqual(record["status"], "candidate")
            self.assertEqual(record["manifest_sha256"], digest(
                (self.bundle / "release-manifest.json").read_bytes()))
            with self.assertRaises(FleetError):
                import_product_release(self.catalog, "REL-PROD1", self.bundle,
                                       self.trusted)
        audit = self.catalog.audit()
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["action"],
                         "import-signed-release:" + record["signing_key_id"])
        self.catalog.add("customer", Customer(code="CUST-LAB1",
                                               category="owner_manager"))
        deployment = Deployment(code="VSL-LAB1", customer_code="CUST-LAB1",
                                release_code="REL-PROD1", hardware_profile="reference_gpu",
                                status="lab")
        with self.assertRaises(FleetError):
            self.catalog.add("deployment", deployment)
        self.assertEqual(self.catalog.transition("release", "REL-PROD1",
                                                 "approved")["status"], "approved")
        self.catalog.add("deployment", deployment)
        self.assertEqual(self.catalog.transition("release", "REL-PROD1",
                                                 "retired")["status"], "retired")
        with self.assertRaises(FleetError):
            self.catalog.transition("release", "REL-PROD1", "approved")

    def test_unverified_catalog_release_cannot_be_approved(self) -> None:
        self.catalog.add("release", Release(
            code="REL-FAKE1", version="1.2.3", manifest_sha256="a" * 64,
            signing_key_id="b" * 64, status="candidate"))
        with self.assertRaises(FleetError):
            self.catalog.transition("release", "REL-FAKE1", "approved")

    def test_tampered_product_and_wrong_key_are_rejected(self) -> None:
        self.product_bundle()
        other = Ed25519PrivateKey.generate().public_key()
        wrong_key = self.root / "wrong.pem"
        wrong_key.write_bytes(other.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        wrong_key.chmod(0o600)
        with self.assertRaises(BundleError):
            import_product_release(self.catalog, "REL-PROD1", self.bundle,
                                   wrong_key)
        (self.bundle / "images" / "console.tar").write_bytes(b"tampered")
        with self.assertRaises(BundleError):
            import_product_release(self.catalog, "REL-PROD1", self.bundle,
                                   self.trusted)
        self.assertEqual(self.catalog.list("release"), [])

    def test_signed_schema_two_bundle_is_not_a_product(self) -> None:
        payload = self.root / "simple"
        payload.mkdir()
        (payload / "note.txt").write_text("synthetic")
        simple = self.root / "simple-bundle"
        create_bundle(payload, simple, self.private, "1.2.3")
        with self.assertRaises(FleetError):
            import_product_release(self.catalog, "REL-PROD1", simple,
                                   self.trusted)
        self.assertEqual(self.catalog.list("release"), [])


if __name__ == "__main__":
    unittest.main()
