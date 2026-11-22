"""A three-image vessel release must bind every database image byte."""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import (
    BundleError, SUPPORTED_VESSEL_COMPATIBILITY, create_knowledge_bundle,
    require_supported_vessel_compatibility, verify_bundle,
)
from infrastructure.release.intake import IntakeError


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class KnowledgeBundleTests(unittest.TestCase):
    def core_archive(self, knowledge_schema: int = 1) -> None:
        archive = self.payload / "images" / "core.tar"
        config = json.dumps({"config": {"Labels": {
            "sovereign.compat.knowledge-schema": str(knowledge_schema),
            "sovereign.compat.core-state-schema": "1",
        }}}).encode()
        name = digest(config) + ".json"
        manifest = json.dumps([{"Config": name,
                                "RepoTags": ["sovereign-core:synthetic"],
                                "Layers": []}]).encode()
        with tarfile.open(archive, "w") as output:
            for filename, payload in ((name, config), ("manifest.json", manifest)):
                member = tarfile.TarInfo(filename)
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        if hasattr(self, "images") and "core" in self.images:
            hash_value = digest(archive.read_bytes())
            self.images["core"]["archive_sha256"] = hash_value
            self.images["core"]["image_ref"] = (
                f"registry.example.invalid/sovereign/core@sha256:{hash_value}")

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        (self.payload / "images").mkdir(parents=True)
        (self.payload / "evidence").mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.private = self.root / "signing.pem"
        self.trusted = self.root / "trusted.pem"
        self.private.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.trusted.write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle"
        self.compatibility = SUPPORTED_VESSEL_COMPATIBILITY.copy()
        self.images: dict[str, dict[str, str]] = {}
        for role in ("core", "console", "knowledge"):
            archive = self.payload / "images" / f"{role}.tar"
            scan = self.payload / "evidence" / f"{role}-scan.json"
            sbom = self.payload / "evidence" / f"{role}-sbom.json"
            archive.write_bytes(f"{role} image archive".encode())
            if role == "core":
                self.core_archive()
            scan.write_bytes(f"{role} scan".encode())
            sbom.write_bytes(f"{role} sbom".encode())
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

    @staticmethod
    def identity(archive: Path, *args: object) -> dict[str, str]:
        return {"archive_sha256": digest(archive.read_bytes())}

    def create(self, model_id: str | None = None,
               model_provenance: dict[str, str] | None = None) -> dict[str, object]:
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake), \
                patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            return create_knowledge_bundle(self.payload, self.bundle, self.private,
                                           "0.1.0", self.images, self.compatibility,
                                           crane=self.root / "crane", model_id=model_id,
                                           model_provenance=model_provenance)

    @staticmethod
    def provenance() -> dict[str, str]:
        return {"source_url": "https://example.invalid/synthetic-model",
                "revision": "a" * 40, "publisher": "synthetic fixture",
                "license_claim": "Synthetic lab only"}

    def test_signed_model_provenance_is_declared_and_validated(self) -> None:
        (self.payload / "model").mkdir()
        (self.payload / "model" / "weights.bin").write_bytes(b"fictional weights")
        declaration = self.provenance()
        manifest = self.create("synthetic-lab-model", declaration)
        self.assertEqual(manifest["schema"], 8)
        self.assertEqual(manifest["model"]["provenance"], declaration)
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            self.assertEqual(verify_bundle(self.bundle, self.trusted), manifest)
        value = json.loads((self.bundle / "release-manifest.json").read_bytes())
        value["model"]["provenance"]["source_url"] = "http://untrusted.invalid/model"
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        (self.bundle / "release-manifest.json").write_bytes(raw)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            with self.assertRaisesRegex(BundleError, "model provenance source"):
                verify_bundle(self.bundle, self.trusted)

    def test_model_provenance_requires_model_and_immutable_revision(self) -> None:
        with self.assertRaisesRegex(BundleError, "requires a model ID"):
            self.create(model_provenance=self.provenance())
        (self.payload / "model").mkdir()
        (self.payload / "model" / "weights.bin").write_bytes(b"fictional weights")
        declaration = self.provenance()
        declaration["revision"] = "moving-main"
        with self.assertRaisesRegex(BundleError, "revision"):
            self.create("synthetic-lab-model", declaration)

    def test_model_files_are_signed_with_exact_inventory(self) -> None:
        model = self.payload / "model"
        model.mkdir()
        (model / "config.json").write_text('{"model_type":"synthetic"}')
        (model / "weights.bin").write_bytes(b"fictional weights")
        with self.assertRaisesRegex(BundleError, "model files require"):
            self.create()
        manifest = self.create("synthetic-lab-model")
        self.assertEqual(manifest["schema"], 7)
        self.assertEqual(manifest["model"]["id"], "synthetic-lab-model")
        self.assertEqual([row["path"] for row in manifest["model"]["files"]],
                         ["model/config.json", "model/weights.bin"])
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            verified = verify_bundle(self.bundle, self.trusted)
        self.assertEqual(verified, manifest)
        require_supported_vessel_compatibility(verified)
        (self.bundle / "model" / "weights.bin").write_bytes(b"fictional weightX")
        with self.assertRaisesRegex(BundleError, "payload hash mismatch"):
            verify_bundle(self.bundle, self.trusted)

    def test_signed_model_descriptor_must_match_signed_file_rows(self) -> None:
        (self.payload / "model").mkdir()
        (self.payload / "model" / "weights.bin").write_bytes(b"fictional weights")
        self.create("synthetic-lab-model")
        manifest_path = self.bundle / "release-manifest.json"
        value = json.loads(manifest_path.read_bytes())
        value["model"]["files"] = []
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        manifest_path.write_bytes(raw)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            with self.assertRaisesRegex(BundleError, "model files differ"):
                verify_bundle(self.bundle, self.trusted)

    def test_resigned_fractional_schema_cannot_select_model_format(self) -> None:
        (self.payload / "model").mkdir()
        (self.payload / "model" / "weights.bin").write_bytes(b"fictional weights")
        self.create("synthetic-lab-model")
        manifest_path = self.bundle / "release-manifest.json"
        value = json.loads(manifest_path.read_bytes())
        value["schema"] = 7.0
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        manifest_path.write_bytes(raw)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        with self.assertRaisesRegex(BundleError, "invalid manifest fields"):
            verify_bundle(self.bundle, self.trusted)

    def test_signs_and_verifies_exact_three_image_vessel_set(self) -> None:
        manifest = self.create()
        self.assertEqual(manifest["schema"], 6)
        self.assertEqual(manifest["target"], "vessel")
        self.assertEqual(manifest["compatibility"], self.compatibility)
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            checked = verify_bundle(self.bundle, self.trusted)
        self.assertEqual(set(checked["images"]), {"core", "console", "knowledge"})
        (self.bundle / "images" / "knowledge.tar").write_bytes(b"altered")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.trusted)

    def test_missing_extra_or_denied_knowledge_image_prevents_signing(self) -> None:
        with self.assertRaises(BundleError):
            create_knowledge_bundle(self.payload, self.bundle, self.private,
                                    "0.1.0", {key: value for key, value in self.images.items()
                                              if key != "knowledge"}, self.compatibility,
                                    crane=self.root / "crane")
        (self.payload / "images" / "extra.tar").write_bytes(b"unreviewed")
        with self.assertRaises(BundleError):
            create_knowledge_bundle(self.payload, self.bundle, self.private,
                                    "0.1.0", self.images, self.compatibility,
                                    crane=self.root / "crane")
        (self.payload / "images" / "extra.tar").unlink()

        def deny_knowledge(scan: Path, *args: object, **kwargs: object) -> dict[str, str]:
            if scan.name == "knowledge-scan.json":
                raise IntakeError("unresolved high, critical or unknown findings: 1")
            return self.intake(scan)

        with patch("infrastructure.release.bundle.verify_intake", side_effect=deny_knowledge), \
                patch("infrastructure.release.bundle.validate_image_archive", side_effect=self.identity):
            with self.assertRaises(IntakeError):
                create_knowledge_bundle(self.payload, self.bundle, self.private,
                                        "0.1.0", self.images, self.compatibility,
                                        crane=self.root / "crane")

    def test_requires_exact_explicit_compatibility_contract(self) -> None:
        for value in ({"knowledge_schema": True, "core_state_schema": 1},
                      {"knowledge_schema": 2},
                      {"knowledge_schema": 1, "core_state_schema": 0},
                      {"knowledge_schema": 1, "core_state_schema": 1, "extra": 1}):
            with self.subTest(value=value), self.assertRaisesRegex(BundleError, "compatibility"):
                create_knowledge_bundle(self.payload, self.bundle, self.private,
                                        "0.1.0", self.images, value,
                                        crane=self.root / "crane")
            self.assertFalse(self.bundle.exists())

    def test_future_signed_contract_is_not_runnable_by_this_installer(self) -> None:
        self.compatibility = {"knowledge_schema": 2, "core_state_schema": 1}
        self.core_archive(2)
        self.create()
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            future = verify_bundle(self.bundle, self.trusted)
        self.assertEqual(future["compatibility"]["knowledge_schema"], 2)
        with self.assertRaisesRegex(BundleError, "unsupported vessel compatibility"):
            require_supported_vessel_compatibility(future)

    def test_signer_and_verifier_reject_core_label_mismatch(self) -> None:
        self.compatibility = {"knowledge_schema": 2, "core_state_schema": 1}
        with self.assertRaisesRegex(BundleError, "Core image and signed compatibility"):
            self.create()
        self.assertFalse(self.bundle.exists())
        self.compatibility = SUPPORTED_VESSEL_COMPATIBILITY.copy()
        self.create()
        manifest_path = self.bundle / "release-manifest.json"
        value = json.loads(manifest_path.read_bytes())
        value["compatibility"]["knowledge_schema"] = 2
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        manifest_path.write_bytes(raw)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        with patch("infrastructure.release.bundle.verify_intake", side_effect=self.intake):
            with self.assertRaisesRegex(BundleError, "Core image and signed compatibility"):
                verify_bundle(self.bundle, self.trusted)

    def test_signer_rejects_duplicate_core_configuration_keys(self) -> None:
        archive = self.payload / "images" / "core.tar"
        config = (b'{"config":{"Labels":{'
                  b'"sovereign.compat.knowledge-schema":"1",'
                  b'"sovereign.compat.knowledge-schema":"2",'
                  b'"sovereign.compat.core-state-schema":"1"}}}')
        name = digest(config) + ".json"
        manifest = json.dumps([{"Config": name,
                                "RepoTags": ["sovereign-core:synthetic"],
                                "Layers": []}]).encode()
        with tarfile.open(archive, "w") as output:
            for filename, payload in ((name, config), ("manifest.json", manifest)):
                member = tarfile.TarInfo(filename)
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        hash_value = digest(archive.read_bytes())
        self.images["core"]["archive_sha256"] = hash_value
        self.images["core"]["image_ref"] = (
            f"registry.example.invalid/sovereign/core@sha256:{hash_value}")
        with self.assertRaisesRegex(BundleError, "Core archive has no verified"):
            self.create()
        self.assertFalse(self.bundle.exists())

    def test_resigned_wrong_target_is_still_rejected(self) -> None:
        self.create()
        manifest_path = self.bundle / "release-manifest.json"
        value = json.loads(manifest_path.read_bytes())
        value["target"] = "fleet"
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        manifest_path.write_bytes(raw)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        with self.assertRaisesRegex(BundleError, "target"):
            verify_bundle(self.bundle, self.trusted)
