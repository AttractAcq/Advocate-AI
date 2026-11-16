from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import BundleError, create_candidate_bundle, verify_bundle
from infrastructure.release.intake import IntakeError


DIGEST = "a" * 64
IMAGE = f"registry.example.invalid/fictional/identity@sha256:{DIGEST}"


class CandidateBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        (self.payload / "evidence").mkdir(parents=True)
        (self.payload / "images").mkdir()
        (self.payload / "images" / "fictional.tar").write_bytes(b"fictional image")
        key = Ed25519PrivateKey.generate()
        self.private = self.root / "signing.pem"
        self.public = self.root / "trusted.pem"
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle"
        timestamp = datetime.now(timezone.utc).isoformat()
        scan = {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": IMAGE,
                "CreatedAt": timestamp, "Trivy": {"Version": "0.76.2"},
                "Metadata": {"RepoDigests": [IMAGE]},
                "Results": [{"Target": "fictional OS", "Vulnerabilities": []}]}
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"timestamp": timestamp,
                             "properties": [{"name": "sovereign-ai:inventory-status",
                                             "value": "resolved-release-candidate"}],
                             "component": {"name": IMAGE.split("@")[0],
                                           "hashes": [{"alg": "SHA-256", "content": DIGEST}]}},
                "components": [{"bom-ref": "fictional-lib", "name": "fictional-lib",
                                "version": "1.0.0", "hashes": [{"alg": "SHA-256",
                                                               "content": "b" * 64}]}]}
        self.scan = self.payload / "evidence" / "scan.json"
        self.sbom = self.payload / "evidence" / "sbom.json"
        self.scan.write_text(json.dumps(scan))
        self.sbom.write_text(json.dumps(sbom))

    def evidence(self) -> dict[str, str]:
        return {"image_ref": IMAGE, "scan_path": "evidence/scan.json",
                "scan_sha256": hashlib.sha256(self.scan.read_bytes()).hexdigest(),
                "sbom_path": "evidence/sbom.json",
                "sbom_sha256": hashlib.sha256(self.sbom.read_bytes()).hexdigest()}

    def test_candidate_evidence_is_signed_and_verified(self) -> None:
        descriptor = self.evidence()
        manifest = create_candidate_bundle(self.payload, self.bundle, self.private,
                                           "0.1.0", descriptor)
        self.assertEqual(manifest["schema"], 3)
        self.assertEqual(verify_bundle(self.bundle, self.public)["evidence"], descriptor)
        (self.bundle / "evidence" / "scan.json").write_text("{}")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)

    def test_findings_or_missing_evidence_prevent_bundle_creation(self) -> None:
        scan = json.loads(self.scan.read_text())
        scan["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2026-000001", "Severity": "HIGH"}]
        self.scan.write_text(json.dumps(scan))
        with self.assertRaises(IntakeError):
            create_candidate_bundle(self.payload, self.bundle, self.private,
                                    "0.1.0", self.evidence())
        self.assertFalse(self.bundle.exists())
        scan["Results"][0]["Vulnerabilities"] = []
        self.scan.write_text(json.dumps(scan))
        descriptor = self.evidence()
        descriptor["scan_path"] = "outside.json"
        with self.assertRaises(BundleError):
            create_candidate_bundle(self.payload, self.bundle, self.private,
                                    "0.1.0", descriptor)
        self.assertFalse(self.bundle.exists())

    def test_signed_descriptor_must_match_inventory(self) -> None:
        create_candidate_bundle(self.payload, self.bundle, self.private,
                                "0.1.0", self.evidence())
        manifest_path = self.bundle / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["evidence"]["scan_path"] = "images/fictional.tar"
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_path.write_bytes(raw)
        key = serialization.load_pem_private_key(self.private.read_bytes(), password=None)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)


if __name__ == "__main__":
    unittest.main()
