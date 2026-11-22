from __future__ import annotations

import hashlib
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.phase5_verify_ci_release_evidence import read_result, verify


class RetainedReleaseEvidenceTests(unittest.TestCase):
    def test_exact_result_hash_and_reported_gate_are_required(self) -> None:
        digest = "a" * 64
        image = {"image_ref": "registry.example.invalid/sovereign/core@sha256:" + digest,
                 "scan_sha256": "b" * 64, "sbom_sha256": "c" * 64,
                 "archive_sha256": "d" * 64, "components": 1,
                 "intake": "preflight-pass", "unresolved_findings": 0}
        result = {"source": "locally-built-synthetic-vessel-images",
                  "three_image_bundle": "signed-and-verified",
                  "images": {name: dict(image) for name in ("core", "console", "knowledge")},
                  "updated_core_image": dict(image),
                  "feed_bound_clean_restore": {"result": "pass", "feed_status": "stale",
                                               "indicator_values": "withheld",
                                               "restore": "signed-and-healthy"}}
        for key in ("signed_vessel_first_install", "signed_vessel_clean_restore",
                    "signed_vessel_updated_restore", "signed_vessel_oidc",
                    "signed_vessel_keycloak_pair"):
            result[key] = {"result": "pass"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "updated-core").mkdir()
            path = root / "result.json"
            proof = root / "signed-manifests"
            proof.mkdir()
            key = Ed25519PrivateKey.generate()
            public = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            (proof / "synthetic-trusted.pem").write_bytes(public)
            result["synthetic_public_key_sha256"] = hashlib.sha256(public).hexdigest()
            result["vessel_compatibility"] = {"knowledge_schema": 1,
                                               "core_state_schema": 1}
            for label, field in (("initial", "bundle_manifest_sha256"),
                                 ("updated", "updated_bundle_manifest_sha256")):
                folder = proof / label
                folder.mkdir()
                descriptors = {}
                rows = []
                for role in ("core", "console", "knowledge"):
                    descriptors[role] = {"image_ref": image["image_ref"]}
                    for kind, extension in (("archive", "tar"), ("scan", "json"),
                                            ("sbom", "json")):
                        name = (f"images/{role}.tar" if kind == "archive" else
                                f"evidence/{role}-{kind}.{extension}")
                        descriptors[role][f"{kind}_path"] = name
                        descriptors[role][f"{kind}_sha256"] = image[f"{kind}_sha256"]
                        rows.append({"path": name,
                                     "sha256": image[f"{kind}_sha256"], "size": 1})
                manifest = {"schema": 8, "target": "vessel",
                            "key_id": hashlib.sha256(key.public_key().public_bytes(
                                serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw)).hexdigest(),
                            "images": descriptors, "files": rows,
                            "compatibility": result["vessel_compatibility"]}
                raw = json.dumps(manifest).encode()
                (folder / "release-manifest.json").write_bytes(raw)
                (folder / "release-manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))
                result[field] = hashlib.sha256(raw).hexdigest()

            def write() -> str:
                raw = json.dumps(result).encode()
                path.write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()

            expected = write()
            with patch("scripts.phase5_verify_ci_release_evidence.verify_intake",
                       return_value={"components": 1, "archive_sha256": "d" * 64}) as intake:
                report = verify(root, expected)
            self.assertEqual(report["status"], "artifact-consistency-pass")
            self.assertEqual(report["signed_manifests"], "initial-and-updated-verified")
            self.assertEqual(intake.call_count, 4)
            signature = proof / "initial" / "release-manifest.sig"
            signature.write_bytes(base64.b64encode(b"0" * 64))
            with patch("scripts.phase5_verify_ci_release_evidence.verify_intake",
                       return_value={"components": 1, "archive_sha256": "d" * 64}):
                with self.assertRaisesRegex(ValueError, "signature mismatch"):
                    verify(root, expected)
            signature.write_bytes(base64.b64encode(key.sign(
                (proof / "initial" / "release-manifest.json").read_bytes())))
            manifest_path = proof / "initial" / "release-manifest.json"
            original_manifest = manifest_path.read_bytes()
            altered = json.loads(original_manifest)
            altered["images"]["core"]["archive_sha256"] = "e" * 64
            altered_raw = json.dumps(altered).encode()
            manifest_path.write_bytes(altered_raw)
            signature.write_bytes(base64.b64encode(key.sign(altered_raw)))
            result["bundle_manifest_sha256"] = hashlib.sha256(altered_raw).hexdigest()
            with patch("scripts.phase5_verify_ci_release_evidence.verify_intake",
                       return_value={"components": 1, "archive_sha256": "d" * 64}):
                with self.assertRaisesRegex(ValueError, "signed inventory|image evidence"):
                    verify(root, write())
            manifest_path.write_bytes(original_manifest)
            signature.write_bytes(base64.b64encode(key.sign(original_manifest)))
            result["bundle_manifest_sha256"] = hashlib.sha256(original_manifest).hexdigest()
            result["signed_vessel_keycloak_pair"]["result"] = "fail"
            with self.assertRaisesRegex(ValueError, "signed_vessel_keycloak_pair"):
                verify(root, write())
            path.write_bytes(b'{"source":1,"source":2}')
            duplicate_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_result(path, duplicate_hash)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                read_result(path, expected)


if __name__ == "__main__":
    unittest.main()
