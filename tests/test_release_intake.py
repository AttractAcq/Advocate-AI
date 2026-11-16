from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from infrastructure.release.intake import IntakeError, verify_intake


NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
IMAGE = f"registry.example.invalid/fictional/identity@sha256:{DIGEST}"


class ReleaseIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scan = {"SchemaVersion": 2, "ArtifactType": "container_image",
                     "ArtifactName": IMAGE, "CreatedAt": "2026-11-16T11:00:00Z",
                     "Trivy": {"Version": "0.76.2"},
                     "Metadata": {"RepoDigests": [IMAGE]},
                     "Results": [{"Target": "fictional OS", "Vulnerabilities": []}]}
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                     "metadata": {"timestamp": "2026-11-16T11:00:00Z",
                                  "properties": [{"name": "sovereign-ai:inventory-status",
                                                  "value": "resolved-release-candidate"}],
                                  "component": {"name": "registry.example.invalid/fictional/identity",
                                                "hashes": [{"alg": "SHA-256", "content": DIGEST}]}},
                     "components": [{"bom-ref": "fictional-lib-1", "name": "fictional-lib",
                                     "version": "1.0.0", "hashes": [{"alg": "SHA-256", "content": "b" * 64}]}]}

    def write(self, name: str, payload: object) -> tuple[Path, str]:
        path = self.root / name
        raw = json.dumps(payload).encode()
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def verify(self, scan: object | None = None, sbom: object | None = None,
               image: str = IMAGE) -> dict[str, object]:
        scan_path, scan_hash = self.write("scan.json", self.scan if scan is None else scan)
        sbom_path, sbom_hash = self.write("sbom.json", self.sbom if sbom is None else sbom)
        return verify_intake(scan_path, sbom_path, image, scan_hash, sbom_hash, now=NOW)

    def test_resolved_clean_evidence_passes_preflight(self) -> None:
        result = self.verify()
        self.assertEqual(result["status"], "preflight-pass")
        self.assertEqual(result["components"], 1)

    def test_high_unknown_and_old_scan_rejected(self) -> None:
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            with self.subTest(severity=severity):
                scan = copy.deepcopy(self.scan)
                scan["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2026-000001",
                                                              "Severity": severity, "Status": "fixed"}]
                with self.assertRaises(IntakeError):
                    self.verify(scan=scan)
        scan = copy.deepcopy(self.scan)
        scan["CreatedAt"] = "2026-09-01T00:00:00Z"
        with self.assertRaises(IntakeError):
            self.verify(scan=scan)
        scan = copy.deepcopy(self.scan)
        scan["Trivy"]["Version"] = "0.75.0"
        with self.assertRaises(IntakeError):
            self.verify(scan=scan)

    def test_malformed_scan_sections_fail_closed(self) -> None:
        for value in (None, "", False, {}):
            with self.subTest(value=value):
                scan = copy.deepcopy(self.scan)
                scan["Results"][0]["Vulnerabilities"] = value
                with self.assertRaises(IntakeError):
                    self.verify(scan=scan)

    def test_mismatched_image_hash_or_candidate_sbom_rejected(self) -> None:
        with self.assertRaises(IntakeError):
            self.verify(image=f"registry.example.invalid/other@sha256:{DIGEST}")
        sbom = copy.deepcopy(self.sbom)
        sbom["metadata"]["properties"][0]["value"] = "candidate-only"
        with self.assertRaises(IntakeError):
            self.verify(sbom=sbom)
        sbom = copy.deepcopy(self.sbom)
        sbom["components"][0]["hashes"] = []
        with self.assertRaises(IntakeError):
            self.verify(sbom=sbom)
        path, digest = self.write("scan.json", self.scan)
        sbom_path, sbom_digest = self.write("sbom.json", self.sbom)
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(IntakeError):
            verify_intake(path, sbom_path, IMAGE, digest, sbom_digest, now=NOW)

    def test_duplicate_json_key_and_symlinked_evidence_rejected(self) -> None:
        scan_path = self.root / "scan.json"
        raw = json.dumps(self.scan).replace('"SchemaVersion": 2',
                                           '"SchemaVersion": 2, "SchemaVersion": 2', 1).encode()
        scan_path.write_bytes(raw)
        sbom_path, sbom_digest = self.write("sbom.json", self.sbom)
        with self.assertRaises(IntakeError):
            verify_intake(scan_path, sbom_path, IMAGE, hashlib.sha256(raw).hexdigest(),
                          sbom_digest, now=NOW)
        scan_path.unlink()
        target, digest = self.write("target.json", self.scan)
        scan_path.symlink_to(target)
        with self.assertRaises(IntakeError):
            verify_intake(scan_path, sbom_path, IMAGE, digest, sbom_digest, now=NOW)


if __name__ == "__main__":
    unittest.main()
