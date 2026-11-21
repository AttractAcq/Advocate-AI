from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.release.intake import IntakeError, MAX_EVIDENCE_BYTES, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import (UpstreamError, _read_generated_json,
                                             _write_new_json, generate_resolved_sbom,
                                             validate_image_archive)


NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
IMAGE = f"registry.example.invalid/fictional/identity@sha256:{DIGEST}"


class ArchiveStabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "image.tar"
        self.archive.write_bytes(b"original synthetic archive")

    def test_generated_evidence_rejects_oversize_duplicate_keys_and_links(self) -> None:
        raw = self.root / "raw.json"
        with raw.open("wb") as stream:
            stream.seek(MAX_EVIDENCE_BYTES)
            stream.write(b"x")
        with self.assertRaisesRegex(UpstreamError, "exceeds size limit"):
            _read_generated_json(raw)
        raw.write_bytes(b'{"version":1,"version":2}')
        with self.assertRaisesRegex(UpstreamError, "duplicate generated evidence key"):
            _read_generated_json(raw)
        linked = self.root / "linked.json"
        linked.symlink_to(raw)
        with self.assertRaises(OSError):
            _read_generated_json(linked)
        with self.assertRaisesRegex(UpstreamError, "exceeds size limit"):
            _write_new_json(self.root / "evidence.json", {"blob": "x" * MAX_EVIDENCE_BYTES})
        self.assertFalse((self.root / "evidence.json").exists())

    def test_crane_validation_rejects_archive_changed_during_digest_read(self) -> None:
        def run(argv, **kwargs):
            if argv[1] == "version":
                return "0.22.1"
            if argv[1] == "digest":
                self.archive.write_bytes(b"changed synthetic archive")
                return f"sha256:{DIGEST}"
            return ""

        with patch("infrastructure.release.upstream._binary"), \
             patch("infrastructure.release.upstream._run", side_effect=run):
            with self.assertRaisesRegex(UpstreamError, "changed during validation"):
                validate_image_archive(self.archive, IMAGE, Path("/fake/crane"), "0" * 64)

    def test_syft_inventory_rejects_archive_changed_during_catalog(self) -> None:
        def run(argv, **kwargs):
            if argv[0] == "/fake/crane":
                return "0.22.1" if argv[1] == "version" else \
                    f"sha256:{DIGEST}" if argv[1] == "digest" else ""
            if argv[1] == "version":
                return json.dumps({"version": "1.57.1"})
            output = Path(next(value.split("=", 1)[1] for value in argv
                               if value.startswith("cyclonedx-json@1.6=")))
            output.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"tools": {"components": [{"name": "syft", "version": "1.57.1"}]}},
                "components": [{"bom-ref": "fictional", "name": "fictional"}],
            }))
            self.archive.write_bytes(b"changed synthetic archive")
            return ""

        with patch("infrastructure.release.upstream._binary"), \
             patch("infrastructure.release.upstream._run", side_effect=run):
            with self.assertRaisesRegex(UpstreamError, "changed during inventory generation"):
                generate_resolved_sbom(self.archive, IMAGE, self.root / "sbom.json",
                                       Path("/fake/crane"), "0" * 64,
                                       Path("/fake/syft"), "0" * 64)
        self.assertFalse((self.root / "sbom.json").exists())

    def test_sbom_output_replacement_cannot_overwrite_another_file(self) -> None:
        output = self.root / "sbom.json"
        outside = self.root / "outside.txt"
        outside.write_text("preserve this file")

        def run(argv, **kwargs):
            if argv[1] == "version":
                return json.dumps({"version": "1.57.1"})
            raw = Path(next(value.split("=", 1)[1] for value in argv
                            if value.startswith("cyclonedx-json@1.6=")))
            raw.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"tools": {"components": [{"name": "syft", "version": "1.57.1"}]}},
                "components": [{"bom-ref": "fictional", "name": "fictional"}],
            }))
            output.symlink_to(outside)
            return ""

        identity = {"archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        with patch("infrastructure.release.upstream.validate_image_archive", return_value=identity), \
             patch("infrastructure.release.upstream._binary"), \
             patch("infrastructure.release.upstream._run", side_effect=run):
            with self.assertRaises(FileExistsError):
                generate_resolved_sbom(self.archive, IMAGE, output, Path("/fake/crane"),
                                       "0" * 64, Path("/fake/syft"), "0" * 64)
        self.assertEqual(outside.read_text(), "preserve this file")

    def test_trivy_raw_output_uses_private_directory(self) -> None:
        output = self.root / "scan.json"
        outside = self.root / "outside.txt"
        outside.write_text("preserve this file")
        cache = self.root / "cache" / "db"
        cache.mkdir(parents=True)
        (cache / "trivy.db").write_bytes(b"synthetic scanner database")
        now = datetime.now(timezone.utc)
        updated = (now - timedelta(hours=1)).isoformat()
        next_update = (now + timedelta(days=1)).isoformat()
        (cache / "metadata.json").write_text(json.dumps({
            "Version": 2, "UpdatedAt": updated, "NextUpdate": next_update,
        }))
        report = {"SchemaVersion": 2, "ArtifactType": "container_image",
                  "ArtifactName": str(self.archive), "Trivy": {"Version": "0.76.2"},
                  "Metadata": {}, "Results": [{"Target": "fictional", "Vulnerabilities": []}],
                  "CreatedAt": now.isoformat()}

        def run(argv, **kwargs):
            if argv[1] == "--version":
                return "Version: 0.76.2"
            raw = Path(argv[argv.index("--output") + 1])
            self.assertEqual(raw.parent.stat().st_mode & 0o777, 0o700)
            (self.root / "scan.json.raw.tmp").symlink_to(outside)
            raw.write_text(json.dumps(report))
            return ""

        identity = {"archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                    "manifest_digest": f"sha256:{DIGEST}"}
        with patch("infrastructure.release.scan.validate_image_archive", return_value=identity), \
             patch("infrastructure.release.scan._binary"), \
             patch("infrastructure.release.scan._run", side_effect=run):
            generated = generate_archive_scan(
                self.archive, IMAGE, output, Path("/fake/crane"), "0" * 64,
                Path("/fake/trivy"), "0" * 64, cache.parent)
        self.assertEqual(outside.read_text(), "preserve this file")
        self.assertEqual(generated["scan_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())


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

    def test_generated_syft_inventory_accepts_distinct_package_and_file_evidence(self) -> None:
        scan = copy.deepcopy(self.scan)
        scan["Sovereign"] = {
            "Source": "offline-local-docker-archive", "ArchiveSHA256": "c" * 64,
            "ManifestDigest": "sha256:" + DIGEST, "ScannerBinarySHA256": "e" * 64,
            "DatabaseSHA256": "f" * 64,
            "DatabaseUpdatedAt": "2026-11-16T10:00:00Z",
            "DatabaseNextUpdate": "2026-11-16T13:00:00Z",
        }
        sbom = copy.deepcopy(self.sbom)
        sbom["metadata"]["tools"] = {"components": [{"name": "syft", "version": "1.57.1"}]}
        sbom["metadata"]["properties"] = [
            {"name": "sovereign-ai:inventory-status", "value": "generated-from-validated-archive"},
            {"name": "sovereign-ai:archive-sha256", "value": "c" * 64},
            {"name": "sovereign-ai:crane-version", "value": "0.22.1"},
        ]
        sbom["components"] = [
            {"type": "library", "bom-ref": "pkg:npm/fictional@1.0.0", "name": "fictional",
             "version": "1.0.0", "purl": "pkg:npm/fictional@1.0.0"},
            {"type": "application", "bom-ref": "pkg:generic/python@3.14.10", "name": "python",
             "version": "3.14.10", "purl": "pkg:generic/python@3.14.10"},
            {"type": "file", "bom-ref": "file-1", "name": "/app/package.json",
             "hashes": [{"alg": "SHA-256", "content": "d" * 64}]},
        ]
        self.assertEqual(self.verify(scan=scan, sbom=sbom)["archive_sha256"], "c" * 64)
        sbom["components"][1].pop("purl")
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)
        sbom["components"][1]["purl"] = "pkg:generic/python@3.14.10"
        sbom["components"][0].pop("purl")
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)
        sbom["components"][0]["purl"] = "pkg:npm/fictional@1.0.0"
        sbom["metadata"]["properties"].append(
            {"name": "sovereign-ai:archive-sha256", "value": "e" * 64})
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)
        sbom["metadata"]["properties"].pop()
        scan["Sovereign"]["ArchiveSHA256"] = "0" * 64
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)
        scan["Sovereign"]["ArchiveSHA256"] = "c" * 64
        scan["Sovereign"]["DatabaseUpdatedAt"] = "2026-11-01T10:00:00Z"
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)
        del scan["Sovereign"]
        with self.assertRaises(IntakeError):
            self.verify(scan=scan, sbom=sbom)


if __name__ == "__main__":
    unittest.main()
