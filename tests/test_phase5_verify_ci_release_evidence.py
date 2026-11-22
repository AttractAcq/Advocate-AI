from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

            def write() -> str:
                raw = json.dumps(result).encode()
                path.write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()

            expected = write()
            with patch("scripts.phase5_verify_ci_release_evidence.verify_intake",
                       return_value={"components": 1, "archive_sha256": "d" * 64}) as intake:
                report = verify(root, expected)
            self.assertEqual(report["status"], "artifact-consistency-pass")
            self.assertEqual(intake.call_count, 4)
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
