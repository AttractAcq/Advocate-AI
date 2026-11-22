"""The release CI command must fail when image intake skips the Fleet run."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from scripts.phase8_fleet_release_rehearsal import main


class FleetReleaseGateTests(unittest.TestCase):
    def test_scan_denial_is_a_failing_ci_result_with_retained_summary(self) -> None:
        arguments = ["phase8_fleet_release_rehearsal", "--output", "/tmp/fleet-result",
                     "--crane", "/tmp/crane", "--crane-sha256", "0" * 64,
                     "--syft", "/tmp/syft", "--syft-sha256", "0" * 64,
                     "--trivy", "/tmp/trivy", "--trivy-sha256", "0" * 64,
                     "--trivy-cache", "/tmp/cache"]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", arguments), patch(
                "scripts.phase8_fleet_release_rehearsal.rehearse",
                return_value={"fleet_bundle": "denied-findings"}), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as stopped:
                main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(json.loads(stdout.getvalue())["fleet_bundle"],
                         "denied-findings")
        self.assertIn("was not run", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
