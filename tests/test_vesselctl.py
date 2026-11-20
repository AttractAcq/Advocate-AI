from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.vesselctl import main


class VesselCtlTests(unittest.TestCase):
    def test_install_routes_explicit_paths_and_prints_bounded_result(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.install_vessel",
                   return_value={"result": "activated", "active": "a" * 24}) as install, \
             redirect_stdout(output):
            main(["install", "--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                  "--crane", "/tmp/crane", "--bundle", "/tmp/bundle",
                  "--console-config", "/tmp/config", "--core-state", "/tmp/state",
                  "--lab-password-file", "/tmp/password"])
        install.assert_called_once_with(Path("/tmp/bundle"), Path("/tmp/key"),
                                        Path("/tmp/crane"), Path("/tmp/config"),
                                        Path("/tmp/vessel"), Path("/tmp/state"),
                                        Path("/tmp/password"))
        self.assertEqual(json.loads(output.getvalue())["result"], "activated")

    def test_recover_routes_to_existing_root(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.recover_vessel",
                   return_value={"result": "recovered", "active": "a" * 24}) as recover, \
             redirect_stdout(output):
            main(["recover", "--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                  "--crane", "/tmp/crane"])
        recover.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                        Path("/tmp/crane"))
        self.assertEqual(json.loads(output.getvalue())["result"], "recovered")


if __name__ == "__main__":
    unittest.main()
