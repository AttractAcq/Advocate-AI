from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.vesselctl import main


class VesselCtlTests(unittest.TestCase):
    def test_stopped_release_commands_route_explicit_paths(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.switch_stopped_vessel_release",
                   return_value={"result": "upgraded"}) as switch, \
             patch("scripts.vesselctl.rollback_stopped_vessel_release",
                   return_value={"result": "rolled-back"}) as rollback, \
             redirect_stdout(output):
            common = ["--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                      "--crane", "/tmp/crane"]
            main(["switch-stopped", *common, "--bundle", "/tmp/bundle",
                  "--console-config", "/tmp/config"])
            main(["rollback-stopped", *common])
        switch.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                       Path("/tmp/crane"), Path("/tmp/bundle"),
                                       Path("/tmp/config"))
        rollback.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                         Path("/tmp/crane"))
        self.assertIn('"result": "rolled-back"', output.getvalue())

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

    def test_reconcile_routes_to_existing_root(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.reconcile_vessel",
                   return_value={"result": "reconciled", "containers": 3,
                                 "networks": 1, "sockets": 1}) as reconcile, \
             redirect_stdout(output):
            main(["reconcile", "--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                  "--crane", "/tmp/crane"])
        reconcile.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                          Path("/tmp/crane"))
        self.assertEqual(json.loads(output.getvalue())["containers"], 3)

    def test_finish_stop_routes_to_existing_root(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.finish_vessel_stop",
                   return_value={"result": "stopped", "active": "a" * 24}) as finish, \
             redirect_stdout(output):
            main(["finish-stop", "--root", "/tmp/vessel",
                  "--trusted-key", "/tmp/key", "--crane", "/tmp/crane"])
        finish.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                       Path("/tmp/crane"))
        self.assertEqual(json.loads(output.getvalue())["result"], "stopped")

    def test_resume_install_routes_to_private_root(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.resume_first_install",
                   return_value={"result": "activated", "active": "a" * 24}) as resume, \
             redirect_stdout(output):
            main(["resume-install", "--root", "/tmp/vessel",
                  "--trusted-key", "/tmp/key", "--crane", "/tmp/crane"])
        resume.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                       Path("/tmp/crane"))
        self.assertEqual(json.loads(output.getvalue())["result"], "activated")

    def test_bootstrap_reset_requires_explicit_discard_flag(self) -> None:
        args = ["reset-bootstrap", "--root", "/tmp/vessel",
                "--trusted-key", "/tmp/key", "--crane", "/tmp/crane"]
        with patch("scripts.vesselctl.reset_first_install") as reset, \
             redirect_stderr(StringIO()), \
             self.assertRaises(SystemExit):
            main(args)
        reset.assert_not_called()
        output = StringIO()
        with patch("scripts.vesselctl.reset_first_install",
                   return_value={"result": "bootstrap-reset"}) as reset, \
             redirect_stdout(output):
            main(args + ["--discard-data"])
        reset.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                      Path("/tmp/crane"))
        self.assertEqual(json.loads(output.getvalue())["result"], "bootstrap-reset")


if __name__ == "__main__":
    unittest.main()
