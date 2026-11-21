from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.vesselctl import main


class VesselCtlTests(unittest.TestCase):
    def test_finish_incomplete_restore_routes_signed_inputs(self) -> None:
        args = ["finish-incomplete-restore", "--root", "/tmp/vessel",
                "--trusted-key", "/tmp/key", "--crane", "/tmp/crane",
                "--receipt", "/tmp/receipt", "--receipt-key", "/tmp/receipt-key",
                "--password-file", "/tmp/password", "--restic", "/tmp/restic",
                "--restic-sha256", "0" * 64, "--staging-parent", "/tmp/staging"]
        with patch("scripts.vesselctl.finish_incomplete_vessel_restore",
                   return_value={"result": "restored-and-activated"}) as finish, \
             redirect_stdout(StringIO()):
            main(args)
        finish.assert_called_once_with(
            Path("/tmp/vessel"), Path("/tmp/key"), Path("/tmp/crane"),
            Path("/tmp/receipt"), Path("/tmp/receipt-key"),
            Path("/tmp/password"), Path("/tmp/restic"), "0" * 64,
            Path("/tmp/staging"))

    def test_partial_stage_discard_requires_explicit_flag(self) -> None:
        args = ["discard-staged-candidate", "--root", "/tmp/vessel",
                "--trusted-key", "/tmp/key", "--bundle", "/tmp/bundle",
                "--console-config", "/tmp/config"]
        with patch("scripts.vesselctl.discard_stopped_vessel_stage") as discard, \
             redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            main(args)
        discard.assert_not_called()
        with patch("scripts.vesselctl.discard_stopped_vessel_stage",
                   return_value={"result": "staged-candidate-discarded"}) as discard, \
             redirect_stdout(StringIO()):
            main(args + ["--discard-stage"])
        discard.assert_called_once_with(
            Path("/tmp/vessel"), Path("/tmp/key"), Path("/tmp/bundle"),
            Path("/tmp/config"), discard_stage=True)

    def test_stopped_release_commands_route_explicit_paths(self) -> None:
        output = StringIO()
        with patch("scripts.vesselctl.switch_stopped_vessel_release",
                   return_value={"result": "upgraded"}) as switch, \
             patch("scripts.vesselctl.rollback_stopped_vessel_release",
                   return_value={"result": "rolled-back"}) as rollback, \
             redirect_stdout(output):
            common = ["--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                      "--crane", "/tmp/crane"]
            recovery = ["--recovery-receipt", "/tmp/receipt",
                        "--receipt-key", "/tmp/receipt-key",
                        "--password-file", "/tmp/backup-password",
                        "--restic", "/tmp/restic", "--restic-sha256", "0" * 64,
                        "--staging-parent", "/tmp/staging"]
            main(["switch-stopped", *common, "--bundle", "/tmp/bundle",
                  "--console-config", "/tmp/config", *recovery])
            main(["rollback-stopped", *common, *recovery])
        switch.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                       Path("/tmp/crane"), Path("/tmp/bundle"),
                                       Path("/tmp/config"), Path("/tmp/receipt"),
                                       Path("/tmp/receipt-key"),
                                       Path("/tmp/backup-password"),
                                       Path("/tmp/restic"), "0" * 64,
                                       Path("/tmp/staging"))
        rollback.assert_called_once_with(Path("/tmp/vessel"), Path("/tmp/key"),
                                         Path("/tmp/crane"), Path("/tmp/receipt"),
                                         Path("/tmp/receipt-key"),
                                         Path("/tmp/backup-password"),
                                         Path("/tmp/restic"), "0" * 64,
                                         Path("/tmp/staging"))
        self.assertIn('"result": "rolled-back"', output.getvalue())

    def test_switch_cli_requires_preupdate_recovery_inputs(self) -> None:
        with patch("scripts.vesselctl.switch_stopped_vessel_release") as switch, \
             redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            main(["switch-stopped", "--root", "/tmp/vessel",
                  "--trusted-key", "/tmp/key", "--crane", "/tmp/crane",
                  "--bundle", "/tmp/bundle", "--console-config", "/tmp/config"])
        switch.assert_not_called()

    def test_rollback_cli_requires_current_recovery_inputs(self) -> None:
        with patch("scripts.vesselctl.rollback_stopped_vessel_release") as rollback, \
             redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            main(["rollback-stopped", "--root", "/tmp/vessel",
                  "--trusted-key", "/tmp/key", "--crane", "/tmp/crane"])
        rollback.assert_not_called()

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

    def test_oidc_install_requires_network_instead_of_lab_password(self) -> None:
        command = ["install", "--root", "/tmp/vessel", "--trusted-key", "/tmp/key",
                   "--crane", "/tmp/crane", "--bundle", "/tmp/bundle",
                   "--console-config", "/tmp/config", "--core-state", "/tmp/state"]
        with patch("scripts.vesselctl.install_vessel",
                   return_value={"result": "activated"}) as install, \
             redirect_stdout(StringIO()):
            main(command + ["--identity-network", "vessel-identity"])
        install.assert_called_once_with(
            Path("/tmp/bundle"), Path("/tmp/key"), Path("/tmp/crane"),
            Path("/tmp/config"), Path("/tmp/vessel"), Path("/tmp/state"), None,
            identity_network="vessel-identity")
        with patch("scripts.vesselctl.install_vessel") as install, \
             redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            main(command + ["--identity-network", "vessel-identity",
                            "--lab-password-file", "/tmp/password"])
        install.assert_not_called()

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
