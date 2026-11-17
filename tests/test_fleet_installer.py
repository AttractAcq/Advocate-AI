"""Synthetic Fleet update state changes only after a healthy candidate."""

from __future__ import annotations

from pathlib import Path
import ast
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.fleet_installer import (
    FleetInstallError, fleet_status, install_fleet, recover_fleet, rollback_fleet,
)
from infrastructure.deploy.fleet_runtime import FleetRuntime, RuntimeError
from infrastructure.deploy.fleet_runtime import _health


class FleetInstallerTests(unittest.TestCase):
    def test_runtime_probe_python_is_valid(self) -> None:
        commands = []
        with patch("infrastructure.deploy.fleet_runtime._docker",
                   side_effect=lambda *args: commands.append(args) or ""):
            _health("a" * 64)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(command[:4], ("exec", "a" * 64, "python", "-c"))
            ast.parse(command[4])

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "install"
        self.trusted = self.base / "trusted.pem"
        self.crane = self.base / "crane"
        self.config = self.base / "fleet-config.json"
        self.config.write_text('{"schema":1,"oidc_issuer":null}\n')
        self.token = self.base / "lab-token"
        self.token.write_text("synthetic-fleet-admin-token-0123456789\n")
        self.token.chmod(0o600)
        self.first = self._bundle("first")
        self.second = self._bundle("second")
        self.runtimes = [FleetRuntime("a" * 64, "b" * 64, "c" * 64),
                         FleetRuntime("d" * 64, "e" * 64, "f" * 64),
                         FleetRuntime("1" * 64, "2" * 64, "3" * 64)]

    def _bundle(self, name: str) -> Path:
        path = self.base / name
        path.mkdir()
        (path / "release-manifest.json").write_text(name)
        return path

    def test_update_failure_preserves_active_then_rollback(self) -> None:
        started: list[FleetRuntime] = []
        stopped: list[FleetRuntime] = []

        def start(*args):
            handle = self.runtimes[len(started)]
            started.append(handle)
            return handle

        with patch("infrastructure.deploy.fleet_installer.verify_bundle",
                   return_value={"schema": 5, "target": "fleet"}), \
             patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                   side_effect=start) as launch, \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime",
                   side_effect=stopped.append):
            first = install_fleet(self.first, self.trusted, self.crane,
                                  self.config, self.root, self.token)
            self.assertEqual(first["result"], "activated")
            self.assertEqual(fleet_status(self.root, self.trusted)["active"], first["active"])
            launch.side_effect = RuntimeError("candidate failed health")
            with self.assertRaises(RuntimeError):
                install_fleet(self.second, self.trusted, self.crane,
                              self.config, self.root)
            self.assertEqual(fleet_status(self.root, self.trusted)["active"], first["active"])
            self.assertEqual(stopped, [])
            launch.side_effect = start
            second = install_fleet(self.second, self.trusted, self.crane,
                                   self.config, self.root)
            self.assertEqual(second["previous"], first["active"])
            self.assertEqual(stopped, [self.runtimes[0]])
            restored = rollback_fleet(self.root, self.trusted, self.crane)
            self.assertEqual(restored["active"], first["active"])
            self.assertEqual(stopped, [self.runtimes[0], self.runtimes[1]])

    def test_recovery_preserves_release_and_rejects_wrong_bundle(self) -> None:
        with patch("infrastructure.deploy.fleet_installer.verify_bundle",
                   return_value={"schema": 4}) as verifier:
            with self.assertRaises(FleetInstallError):
                install_fleet(self.first, self.trusted, self.crane,
                              self.config, self.root, self.token)
            self.assertFalse((self.root / "fleet-state.json").exists())
            verifier.return_value = {"schema": 5, "target": "fleet"}
            with patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                       side_effect=self.runtimes[:2]), \
                 patch("infrastructure.deploy.fleet_installer.probe_runtime",
                       side_effect=[RuntimeError("stopped"), RuntimeError("stopped")]), \
                 patch("infrastructure.deploy.fleet_installer.verify_runtime_identity"), \
                 patch("infrastructure.deploy.fleet_installer.stop_runtime") as stop:
                first = install_fleet(self.first, self.trusted, self.crane,
                                      self.config, self.root)
                recovered = recover_fleet(self.root, self.trusted, self.crane)
                self.assertEqual(recovered["active"], first["active"])
                self.assertEqual(recovered["result"], "recovered")
                stop.assert_called_once_with(self.runtimes[0])


if __name__ == "__main__":
    unittest.main()
