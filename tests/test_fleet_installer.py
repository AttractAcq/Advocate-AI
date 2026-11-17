"""Synthetic Fleet update state changes only after a healthy candidate."""

from __future__ import annotations

from pathlib import Path
import ast
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.fleet_installer import (
    FleetInstallError, fleet_status, install_fleet, recover_fleet, rollback_fleet,
)
from infrastructure.deploy.fleet_runtime import FleetRuntime, RuntimeError
from infrastructure.deploy.fleet_runtime import (
    _health, start_verified_bundle, validate_config, verify_runtime_identity,
)


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
        commands.clear()
        issuer = "https://identity.example.invalid/realms/fleet"
        with patch("infrastructure.deploy.fleet_runtime._docker",
                   side_effect=lambda *args: commands.append(args) or ""):
            _health("a" * 64, issuer)
        ast.parse(commands[1][4])
        self.assertIn("lab token accepted in OIDC mode", commands[1][4])
        self.assertIn("/protocol/openid-connect/certs", commands[1][4])

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

    def test_oidc_install_uses_separate_roles_and_preserves_network(self) -> None:
        self.config.write_text('{"schema":1,"oidc_issuer":'
                               '"https://identity.example.invalid/realms/fleet"}\n')
        roles = self.base / "roles.json"
        roles.write_text('{"users":[{"id":"admin","role":"fleet_admin",'
                         '"status":"active","customer_codes":["*"]}]}\n')
        roles.chmod(0o600)
        linked = self.base / "linked-roles.json"
        linked.symlink_to(roles)
        with self.assertRaises(FleetInstallError):
            install_fleet(self.first, self.trusted, self.crane,
                          self.config, self.root, roles_file=linked,
                          identity_network="fleet-identity")
        roles.chmod(0o644)
        with self.assertRaises(FleetInstallError):
            install_fleet(self.first, self.trusted, self.crane,
                          self.config, self.root, roles_file=roles,
                          identity_network="fleet-identity")
        roles.chmod(0o600)
        first_handle = FleetRuntime("a" * 64, "b" * 64, "c" * 64,
                                    "9" * 64, "fleet-identity")
        second_handle = FleetRuntime("d" * 64, "e" * 64, "f" * 64,
                                     "9" * 64, "fleet-identity")
        with patch("infrastructure.deploy.fleet_installer.verify_bundle",
                   return_value={"schema": 5, "target": "fleet"}), \
             patch("infrastructure.deploy.fleet_installer.start_verified_bundle",
                   side_effect=[first_handle, second_handle]) as launch, \
             patch("infrastructure.deploy.fleet_installer.probe_runtime"), \
             patch("infrastructure.deploy.fleet_installer.stop_runtime"):
            first = install_fleet(self.first, self.trusted, self.crane,
                                  self.config, self.root, roles_file=roles,
                                  identity_network="fleet-identity")
            self.assertEqual(first["result"], "activated")
            self.assertFalse((self.root / "state" / "token").exists())
            self.assertEqual((self.root / "identity" / "roles.json").read_bytes(),
                             roles.read_bytes())
            self.assertEqual((self.root / "identity" / "roles.json").stat().st_mode & 0o777,
                             0o600)
            with self.assertRaises(FleetInstallError):
                install_fleet(self.second, self.trusted, self.crane,
                              self.config, self.root, identity_network="other-network")
            with self.assertRaises(FleetInstallError):
                install_fleet(self.second, self.trusted, self.crane,
                              self.config, self.root, token_file=self.token)
            updated = install_fleet(self.second, self.trusted, self.crane,
                                    self.config, self.root)
            self.assertEqual(updated["previous"], first["active"])
            self.assertEqual(launch.call_args.args[-1], "fleet-identity")

    def test_oidc_runtime_attaches_only_api_to_labelled_network(self) -> None:
        self.config.write_text('{"schema":1,"oidc_issuer":'
                               '"https://identity.example.invalid/realms/fleet"}\n')
        state = self.base / "state"
        state.mkdir(mode=0o700)
        identity = self.base / "identity"
        identity.mkdir(mode=0o700)
        (identity / "roles.json").write_text(
            '{"users":[{"id":"admin","role":"fleet_admin",'
            '"status":"active","customer_codes":["*"]}]}\n')
        (identity / "roles.json").chmod(0o600)
        commands: list[tuple[str, ...]] = []

        def docker(*args: str) -> str:
            commands.append(args)
            if args[:3] == ("network", "inspect", "fleet-identity"):
                return {"{{.Id}}": "9" * 64, "{{.Internal}}": "true",
                        '{{index .Labels "sovereign.fleet.identity"}}': "true"}[args[-1]]
            if args[:2] == ("network", "create"):
                return "a" * 64
            if args[0] == "run":
                return "b" * 64 if "fleet-api" in args else "c" * 64
            return ""

        with patch("infrastructure.deploy.fleet_runtime.verify_bundle",
                   return_value={"schema": 5, "target": "fleet",
                                 "images": {"fleet-api": {}, "fleet-portal": {}}}), \
             patch("infrastructure.deploy.fleet_runtime._image_id",
                   return_value="d" * 64), \
             patch("infrastructure.deploy.fleet_runtime._docker", side_effect=docker), \
             patch("infrastructure.deploy.fleet_runtime.probe_runtime"):
            handle = start_verified_bundle(self.first, self.trusted, self.crane,
                                           self.config, state, "fleet-identity")
        self.assertEqual(handle.identity_network_id, "9" * 64)
        api = next(args for args in commands if args[0] == "run" and "fleet-api" in args)
        portal = next(args for args in commands if args[0] == "run" and "fleet-portal" in args)
        self.assertIn("SOVEREIGN_FLEET_ROLES_FILE=/etc/fleet-roles.json", api)
        self.assertIn("SOVEREIGN_FLEET_OIDC_ISSUER=https://identity.example.invalid/realms/fleet", api)
        self.assertNotIn("SOVEREIGN_FLEET_TOKEN_FILE=/state/token", api)
        self.assertTrue(any("target=/etc/fleet-roles.json,readonly" in arg for arg in api))
        self.assertFalse(any("roles.json" in arg for arg in portal))
        self.assertIn(("network", "connect", "fleet-identity", "b" * 64), commands)
        with patch("infrastructure.deploy.fleet_runtime.verify_bundle",
                   return_value={"schema": 5, "target": "fleet"}), \
             patch("infrastructure.deploy.fleet_runtime._docker",
                   side_effect=lambda *args: "false" if args[-1] == "{{.Internal}}" else "9" * 64):
            with self.assertRaises(RuntimeError):
                start_verified_bundle(self.first, self.trusted, self.crane,
                                      self.config, state, "fleet-identity")

    def test_oidc_config_requires_https_realm(self) -> None:
        for issuer in ("http://127.0.0.1:18086/realms/fleet",
                       "https://127.0.0.1/realms/fleet",
                       "https://identity.example.invalid:8443/realms/fleet"):
            self.config.write_text('{"schema":1,"oidc_issuer":"' + issuer + '"}')
            with self.subTest(issuer=issuer), self.assertRaises(RuntimeError):
                validate_config(self.config)

    def test_oidc_runtime_identity_rejects_network_mount_and_env_drift(self) -> None:
        issuer = "https://identity.example.invalid/realms/fleet"
        self.config.write_text(json.dumps({"schema": 1, "oidc_issuer": issuer}))
        state = self.base / "state"
        state.mkdir(mode=0o700)
        identity = self.base / "identity"
        identity.mkdir(mode=0o700)
        roles = identity / "roles.json"
        roles.write_text('{"users":[{"id":"admin","role":"fleet_admin",'
                         '"status":"active","customer_codes":["*"]}]}')
        roles.chmod(0o600)
        handle = FleetRuntime("a" * 64, "b" * 64, "c" * 64,
                              "9" * 64, "fleet-identity")
        name = "sovereign-fleet-123456abcdef"
        networks = {
            "fleet-api": {name: {"NetworkID": handle.network_id},
                          "fleet-identity": {"NetworkID": handle.identity_network_id}},
            "fleet-portal": {name: {"NetworkID": handle.network_id}},
        }
        mounts = {
            "fleet-api": [{"Destination": "/state", "Type": "bind",
                           "Source": str(state.resolve()), "RW": True},
                          {"Destination": "/etc/fleet-roles.json", "Type": "bind",
                           "Source": str(roles.resolve()), "RW": False}],
            "fleet-portal": [{"Destination": "/srv/fleet-config.json", "Type": "bind",
                              "Source": str(self.config.resolve()), "RW": False}],
        }
        environment = ["SOVEREIGN_FLEET_DB=/state/fleet.db",
                       f"SOVEREIGN_FLEET_OIDC_ISSUER={issuer}",
                       "SOVEREIGN_FLEET_ROLES_FILE=/etc/fleet-roles.json"]

        def docker(*args: str) -> str:
            if args[:2] == ("network", "inspect"):
                if args[2] == "fleet-identity":
                    return {"{{.Id}}": handle.identity_network_id,
                            "{{.Internal}}": "true",
                            '{{index .Labels "sovereign.fleet.identity"}}': "true"}[args[-1]]
                return {"{{.Name}}": name, "{{.Internal}}": "true",
                        '{{index .Labels "sovereign.fleet.run"}}': name}[args[-1]]
            role = "fleet-api" if args[1] == handle.api_id else "fleet-portal"
            return {
                '{{index .Config.Labels "sovereign.fleet.run"}}': name,
                "{{.Image}}": "d" * 64,
                "{{json .HostConfig.PortBindings}}": "null",
                "{{json .NetworkSettings.Networks}}": json.dumps(networks[role]),
                "{{json .Mounts}}": json.dumps(mounts[role]),
                "{{json .Config.Env}}": json.dumps(environment),
                "{{.Config.User}}": f"{os.getuid()}:{os.getgid()}",
            }[args[-1]]

        manifest = {"schema": 5, "target": "fleet", "images": {
            "fleet-api": {"archive_path": "images/fleet-api.tar"},
            "fleet-portal": {"archive_path": "images/fleet-portal.tar"}}}
        with patch("infrastructure.deploy.fleet_runtime.verify_bundle",
                   return_value=manifest), \
             patch("infrastructure.deploy.fleet_runtime._archive_image_ids",
                   return_value={"d" * 64}), \
             patch("infrastructure.deploy.fleet_runtime._docker", side_effect=docker):
            verify_runtime_identity(handle, self.first, self.trusted, state, self.config)
            networks["fleet-api"].pop("fleet-identity")
            with self.assertRaises(RuntimeError):
                verify_runtime_identity(handle, self.first, self.trusted, state, self.config)
            networks["fleet-api"]["fleet-identity"] = {
                "NetworkID": handle.identity_network_id}
            mounts["fleet-api"][1]["RW"] = True
            with self.assertRaises(RuntimeError):
                verify_runtime_identity(handle, self.first, self.trusted, state, self.config)
            mounts["fleet-api"][1]["RW"] = False
            environment.append("SOVEREIGN_FLEET_TOKEN_FILE=/state/token")
            with self.assertRaises(RuntimeError):
                verify_runtime_identity(handle, self.first, self.trusted, state, self.config)


if __name__ == "__main__":
    unittest.main()
