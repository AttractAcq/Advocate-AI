"""Fail closed before Docker receives untrusted restored-state mount paths."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import (
    RuntimeError, RuntimeHandle, _core_state_options, _verify_core_state_runtime,
)


class SignedCoreStateMountTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        (self.state / "sources").mkdir()
        for name in ("roles.json", "manifest.csv", "history.db"):
            path = self.state / name
            path.write_bytes(b"synthetic")
            path.chmod(0o600)
        self.credential = self.root / "credential"
        self.credential.write_text("synthetic-passphrase\n")
        self.credential.chmod(0o600)

    def test_separate_owner_only_paths_produce_runtime_mounts(self) -> None:
        options = _core_state_options(self.state, self.credential)
        self.assertIn("SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign", options)
        self.assertIn("SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password", options)
        self.assertTrue(any("target=/var/lib/sovereign" in item for item in options))
        self.assertTrue(any("target=/run/secrets/lab-password,readonly" in item
                            for item in options))

    def test_upload_quarantine_mount_and_identity_are_enforced(self) -> None:
        upload = self.root / "uploads"
        upload.mkdir(mode=0o700)
        options = _core_state_options(self.state, self.credential, upload_root=upload)
        self.assertIn("SOVEREIGN_UPLOAD_ROOT=/var/lib/sovereign-uploads", options)
        self.assertTrue(any("target=/var/lib/sovereign-uploads" in item for item in options))
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        mounts = [
            {"Destination": "/var/lib/sovereign", "Type": "bind",
             "Source": str(self.state.resolve()), "RW": True},
            {"Destination": "/run/secrets/lab-password", "Type": "bind",
             "Source": str(self.credential.resolve()), "RW": False},
            {"Destination": "/var/lib/sovereign-uploads", "Type": "bind",
             "Source": str(upload.resolve()), "RW": True},
        ]
        environment = ["SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                       "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                       "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                       "SOVEREIGN_UPLOAD_ROOT=/var/lib/sovereign-uploads"]

        def docker(*args: str, timeout: int = 120) -> str:
            if args[-1] == "{{json .Mounts}}":
                return json.dumps(mounts)
            if args[-1] == "{{json .Config.Env}}":
                return json.dumps(environment)
            if args[-1] == "{{.Config.User}}":
                return f"{os.getuid()}:{os.getgid()}"
            raise AssertionError("unexpected Docker inspection")

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            _verify_core_state_runtime(handle, self.state, self.credential,
                                       upload_root=upload)
            mounts[2]["RW"] = False
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential,
                                           upload_root=upload)
            mounts[2]["RW"] = True
            environment.pop()
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential,
                                           upload_root=upload)
        linked = self.root / "linked-uploads"
        linked.symlink_to(upload, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential, upload_root=linked)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential,
                                upload_root=self.state / "sources")

    def test_missing_or_linked_state_and_credential_fail(self) -> None:
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, None)
        linked = self.root / "linked-state"
        linked.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            _core_state_options(linked, self.credential)
        linked_credential = self.root / "linked-credential"
        linked_credential.symlink_to(self.credential)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, linked_credential)

    def test_secret_in_snapshot_and_writable_policy_fail(self) -> None:
        nested_credential = self.state / "snapshot-secret"
        nested_credential.write_text("synthetic-passphrase\n")
        nested_credential.chmod(0o600)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, nested_credential)
        (self.state / "roles.json").chmod(0o666)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential)

    def test_emergency_secret_is_separate_owner_only_and_read_only(self) -> None:
        emergency = self.root / "emergency-password"
        emergency.write_text(secrets.token_urlsafe(24) + "\n")
        emergency.chmod(0o600)
        options = _core_state_options(self.state, self.credential, emergency)
        self.assertIn("SOVEREIGN_EMERGENCY_PASSWORD_FILE=/run/secrets/emergency-password",
                      options)
        self.assertTrue(any("target=/run/secrets/emergency-password,readonly" in item
                            for item in options))
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential, self.credential)
        with self.assertRaises(RuntimeError):
            _core_state_options(None, None, emergency)
        hardlink = self.root / "hardlink-emergency"
        os.link(self.credential, hardlink)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential, hardlink)
        emergency.chmod(0o644)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential, emergency)
        emergency.chmod(0o600)
        linked = self.root / "linked-emergency"
        linked.symlink_to(emergency)
        with self.assertRaises(RuntimeError):
            _core_state_options(self.state, self.credential, linked)

    def test_emergency_mount_identity_detects_removal_or_replacement(self) -> None:
        emergency = self.root / "emergency-password"
        emergency.write_text(secrets.token_urlsafe(24) + "\n")
        emergency.chmod(0o600)
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        mounts = [
            {"Destination": "/var/lib/sovereign", "Type": "bind",
             "Source": str(self.state.resolve()), "RW": True},
            {"Destination": "/run/secrets/lab-password", "Type": "bind",
             "Source": str(self.credential.resolve()), "RW": False},
            {"Destination": "/run/secrets/emergency-password", "Type": "bind",
             "Source": str(emergency.resolve()), "RW": False},
        ]
        environment = ["SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                       "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                       "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                       "SOVEREIGN_EMERGENCY_PASSWORD_FILE=/run/secrets/emergency-password"]
        mounted_digest = hashlib.sha256(emergency.read_bytes()).hexdigest()

        def docker(*args: str, timeout: int = 120) -> str:
            if args[0] == "exec":
                return mounted_digest
            if args[-1] == "{{json .Mounts}}":
                return json.dumps(mounts)
            if args[-1] == "{{json .Config.Env}}":
                return json.dumps(environment)
            if args[-1] == "{{.Config.User}}":
                return f"{os.getuid()}:{os.getgid()}"
            raise AssertionError("unexpected Docker inspection")

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            _verify_core_state_runtime(handle, self.state, self.credential, emergency)
            mounts[2]["RW"] = True
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential, emergency)
            mounts[2]["RW"] = False
            environment.pop()
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential, emergency)
            environment.append("SOVEREIGN_EMERGENCY_PASSWORD_FILE=/run/secrets/emergency-password")
            replacement = self.root / "replacement"
            replacement.write_text(secrets.token_urlsafe(24) + "\n")
            replacement.chmod(0o600)
            replacement.replace(emergency)
            with self.assertRaisesRegex(RuntimeError, "stale"):
                _verify_core_state_runtime(handle, self.state, self.credential, emergency)
            _verify_core_state_runtime(handle, self.state, self.credential, emergency,
                                       allow_stale_emergency=True)
            mounted_digest = hashlib.sha256(emergency.read_bytes()).hexdigest()
            _verify_core_state_runtime(handle, self.state, self.credential, emergency)

    def test_runtime_mount_identity_catches_replaced_state(self) -> None:
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        mounts = [
            {"Destination": "/var/lib/sovereign", "Type": "bind",
             "Source": str(self.state.resolve()), "RW": True},
            {"Destination": "/run/secrets/lab-password",
             "Type": "bind", "Source": str(self.credential.resolve()), "RW": False},
        ]
        environment = ["SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                       "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                       "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password"]

        def docker(*args: str, timeout: int = 120) -> str:
            if args[-1] == "{{json .Mounts}}":
                return json.dumps(mounts)
            if args[-1] == "{{json .Config.Env}}":
                return json.dumps(environment)
            if args[-1] == "{{.Config.User}}":
                return f"{os.getuid()}:{os.getgid()}"
            raise AssertionError("unexpected Docker inspection")

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            _verify_core_state_runtime(handle, self.state, self.credential)
            mounts[0]["Source"] = str(self.root / "other")
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential)
            mounts[0]["Source"] = str(self.state.resolve())
            environment.append("SOVEREIGN_FIXTURE_ROOT=/tmp/other")
            with self.assertRaises(RuntimeError):
                _verify_core_state_runtime(handle, self.state, self.credential)


if __name__ == "__main__":
    unittest.main()
