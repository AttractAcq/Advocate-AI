"""Synthetic two-person policy changes and interrupted activation recovery."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.api.auth import LabSessions
from services.policy.audit import verify
from services.policy.change import (PolicyChangeError, apply_change, create_proposal,
                                    recover_change, sign_proposal)
from services.policy.policy_file import PolicyUnavailable, load_policy


class PolicyChangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = self.root / "roles.json"
        self.candidate = self.root / "candidate.json"
        self.proposal = self.root / "proposal.json"
        self.audit = self.root / "audit.jsonl"
        self.trust = self.root / "trusted-admins.json"
        self.approvals = (self.root / "alice.json", self.root / "bob.json")
        self.old = {"users": [{"id": "engineer", "role": "chief_engineer", "status": "active"}],
                    "allow": {"chief_engineer": ["engineering"], "captain": ["management"]},
                    "document_rules": {}}
        self.new = {**self.old, "users": [{"id": "engineer", "role": "captain", "status": "active"}]}
        self.policy.write_text(json.dumps(self.old), encoding="utf-8")
        self.candidate.write_text(json.dumps(self.new), encoding="utf-8")
        self.keys = {name: Ed25519PrivateKey.generate() for name in ("alice", "bob")}
        self.trust.write_text(json.dumps({"schema": 1, "signers": {
            name: base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
            for name, key in self.keys.items()}}), encoding="utf-8")
        self.trust.chmod(0o600)
        self.now = datetime.now(timezone.utc)
        self.proposal.write_bytes(create_proposal(
            self.policy, self.candidate, "alice", "Synthetic approved role change",
            now=self.now))
        for path, name in zip(self.approvals, ("alice", "bob")):
            path.write_bytes(sign_proposal(self.proposal.read_bytes(), name, self.keys[name], now=self.now))

    def apply(self) -> str:
        return apply_change(self.policy, self.candidate, self.proposal,
                            self.approvals, self.trust, self.audit, now=self.now)

    def test_two_distinct_signatures_apply_exact_candidate_and_revoke_old_role_token(self) -> None:
        sessions = LabSessions(self.policy, "synthetic-test-passphrase")
        token = sessions.login("engineer", "synthetic-test-passphrase")
        self.assertIsNotNone(token)
        request_id = self.apply()
        self.assertEqual(load_policy(self.policy), self.new)
        self.assertFalse((self.root / "roles.json.pending").exists())
        self.assertEqual(verify(self.audit)[0], 2)
        self.assertIn(request_id, self.audit.read_text(encoding="utf-8"))
        evidence = self.root / "policy-change-evidence" / f"{request_id}.json"
        self.assertTrue(evidence.is_file())
        self.assertEqual(evidence.stat().st_mode & 0o077, 0)
        self.assertEqual(base64.b64decode(json.loads(evidence.read_bytes())["candidate"]),
                         self.candidate.read_bytes())
        self.assertIsNone(sessions.user_for(token))
        renewed = sessions.login("engineer", "synthetic-test-passphrase")
        self.assertEqual(sessions.user_for(renewed)["role"], "captain")

    def test_tamper_duplicate_signer_and_expiry_deny_before_mutation(self) -> None:
        original = self.policy.read_bytes()
        self.trust.chmod(0o644)
        with self.assertRaisesRegex(PolicyChangeError, "owner-only"):
            self.apply()
        self.trust.chmod(0o600)
        with self.assertRaisesRegex(PolicyChangeError, "two distinct"):
            apply_change(self.policy, self.candidate, self.proposal,
                         (self.approvals[0], self.approvals[0]), self.trust, self.audit,
                         now=self.now)
        self.candidate.write_text(json.dumps({**self.new, "allow": {"captain": ["restricted"]}}))
        with self.assertRaisesRegex(PolicyChangeError, "hashes"):
            self.apply()
        self.candidate.write_text(json.dumps(self.new))
        with self.assertRaisesRegex(PolicyChangeError, "not current"):
            apply_change(self.policy, self.candidate, self.proposal,
                         self.approvals, self.trust, self.audit,
                         now=self.now + timedelta(hours=2))
        self.assertEqual(self.policy.read_bytes(), original)
        self.assertFalse(self.audit.exists())

    def test_interrupted_activation_blocks_core_and_recovers_old_policy(self) -> None:
        original = self.policy.read_bytes()
        from services.policy import change
        real_replace = change._replace_policy

        def replace_then_interrupt(path: Path, payload: bytes) -> None:
            real_replace(path, payload)
            raise OSError("simulated interruption after replacement")

        with patch("services.policy.change._replace_policy", side_effect=replace_then_interrupt):
            with self.assertRaisesRegex(OSError, "simulated interruption"):
                self.apply()
        self.assertNotEqual(self.policy.read_bytes(), original)
        with self.assertRaisesRegex(PolicyUnavailable, "pending"):
            load_policy(self.policy)
        request_id = json.loads(self.proposal.read_bytes())["request_id"]
        evidence_path = self.root / "policy-change-evidence" / f"{request_id}.json"
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
        evidence["candidate"] = base64.b64encode(b"different candidate").decode("ascii")
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        with self.assertRaisesRegex(PolicyChangeError, "does not match"):
            recover_change(self.policy, self.audit)
        self.assertTrue((self.root / "roles.json.pending").exists())
        evidence_path.write_bytes(evidence_bytes)
        request_id = recover_change(self.policy, self.audit)
        self.assertEqual(request_id, json.loads(self.proposal.read_bytes())["request_id"])
        self.assertEqual(self.policy.read_bytes(), original)
        self.assertFalse((self.root / "roles.json.pending").exists())
        self.assertEqual(verify(self.audit)[0], 2)
        with self.assertRaisesRegex(PolicyChangeError, "already recorded"):
            self.apply()

    def test_offline_cli_requires_owner_only_signer_key(self) -> None:
        proposal = self.root / "cli-proposal.json"
        approvals = (self.root / "cli-alice.json", self.root / "cli-bob.json")
        command = [sys.executable, "-m", "scripts.phase3_policy_admin"]

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run([*command, *args], capture_output=True, text=True, check=False)

        created = run("propose", "--current", str(self.policy), "--candidate", str(self.candidate),
                      "--requester", "alice", "--reason", "Synthetic approved role change",
                      "--out", str(proposal))
        self.assertEqual(created.returncode, 0, created.stderr)
        for path, name in zip(approvals, ("alice", "bob")):
            key_path = self.root / f"{name}.pem"
            key_path.write_bytes(self.keys[name].private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            key_path.chmod(0o644)
            denied = run("approve", "--proposal", str(proposal), "--signer-id", name,
                         "--key", str(key_path), "--out", str(path))
            self.assertNotEqual(denied.returncode, 0)
            self.assertFalse(path.exists())
            key_path.chmod(0o600)
            signed = run("approve", "--proposal", str(proposal), "--signer-id", name,
                         "--key", str(key_path), "--out", str(path))
            self.assertEqual(signed.returncode, 0, signed.stderr)
        applied = run("apply", "--current", str(self.policy), "--candidate", str(self.candidate),
                      "--proposal", str(proposal), "--approval", str(approvals[0]),
                      "--approval", str(approvals[1]), "--trust", str(self.trust),
                      "--audit", str(self.audit))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(load_policy(self.policy), self.new)


if __name__ == "__main__":
    unittest.main()
