"""Boundary checks for the stopped vessel's paired recovery receipt."""

from __future__ import annotations

import json
import os
import shutil
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.vessel_recovery_set import (
    VesselRecoveryError, _grant_restored_knowledge, _partial_knowledge_resources,
    _stage_core, _sign_receipt,
    abandon_incomplete_vessel_restore,
    activate_vessel_recovery_set, retry_abandoned_vessel_restore,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_installer import _write_intent, _write_private_record
from infrastructure.release.bundle import BundleError, SUPPORTED_VESSEL_COMPATIBILITY
from scripts.synthetic_pg_fixture import fixture, put
from services.policy.audit import AuditLog


class VesselRecoverySetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        fixture(self.state)
        AuditLog(self.state / "audit.jsonl").append(
            actor="engineer", action="read", resource="synthetic",
            decision="allow", policy_version="1")
        with closing(sqlite3.connect(self.state / "history.db")) as database:
            database.execute("""CREATE TABLE conversations (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL)""")
            database.execute("CREATE INDEX conversations_owner ON conversations(owner)")
            database.execute("INSERT INTO conversations VALUES (?,?,?)",
                             ("synthetic", "engineer", "[]"))
            database.execute("PRAGMA user_version=1")
            database.commit()
        (self.state / "history.db").chmod(0o600)

    def test_freezes_full_private_core_inventory(self) -> None:
        frozen = self.root / "frozen"
        count, checkpoint, digest = _stage_core(self.state, frozen)
        self.assertEqual(count, 2)
        self.assertEqual(checkpoint[0], 1)
        self.assertEqual(len(digest), 64)
        self.assertEqual((frozen / "sources/ENG-001.txt").read_bytes(),
                         (self.state / "sources/ENG-001.txt").read_bytes())
        with closing(sqlite3.connect(frozen / "history.db")) as database:
            self.assertEqual(database.execute("SELECT id FROM conversations").fetchone(),
                             ("synthetic",))

    def test_capture_refuses_future_core_history_format(self) -> None:
        with closing(sqlite3.connect(self.state / "history.db")) as database:
            database.execute("PRAGMA user_version=2")
            database.commit()
        with self.assertRaisesRegex(VesselRecoveryError, "conversation database snapshot"):
            _stage_core(self.state, self.root / "frozen")

    def test_unlisted_source_denies_capture(self) -> None:
        put(self.state / "sources/unlisted.txt", b"secret")
        with self.assertRaisesRegex(VesselRecoveryError, "inventory"):
            _stage_core(self.state, self.root / "frozen")

    def test_hard_linked_core_file_denies_capture(self) -> None:
        for relative in ("approved.json", "roles.json", "audit.jsonl",
                         "history.db", "sources/ENG-001.txt"):
            with self.subTest(relative=relative):
                alias = self.root / "external-alias"
                os.link(self.state / relative, alias)
                try:
                    with self.assertRaises(VesselRecoveryError):
                        _stage_core(self.state, self.root / "frozen")
                finally:
                    alias.unlink()
                    if (self.root / "frozen").exists():
                        shutil.rmtree(self.root / "frozen")

    def test_signed_receipt_rejects_tampering(self) -> None:
        key = Ed25519PrivateKey.generate()
        private = self.root / "private.pem"
        public = self.root / "public.pem"
        put(private, key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        put(public, key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        receipt = self.root / "receipt.json"
        identifier = "a" * 32
        payload = {
            "schema": 1, "installation_id": identifier, "release": "b" * 24,
            "data_volume": f"sovereign-{identifier}-knowledge-data",
            "snapshot_id": "c" * 64, "repository": str(self.root / "repository"),
            "created_utc": "2026-11-20T12:00:00+00:00", "schema_version": 1,
            "audit_count": 1, "audit_tail_hash": "d" * 64,
            "manifest_sha256": "e" * 64, "dump_sha256": "f" * 64,
            "sources": 2, "passages": 2, "files": 7,
        }
        _sign_receipt(receipt, payload, private)
        self.assertEqual(verify_vessel_recovery_receipt(receipt, public), payload)
        envelope = json.loads(receipt.read_text())
        envelope["signature"] = "A" * len(envelope["signature"])
        receipt.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(VesselRecoveryError, "verification failed"):
            verify_vessel_recovery_receipt(receipt, public)

    def test_digest_receipt_requires_exact_row_hash(self) -> None:
        key = Ed25519PrivateKey.generate()
        private = self.root / "digest-private.pem"
        public = self.root / "digest-public.pem"
        put(private, key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        put(public, key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        identifier = "a" * 32
        payload = {
            "schema": 2, "installation_id": identifier, "release": "b" * 24,
            "data_volume": f"sovereign-{identifier}-knowledge-data",
            "snapshot_id": "c" * 64, "repository": str(self.root / "repository"),
            "created_utc": "2026-11-20T12:00:00+00:00", "schema_version": 1,
            "audit_count": 1, "audit_tail_hash": "d" * 64,
            "manifest_sha256": "e" * 64, "dump_sha256": "f" * 64,
            "knowledge_sha256": "1" * 64,
            "sources": 2, "passages": 2, "files": 7,
        }
        receipt = self.root / "digest-receipt.json"
        _sign_receipt(receipt, payload, private)
        self.assertEqual(verify_vessel_recovery_receipt(receipt, public), payload)
        payload["knowledge_sha256"] = "invalid"
        bad = self.root / "bad-digest-receipt.json"
        _sign_receipt(bad, payload, private)
        with self.assertRaisesRegex(VesselRecoveryError, "verification failed"):
            verify_vessel_recovery_receipt(bad, public)

    def test_clean_activation_refuses_existing_data_volume(self) -> None:
        identifier = "a" * 32
        payload = {"schema": 1, "installation_id": identifier,
                   "release": "b" * 24,
                   "data_volume": f"sovereign-{identifier}-knowledge-data"}
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        put(self.root / "lab-password", b"synthetic-private-password\n")
        payload["repository"] = str(self.root / "repository")
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_recovery_set.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_recovery_set._release_id",
                   return_value="b" * 24), \
             patch("infrastructure.deploy.vessel_recovery_set._assert_missing",
                   side_effect=VesselRecoveryError("volume already exists")), \
             patch("infrastructure.deploy.vessel_recovery_set._cleanup_failed_install") as cleanup:
            with self.assertRaisesRegex(VesselRecoveryError, "volume already exists"):
                activate_vessel_recovery_set(
                    self.root / "bundle", self.root / "key", self.root / "crane",
                    self.root / "config", self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "c" * 64,
                    self.root / "new-install", self.root / "new-state",
                    self.root / "lab-password", staging)
        self.assertFalse((self.root / "new-install").exists())
        cleanup.assert_not_called()

    def test_clean_activation_rejects_future_contract_before_restore(self) -> None:
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value={"release": "b" * 24}), \
             patch("infrastructure.deploy.vessel_recovery_set.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": {"knowledge_schema": 2,
                                                   "core_state_schema": 1}}), \
             patch("infrastructure.deploy.vessel_recovery_set.restore_vessel_recovery_files") as restore:
            with self.assertRaisesRegex(BundleError, "unsupported vessel compatibility"):
                activate_vessel_recovery_set(
                    self.root / "bundle", self.root / "key", self.root / "crane",
                    self.root / "config", self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "c" * 64,
                    self.root / "new-install", self.root / "new-state",
                    self.root / "lab-password", staging)
            restore.assert_not_called()
        self.assertFalse((self.root / "new-install").exists())

    def test_restricted_table_grants_follow_clean_restore(self) -> None:
        def sql(_container: str, statement: str) -> str:
            if "SELECT tablename FROM pg_tables" in statement:
                return "\n".join(sorted(("knowledge_sources", "knowledge_passages",
                    "knowledge_quarantine", "knowledge_vectors",
                    "knowledge_schema_version")))
            if "has_table_privilege" in statement:
                return "1:0:1:0"
            return ""

        with patch("infrastructure.deploy.vessel_recovery_set.postgres_sql",
                   side_effect=sql) as query, \
             patch("infrastructure.deploy.vessel_recovery_set.verify_security") as security:
            _grant_restored_knowledge("a" * 64)
        security.assert_called_once_with("a" * 64)
        statements = [call.args[1] for call in query.call_args_list]
        self.assertEqual(sum(item.startswith("ALTER TABLE") for item in statements), 5)
        self.assertTrue(any("TO sovereign_ingest" in item for item in statements))
        self.assertTrue(any("TO sovereign_read" in item for item in statements))

    def test_partial_restore_abandon_requires_receipt_and_exact_volume(self) -> None:
        install = self.root / "partial-install"
        install.mkdir(mode=0o700)
        identifier = "a" * 32
        release = "b" * 24
        snapshot = "c" * 64
        restore_attempt = "d" * 32
        data_volume = f"sovereign-{identifier}-knowledge-data"
        _write_intent(install, release, identifier, self.state,
                      self.root / "lab-password")
        _write_private_record(install, "vessel-restore-intent.json", {
            "schema": 2, "snapshot_id": snapshot, "release": release,
            "installation_id": identifier,
            "restore_attempt": restore_attempt})
        receipt = {"snapshot_id": snapshot, "release": release,
                   "installation_id": identifier, "data_volume": data_volume}
        with self.assertRaisesRegex(VesselRecoveryError, "explicit flag"):
            abandon_incomplete_vessel_restore(
                install, self.root / "key", self.root / "receipt",
                self.root / "receipt-key", discard_partial_data=False)
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value={**receipt, "snapshot_id": "d" * 64}), \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            with self.assertRaisesRegex(VesselRecoveryError, "differs"):
                abandon_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "receipt",
                    self.root / "receipt-key", discard_partial_data=True)
        docker.assert_not_called()
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_stage"), \
             patch("infrastructure.deploy.vessel_recovery_set._scoped_list",
                   side_effect=[[], [], [data_volume]]), \
             patch("infrastructure.deploy.vessel_recovery_set._volume",
                   side_effect=VesselRecoveryError("attempt label mismatch")), \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            with self.assertRaisesRegex(VesselRecoveryError, "attempt label"):
                abandon_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "receipt",
                    self.root / "receipt-key", discard_partial_data=True)
        docker.assert_not_called()
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_stage"), \
             patch("infrastructure.deploy.vessel_recovery_set._scoped_list",
                   side_effect=[[], [], [data_volume], [], [], []]), \
             patch("infrastructure.deploy.vessel_recovery_set._volume"), \
             patch("infrastructure.deploy.vessel_recovery_set._assert_missing"), \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            result = abandon_incomplete_vessel_restore(
                install, self.root / "key", self.root / "receipt",
                self.root / "receipt-key", discard_partial_data=True)
        self.assertEqual(result["result"], "abandoned")
        docker.assert_called_once_with("volume", "rm", data_volume)
        self.assertTrue((install / "vessel-restore-intent.json").exists())
        self.assertTrue((install / "vessel-restore-abandoned.json").exists())
        self.assertTrue(self.state.exists())
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_stage"), \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            with self.assertRaisesRegex(VesselRecoveryError, "already abandoned"):
                abandon_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "receipt",
                    self.root / "receipt-key", discard_partial_data=True)
        docker.assert_not_called()
        args = (install, self.root / "bundle", self.root / "key",
                self.root / "crane", self.root / "config", self.root / "receipt",
                self.root / "receipt-key", self.root / "password",
                self.root / "restic", "e" * 64, self.root / "new-install",
                self.root / "new-state", self.root / "lab-password",
                self.root / "staging")
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_stage"), \
             patch("infrastructure.deploy.vessel_recovery_set.activate_vessel_recovery_set",
                   return_value={"result": "restored-and-activated"}) as activate:
            retried = retry_abandoned_vessel_restore(*args)
        self.assertEqual(retried["retry_of_attempt"], restore_attempt)
        activate.assert_called_once()
        abandoned = install / "vessel-restore-abandoned.json"
        changed = json.loads(abandoned.read_text())
        changed["snapshot_id"] = "f" * 64
        abandoned.write_text(json.dumps(changed))
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set.activate_vessel_recovery_set") as activate:
            with self.assertRaisesRegex(VesselRecoveryError, "differs"):
                retry_abandoned_vessel_restore(*args)
        activate.assert_not_called()

    def test_partial_restore_container_requires_exact_identity(self) -> None:
        identifier = "a" * 32
        data = f"sovereign-{identifier}-knowledge-data"
        run = "sovereign-knowledge-" + "b" * 12
        socket = run + "-socket"
        container = "c" * 64
        labels = {"sovereign.synthetic.install": identifier,
                  "sovereign.synthetic.role": "knowledge",
                  "sovereign.synthetic.run": run}
        mounts = [{"Destination": "/var/lib/postgresql/data",
                   "Type": "volume", "Name": data},
                  {"Destination": "/var/run/postgresql",
                   "Type": "volume", "Name": socket}]
        def inspect(*args: str) -> str:
            if args[-1] == "{{json .Config.Labels}}":
                return json.dumps(labels)
            if args[-1] == "{{json .Mounts}}":
                return json.dumps(mounts)
            if args[-1] == "{{.Name}}":
                return "/" + run
            if args[-1] == "{{.HostConfig.NetworkMode}}":
                return "none"
            if args[-1] == "{{json .HostConfig.PortBindings}}":
                return "null"
            raise AssertionError(args)
        with patch("infrastructure.deploy.vessel_recovery_set._volume") as volume, \
             patch("infrastructure.deploy.vessel_recovery_set._docker",
                   side_effect=inspect):
            self.assertEqual(_partial_knowledge_resources(
                identifier, data, "d" * 32, [container], [], [data, socket]),
                container)
        self.assertEqual(volume.call_count, 2)
        labels["sovereign.synthetic.role"] = "console"
        with patch("infrastructure.deploy.vessel_recovery_set._volume"), \
             patch("infrastructure.deploy.vessel_recovery_set._docker",
                   side_effect=inspect):
            with self.assertRaisesRegex(VesselRecoveryError, "identity mismatch"):
                _partial_knowledge_resources(
                    identifier, data, "d" * 32, [container], [], [data, socket])
        with patch("infrastructure.deploy.vessel_recovery_set._volume") as volume:
            with self.assertRaisesRegex(VesselRecoveryError, "unexpected"):
                _partial_knowledge_resources(
                    identifier, data, "d" * 32, [], ["e" * 64], [data])
            volume.assert_not_called()
        with patch("infrastructure.deploy.vessel_recovery_set._volume") as volume, \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            self.assertIsNone(_partial_knowledge_resources(
                identifier, data, "d" * 32, [], [], [data, socket]))
            self.assertEqual(volume.call_count, 2)
            docker.assert_not_called()

    def test_abandon_removes_only_verified_partial_knowledge_run(self) -> None:
        install = self.root / "crashed-restore"
        install.mkdir(mode=0o700)
        identifier, release, snapshot = "a" * 32, "b" * 24, "c" * 64
        attempt = "d" * 32
        data = f"sovereign-{identifier}-knowledge-data"
        run = "sovereign-knowledge-" + "e" * 12
        socket = run + "-socket"
        container = "f" * 64
        _write_intent(install, release, identifier, self.state,
                      self.root / "lab-password")
        _write_private_record(install, "vessel-restore-intent.json", {
            "schema": 2, "snapshot_id": snapshot, "release": release,
            "installation_id": identifier, "restore_attempt": attempt})
        receipt = {"snapshot_id": snapshot, "release": release,
                   "installation_id": identifier, "data_volume": data}
        labels = {"sovereign.synthetic.install": identifier,
                  "sovereign.synthetic.role": "knowledge",
                  "sovereign.synthetic.run": run}
        mounts = [{"Destination": "/var/lib/postgresql/data",
                   "Type": "volume", "Name": data},
                  {"Destination": "/var/run/postgresql",
                   "Type": "volume", "Name": socket}]
        removed: list[tuple[str, ...]] = []
        def docker(*args: str) -> str:
            if args[0] == "inspect":
                lookup = {"{{json .Config.Labels}}": json.dumps(labels),
                          "{{json .Mounts}}": json.dumps(mounts),
                          "{{.Name}}": "/" + run,
                          "{{.HostConfig.NetworkMode}}": "none",
                          "{{json .HostConfig.PortBindings}}": "null"}
                return lookup[args[-1]]
            removed.append(args)
            return ""
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_stage"), \
             patch("infrastructure.deploy.vessel_recovery_set._scoped_list",
                   side_effect=[[container], [], [data, socket], [], [], []]), \
             patch("infrastructure.deploy.vessel_recovery_set._volume"), \
             patch("infrastructure.deploy.vessel_recovery_set._assert_missing"), \
             patch("infrastructure.deploy.vessel_recovery_set._docker",
                   side_effect=docker):
            result = abandon_incomplete_vessel_restore(
                install, self.root / "key", self.root / "receipt",
                self.root / "receipt-key", discard_partial_data=True)
        self.assertEqual(result["result"], "abandoned")
        self.assertEqual(removed, [("rm", "-f", container),
                                   ("volume", "rm", socket),
                                   ("volume", "rm", data)])


if __name__ == "__main__":
    unittest.main()
