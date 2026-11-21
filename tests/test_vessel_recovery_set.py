"""Boundary checks for the stopped vessel's paired recovery receipt."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from infrastructure.deploy.vessel_recovery_set import (
    VesselRecoveryError, _grant_restored_knowledge, _partial_knowledge_resources,
    _match_restored_core, _receipt_payload, _stage_core, _sign_receipt,
    _verify_activation_identity_pair,
    abandon_incomplete_vessel_restore,
    activate_vessel_recovery_set, create_vessel_recovery_set,
    finish_incomplete_vessel_restore,
    retry_abandoned_vessel_restore,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_identity import VesselIdentity
from infrastructure.deploy.vessel_installer import (
    _read_state, _write_intent, _write_private_record,
)
from infrastructure.release.bundle import BundleError, SUPPORTED_VESSEL_COMPATIBILITY
from scripts.synthetic_pg_fixture import fixture, put
from services.policy.audit import AuditLog


class VesselRecoverySetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "config").write_text('{"schema":1,"oidc_issuer":null}')
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

    def test_feed_backed_capture_requires_signed_feed_binding(self) -> None:
        install = self.root / "install"
        install.mkdir(mode=0o700)
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        with patch("infrastructure.deploy.vessel_recovery_set._read_state",
                   return_value={"threat_feed": {"store": "synthetic"}}), \
             self.assertRaisesRegex(VesselRecoveryError, "feed binding receipt"):
            create_vessel_recovery_set(
                install, self.root / "trusted", self.root / "crane",
                self.root / "repository", self.root / "password",
                self.root / "restic", "0" * 64, staging,
                self.root / "signing", self.root / "receipt")

    def test_oidc_activation_requires_all_pair_artifacts(self) -> None:
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        with self.assertRaisesRegex(VesselRecoveryError, "requires signed identity pair"):
            _verify_activation_identity_pair(True, self.root / "receipt",
                self.root / "key", staging, None, None, None, None)
        with self.assertRaisesRegex(VesselRecoveryError, "lab restore cannot accept"):
            _verify_activation_identity_pair(False, self.root / "receipt",
                self.root / "key", staging, self.root / "pair", None, None, None)

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

    def test_oidc_recovery_freezes_ca_and_revocations(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Vessel CA")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                       .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                      critical=True).sign(key, hashes.SHA256()))
        ca = self.state / "oidc-ca.pem"
        put(ca, certificate.public_bytes(serialization.Encoding.PEM))
        revocations = self.state / "oidc-revocations.jsonl"
        put(revocations, b'{"sha256":"' + b"a" * 64 + b'"}\n')
        frozen = self.root / "frozen"
        _stage_core(self.state, frozen, oidc=True)
        self.assertEqual((frozen / "oidc-ca.pem").read_bytes(), ca.read_bytes())
        self.assertEqual((frozen / "oidc-revocations.jsonl").read_bytes(),
                         revocations.read_bytes())
        shutil.rmtree(frozen)
        revocations.write_bytes(revocations.read_bytes().rstrip(b"\n"))
        with self.assertRaises(ValueError):
            _stage_core(self.state, frozen, oidc=True)

    def test_oidc_receipt_requires_identity_hashes_and_exact_file_count(self) -> None:
        payload = {
            "schema": 3, "installation_id": "a" * 32, "release": "b" * 24,
            "data_volume": "sovereign-" + "a" * 32 + "-knowledge-data",
            "snapshot_id": "c" * 64, "repository": str(self.root),
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "schema_version": 1, "audit_count": 1, "audit_tail_hash": "d" * 64,
            "manifest_sha256": "e" * 64, "dump_sha256": "f" * 64,
            "knowledge_sha256": "1" * 64, "sources": 2, "passages": 2,
            "files": 9,
            "identity": {"issuer": "https://identity.vessel.example/realms/sovereign",
                         "ca_sha256": "2" * 64,
                         "revocations_sha256": "3" * 64},
        }
        self.assertEqual(_receipt_payload(payload), payload)
        with self.assertRaises(VesselRecoveryError):
            _receipt_payload({**payload, "files": 7})
        with self.assertRaises(VesselRecoveryError):
            _receipt_payload({**payload, "identity": {**payload["identity"],
                                                       "issuer": "https://outside.example/"}})

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

    def test_oidc_clean_restore_refuses_lab_mode_and_wrong_console_issuer(self) -> None:
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        payload = {"schema": 3, "release": "b" * 24,
                   "identity": {"issuer": "https://identity.vessel.example/realms/sovereign"}}
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=payload), \
             patch("infrastructure.deploy.vessel_recovery_set.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_recovery_set._release_id",
                   return_value="b" * 24):
            with self.assertRaisesRegex(VesselRecoveryError, "identity mode"):
                activate_vessel_recovery_set(
                    self.root / "bundle", self.root / "key", self.root / "crane",
                    self.root / "config", self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "c" * 64,
                    self.root / "new-install", self.root / "new-state",
                    self.root / "lab-password", staging, identity_network="vessel-identity")
            with self.assertRaisesRegex(VesselRecoveryError, "Console issuer"):
                activate_vessel_recovery_set(
                    self.root / "bundle", self.root / "key", self.root / "crane",
                    self.root / "config", self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "c" * 64,
                    self.root / "new-install", self.root / "new-state",
                    None, staging, identity_network="vessel-identity")
        self.assertFalse((self.root / "new-install").exists())

    def test_oidc_clean_restore_activates_without_lab_credential(self) -> None:
        installation = "a" * 32
        release = "b" * 24
        root = self.root / "new-install"
        core_state = self.root / "new-core"
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        pair = self.root / "identity-pair.json"
        put(pair, b"synthetic signed pair")
        stage = self.root / "signed-stage"
        stage.mkdir(mode=0o700)
        issuer = "https://identity.vessel.example/realms/sovereign"
        self.root.joinpath("config").write_text(json.dumps({"schema": 1,
                                                            "oidc_issuer": issuer}))
        (stage / "console-config.json").write_text(
            self.root.joinpath("config").read_text())
        ca_bytes = b"synthetic restore trust"
        revocation_bytes = b'{"sha256":"' + b"c" * 64 + b'"}\n'
        put(self.state / "oidc-ca.pem", ca_bytes)
        put(self.state / "oidc-revocations.jsonl", revocation_bytes)
        receipt = {
            "schema": 3, "release": release, "installation_id": installation,
            "data_volume": f"sovereign-{installation}-knowledge-data",
            "repository": str(self.root / "repository"), "snapshot_id": "d" * 64,
            "sources": 2, "passages": 2, "knowledge_sha256": "e" * 64,
            "audit_count": 1,
            "identity": {"issuer": issuer,
                         "ca_sha256": hashlib.sha256(ca_bytes).hexdigest(),
                         "revocations_sha256": hashlib.sha256(revocation_bytes).hexdigest()},
        }
        identity = VesselIdentity(issuer, core_state / "oidc-ca.pem",
                                  core_state / "oidc-revocations.jsonl",
                                  "vessel-identity", "f" * 64)
        services = RuntimeHandle("1" * 64, "2" * 64, "3" * 64,
                                 identity.network_id, identity.network_name)
        knowledge = KnowledgeVolumeHandle("4" * 64,
                                          "sovereign-knowledge-" + "5" * 12 + "-socket",
                                          receipt["data_volume"],
                                          "sovereign-knowledge-" + "5" * 12,
                                          installation)

        def restore_files(*args):
            restored = args[-1]
            shutil.copytree(self.state, restored)
            (restored / "postgres.dump").write_bytes(b"PGDMPsynthetic")

        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value=receipt), \
             patch("infrastructure.deploy.vessel_recovery_set.verify_bundle",
                   return_value={"schema": 6, "target": "vessel",
                                 "compatibility": SUPPORTED_VESSEL_COMPATIBILITY}), \
             patch("infrastructure.deploy.vessel_recovery_set._release_id",
                   return_value=release), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_activation_identity_pair",
                   return_value="a" * 64), \
             patch("infrastructure.deploy.vessel_recovery_set._assert_missing"), \
             patch("infrastructure.deploy.vessel_recovery_set._docker", return_value=""), \
             patch("infrastructure.deploy.vessel_recovery_set.restore_vessel_recovery_files",
                   side_effect=restore_files), \
             patch("infrastructure.deploy.vessel_recovery_set._stage",
                   return_value=(release, stage)), \
             patch("infrastructure.deploy.vessel_recovery_set.preflight_vessel_identity",
                   return_value=identity), \
             patch("infrastructure.deploy.vessel_recovery_set.start_signed_knowledge",
                   return_value=knowledge), \
             patch("infrastructure.deploy.vessel_recovery_set._state_options"), \
             patch("infrastructure.deploy.vessel_recovery_set._restore"), \
             patch("infrastructure.deploy.vessel_recovery_set._grant_restored_knowledge"), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_knowledge_schema"), \
             patch("infrastructure.deploy.vessel_recovery_set._verify_database",
                   return_value={"sources": 2, "passages": 2,
                                 "knowledge_sha256": "e" * 64}), \
             patch("infrastructure.deploy.vessel_recovery_set.start_signed_vessel_services",
                   return_value=services) as start:
            result = activate_vessel_recovery_set(
                self.root / "bundle", self.root / "key", self.root / "crane",
                self.root / "config", self.root / "receipt", self.root / "receipt-key",
                self.root / "password", self.root / "restic", "0" * 64,
                root, core_state, None, staging, identity_network="vessel-identity",
                identity_pair=pair, identity_pair_key=self.root / "pair-key",
                identity_archive=self.root / "archive",
                identity_archive_key=self.root / "archive-key")
        self.assertEqual(result["result"], "restored-and-activated")
        self.assertEqual(start.call_args.kwargs["identity"], identity)
        active = _read_state(root)
        self.assertEqual(active["schema"], 2)
        self.assertNotIn("lab_password_file", active)
        self.assertEqual((core_state / "oidc-revocations.jsonl").read_bytes(),
                         revocation_bytes)

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

    def test_interrupted_core_copy_must_match_authenticated_snapshot(self) -> None:
        (self.state / "sources" / "ENG-001.txt").chmod(0o644)
        restored = self.root / "restored"
        shutil.copytree(self.state, restored)
        (restored / "postgres.dump").write_bytes(b"PGDMP")
        (restored / "sovereign-snapshot-manifest.json").write_bytes(b"verified")
        _match_restored_core(self.state, restored)
        policy = self.state / "roles.json"
        policy.write_text(policy.read_text().replace("engineer", "outsider"))
        with self.assertRaisesRegex(VesselRecoveryError, "bytes differ"):
            _match_restored_core(self.state, restored)
        policy.write_bytes((restored / "roles.json").read_bytes())
        extra = self.state / "sources" / "unlisted.txt"
        extra.write_bytes(b"unlisted")
        extra.chmod(0o600)
        with self.assertRaisesRegex(VesselRecoveryError, "inventory differs"):
            _match_restored_core(self.state, restored)

    def test_oidc_finish_rejects_different_identity_pair_before_runtime(self) -> None:
        install = self.root / "partial-oidc"
        install.mkdir(mode=0o700)
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        identifier, release, snapshot, attempt = (
            "a" * 32, "b" * 24, "c" * 64, "d" * 32)
        put(self.state / "oidc-ca.pem", b"synthetic certificate")
        put(self.state / "oidc-revocations.jsonl", b"")
        identity = VesselIdentity(
            "https://identity.vessel.example/realms/sovereign",
            self.state / "oidc-ca.pem", self.state / "oidc-revocations.jsonl",
            "vessel-identity", "f" * 64)
        _write_intent(install, release, identifier, self.state, None,
                      identity=identity)
        _write_private_record(install, "vessel-restore-intent.json", {
            "schema": 2, "snapshot_id": snapshot, "release": release,
            "installation_id": identifier, "restore_attempt": attempt,
            "identity_pair_sha256": "e" * 64})
        receipt = {"schema": 3, "snapshot_id": snapshot, "release": release,
                   "installation_id": identifier,
                   "data_volume": f"sovereign-{identifier}-knowledge-data"}
        base = "infrastructure.deploy.vessel_recovery_set."
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_activation_identity_pair", return_value="f" * 64), \
             patch(base + "_docker") as docker:
            with self.assertRaisesRegex(VesselRecoveryError,
                                        "differs from signed identity pair"):
                finish_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "crane",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    staging, identity_pair=self.root / "pair",
                    identity_pair_key=self.root / "pair-key",
                    identity_archive=self.root / "archive",
                    identity_archive_key=self.root / "archive-key")
            docker.assert_not_called()

    def test_finish_incomplete_restore_requires_full_receipt_digest(self) -> None:
        install = self.root / "partial-finish"
        install.mkdir(mode=0o700)
        staging = self.root / "finish-staging"
        staging.mkdir(mode=0o700)
        identifier, release, snapshot, attempt = (
            "a" * 32, "b" * 24, "c" * 64, "d" * 32)
        data = f"sovereign-{identifier}-knowledge-data"
        socket = "sovereign-knowledge-" + "e" * 12 + "-socket"
        container = "f" * 64
        _write_intent(install, release, identifier, self.state,
                      self.root / "lab-password")
        _write_private_record(install, "vessel-restore-intent.json", {
            "schema": 2, "snapshot_id": snapshot, "release": release,
            "installation_id": identifier, "restore_attempt": attempt})
        receipt = {"schema": 2, "snapshot_id": snapshot, "release": release,
                   "installation_id": identifier, "data_volume": data,
                   "repository": str(self.root / "repository"),
                   "sources": 2, "passages": 2, "knowledge_sha256": "1" * 64,
                   "audit_count": 1}
        with patch("infrastructure.deploy.vessel_recovery_set.verify_vessel_recovery_receipt",
                   return_value={**receipt, "schema": 1}), \
             patch("infrastructure.deploy.vessel_recovery_set._docker") as docker:
            with self.assertRaisesRegex(VesselRecoveryError, "row-digest receipt"):
                finish_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "crane",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    staging)
            docker.assert_not_called()
        def restore(*args: object) -> None:
            destination = args[-1]
            shutil.copytree(self.state, destination)
            (destination / "postgres.dump").write_bytes(b"PGDMP")
        scope = [[container], [], [data, socket]]
        base = "infrastructure.deploy.vessel_recovery_set."
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_stage"), \
             patch(base + "_scoped_list", side_effect=scope), \
             patch(base + "_partial_knowledge_resources", return_value=container), \
             patch(base + "probe_knowledge"), \
             patch(base + "restore_vessel_recovery_files", side_effect=restore), \
             patch(base + "_state_options"), \
             patch(base + "_verify_knowledge_schema"), \
             patch(base + "_verify_database", return_value={
                 "sources": 2, "passages": 2, "knowledge_sha256": "0" * 64}), \
             patch(base + "start_signed_vessel_services") as start:
            with self.assertRaisesRegex(VesselRecoveryError, "differs from receipt"):
                finish_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "crane",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    staging)
            start.assert_not_called()
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_stage"), \
             patch(base + "_scoped_list", side_effect=[
                 [container], [], [data, socket], [], [], [data, socket]]), \
             patch(base + "_partial_knowledge_resources", return_value=container), \
             patch(base + "probe_knowledge"), \
             patch(base + "restore_vessel_recovery_files", side_effect=restore), \
             patch(base + "_state_options"), \
             patch(base + "_verify_knowledge_schema"), \
             patch(base + "_verify_database", return_value={
                 "sources": 2, "passages": 2, "knowledge_sha256": "1" * 64}), \
             patch(base + "start_signed_vessel_services") as start:
            with self.assertRaisesRegex(VesselRecoveryError, "changed during"):
                finish_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "crane",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    staging)
            start.assert_not_called()
        services = RuntimeHandle("2" * 64, "3" * 64, "4" * 64)
        def failed_record(root: Path, _payload: object) -> None:
            (root / "vessel-state.json").write_text("{}")
            raise OSError("synthetic fsync failure")
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_stage"), \
             patch(base + "_scoped_list", side_effect=[
                 [container], [], [data, socket],
                 [container], [], [data, socket]]), \
             patch(base + "_partial_knowledge_resources", return_value=container), \
             patch(base + "probe_knowledge"), \
             patch(base + "restore_vessel_recovery_files", side_effect=restore), \
             patch(base + "_state_options"), \
             patch(base + "_verify_knowledge_schema"), \
             patch(base + "_verify_database", return_value={
                 "sources": 2, "passages": 2, "knowledge_sha256": "1" * 64}), \
             patch(base + "start_signed_vessel_services", return_value=services), \
             patch(base + "_write_state", side_effect=failed_record), \
             patch(base + "stop_runtime") as stop:
            with self.assertRaisesRegex(OSError, "fsync failure"):
                finish_incomplete_vessel_restore(
                    install, self.root / "key", self.root / "crane",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    staging)
            stop.assert_called_once_with(services)
        self.assertFalse((install / "vessel-state.json").exists())
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_stage"), \
             patch(base + "_scoped_list", side_effect=[
                 [container], [], [data, socket],
                 [container], [], [data, socket]]), \
             patch(base + "_partial_knowledge_resources", return_value=container), \
             patch(base + "probe_knowledge"), \
             patch(base + "restore_vessel_recovery_files", side_effect=restore), \
             patch(base + "_state_options"), \
             patch(base + "_verify_knowledge_schema"), \
             patch(base + "_verify_database", return_value={
                 "sources": 2, "passages": 2, "knowledge_sha256": "1" * 64}), \
             patch(base + "start_signed_vessel_services",
                   return_value=services) as start, \
             patch(base + "_write_state") as write:
            result = finish_incomplete_vessel_restore(
                install, self.root / "key", self.root / "crane",
                self.root / "receipt", self.root / "receipt-key",
                self.root / "password", self.root / "restic", "0" * 64,
                staging)
            start.assert_called_once()
            write.assert_called_once()
        self.assertEqual(result["recovered_attempt"], attempt)
        self.assertFalse((install / "vessel-restore-intent.json").exists())

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
        receipt = {"schema": 2, "snapshot_id": snapshot, "release": release,
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

    def test_oidc_retry_rejects_pair_changed_from_abandoned_attempt(self) -> None:
        install = self.root / "abandoned-oidc"
        install.mkdir(mode=0o700)
        staging = self.root / "staging"
        staging.mkdir(mode=0o700)
        identifier, release, snapshot, attempt = (
            "a" * 32, "b" * 24, "c" * 64, "d" * 32)
        put(self.state / "oidc-ca.pem", b"synthetic certificate")
        put(self.state / "oidc-revocations.jsonl", b"")
        identity = VesselIdentity(
            "https://identity.vessel.example/realms/sovereign",
            self.state / "oidc-ca.pem", self.state / "oidc-revocations.jsonl",
            "vessel-identity", "f" * 64)
        _write_intent(install, release, identifier, self.state, None,
                      identity=identity)
        _write_private_record(install, "vessel-restore-intent.json", {
            "schema": 2, "snapshot_id": snapshot, "release": release,
            "installation_id": identifier, "restore_attempt": attempt,
            "identity_pair_sha256": "e" * 64})
        _write_private_record(install, "vessel-restore-abandoned.json", {
            "schema": 1, "snapshot_id": snapshot, "installation_id": identifier,
            "restore_attempt": attempt,
            "discarded_utc": datetime.now(timezone.utc).isoformat()})
        receipt = {"schema": 3, "snapshot_id": snapshot, "release": release,
                   "installation_id": identifier,
                   "data_volume": f"sovereign-{identifier}-knowledge-data"}
        base = "infrastructure.deploy.vessel_recovery_set."
        with patch(base + "verify_vessel_recovery_receipt", return_value=receipt), \
             patch(base + "_verify_activation_identity_pair", return_value="f" * 64), \
             patch(base + "activate_vessel_recovery_set") as activate:
            with self.assertRaisesRegex(VesselRecoveryError,
                                        "differs from signed identity pair"):
                retry_abandoned_vessel_restore(
                    install, self.root / "bundle", self.root / "key",
                    self.root / "crane", self.root / "config",
                    self.root / "receipt", self.root / "receipt-key",
                    self.root / "password", self.root / "restic", "0" * 64,
                    self.root / "new-install", self.root / "new-state",
                    None, staging, identity_network="vessel-identity",
                    identity_pair=self.root / "pair",
                    identity_pair_key=self.root / "pair-key",
                    identity_archive=self.root / "archive",
                    identity_archive_key=self.root / "archive-key")
            activate.assert_not_called()

    def test_partial_restore_container_requires_exact_identity(self) -> None:
        identifier = "a" * 32
        data = f"sovereign-{identifier}-knowledge-data"
        run = "sovereign-knowledge-" + "b" * 12
        socket = run + "-socket"
        container = "c" * 64
        labels = {"sovereign.synthetic.install": identifier,
                  "sovereign.synthetic.role": "knowledge",
                  "sovereign.synthetic.run": run,
                  "sovereign.synthetic.restore_attempt": "d" * 32}
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
        labels["sovereign.synthetic.role"] = "knowledge"
        labels["sovereign.synthetic.restore_attempt"] = "e" * 32
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
        receipt = {"schema": 2, "snapshot_id": snapshot, "release": release,
                   "installation_id": identifier, "data_volume": data}
        labels = {"sovereign.synthetic.install": identifier,
                  "sovereign.synthetic.role": "knowledge",
                  "sovereign.synthetic.run": run,
                  "sovereign.synthetic.restore_attempt": attempt}
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
