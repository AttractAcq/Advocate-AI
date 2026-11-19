from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.knowledge.approval import ApprovalError, apply_promotion, create_proposal, recover_promotion, sign_proposal
from services.knowledge.manifest_io import load_manifest, read_manifest_bytes
from services.knowledge.ingestion import sync_manifest
from services.knowledge.inspection import InspectionError, create_profile
from services.knowledge.indexed_retrieval import SourceManifestError, approved_rows
from services.knowledge.upload_staging import list_uploads, stage_upload
from services.policy.audit import verify


ROOT = Path(__file__).resolve().parents[1]


class DocumentApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.sources = self.base / "fixtures"
        shutil.copytree(ROOT / "fixtures", self.sources)
        self.manifest = self.sources / "phase-3/approved-sources.json"
        self.uploads = self.base / "uploads"
        self.audit = self.base / "audit/events.jsonl"
        self.item = stage_upload(self.uploads, "lab-chief_engineer-1", "new-procedure.txt",
                                 b"Synthetic approved engine procedure.\n")
        self.keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        self.trust = self.base / "trust.json"
        self.trust.write_text(json.dumps({"schema": 1, "signers": {
            name: base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
            for name, key in zip(("lab-captain-1", "lab-chief_engineer-1"), self.keys)}}))
        self.trust.chmod(0o600)
        self.scanner = self.base / "synthetic-clamscan"
        self.scanner.write_text("#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
                                "raw = Path(sys.argv[-1]).read_bytes()\n"
                                "sys.exit(1 if b'synthetic-malware-marker' in raw else "
                                "2 if b'synthetic-scanner-error' in raw else 0)\n")
        self.scanner.chmod(0o700)
        self.database = self.base / "clamav-db"
        self.database.mkdir(mode=0o700)
        (self.database / "synthetic.hdb").write_bytes(b"synthetic-signatures")
        self.profile = self.base / "inspection-profile.json"
        self.profile.write_text(json.dumps({
            "schema": 1, "scanner": str(self.scanner),
            "scanner_sha256": hashlib.sha256(self.scanner.read_bytes()).hexdigest(),
            "database": str(self.database),
            "database_files": {"synthetic.hdb": hashlib.sha256(b"synthetic-signatures").hexdigest()},
            "database_as_of": datetime.now(timezone.utc).isoformat(),
        }))
        self.profile.chmod(0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def proposal(self) -> bytes:
        return create_proposal(self.sources, self.uploads, self.manifest, str(self.item["id"]),
                               requester="lab-captain-1", document_id="ENG-999",
                               collection="engineering", classification="C0_SYNTHETIC_ENGINEERING",
                               owner="fictional engineering custodian", scan_profile=self.profile)

    def approvals(self, proposal: bytes) -> tuple[bytes, bytes]:
        return (sign_proposal(proposal, "lab-captain-1", self.keys[0]),
                sign_proposal(proposal, "lab-chief_engineer-1", self.keys[1]))

    def test_two_person_promotion_and_replay_denial(self) -> None:
        proposal = self.proposal()
        self.assertEqual(apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                        self.approvals(proposal), self.trust, self.audit, self.profile), "ENG-999")
        rows = load_manifest(self.manifest)["sources"]
        self.assertEqual(rows[-1]["document_id"], "ENG-999")
        self.assertEqual((self.sources / rows[-1]["relative_path"]).read_bytes(),
                         b"Synthetic approved engine procedure.\n")
        self.assertEqual(list_uploads(self.uploads, "lab-chief_engineer-1")[0]["status"], "approved")
        self.assertEqual(verify(self.audit)[0], 1)
        database = self.base / "knowledge.sqlite3"
        sync_manifest(self.sources, self.manifest, database)
        engineer = approved_rows(self.sources, self.manifest, database, "lab-chief_engineer-1")
        deckhand = approved_rows(self.sources, self.manifest, database, "lab-deckhand-1")
        self.assertIn("ENG-999", {row["document_id"] for row in engineer})
        self.assertNotIn("ENG-999", {row["document_id"] for row in deckhand})
        with self.assertRaises(ApprovalError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                            self.approvals(proposal), self.trust, self.audit, self.profile)

    def test_changed_blob_manifest_and_signatures_fail_closed(self) -> None:
        proposal = self.proposal()
        approvals = self.approvals(proposal)
        bad = (approvals[0], approvals[0])
        with self.assertRaises(ValueError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal, bad,
                            self.trust, self.audit, self.profile)
        blob = self.uploads / f"{self.item['id']}.blob"
        blob.write_bytes(b"replaced")
        with self.assertRaises(ApprovalError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal, approvals,
                            self.trust, self.audit, self.profile)
        self.assertFalse((self.sources / "sources/ENG-999.txt").exists())
        self.assertFalse(any(row["document_id"] == "ENG-999" for row in load_manifest(self.manifest)["sources"]))

    def test_unmapped_collection_and_existing_id_rejected(self) -> None:
        for collection, document_id in (("owner", "NEW-001"), ("engineering", "ENG-001")):
            with self.assertRaises(ApprovalError):
                create_proposal(self.sources, self.uploads, self.manifest, str(self.item["id"]),
                                requester="lab-captain-1", document_id=document_id,
                                collection=collection, classification="C0_SYNTHETIC_ENGINEERING",
                                owner="fictional engineering custodian", scan_profile=self.profile)

    def test_audit_failure_restores_exact_manifest_and_removes_source(self) -> None:
        proposal = self.proposal()
        original = self.manifest.read_bytes()
        with patch("services.knowledge.approval.AuditLog.append", side_effect=OSError("audit unavailable")):
            with self.assertRaises(OSError):
                apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                self.approvals(proposal), self.trust, self.audit, self.profile)
        self.assertEqual(self.manifest.read_bytes(), original)
        self.assertFalse((self.sources / "sources/ENG-999.txt").exists())
        self.assertEqual(list_uploads(self.uploads, "lab-chief_engineer-1")[0]["status"], "pending")

    def test_interrupted_publication_fails_closed_then_recovers(self) -> None:
        proposal = self.proposal()
        original = self.manifest.read_bytes()
        database = self.base / "knowledge.sqlite3"
        sync_manifest(self.sources, self.manifest, database)
        with patch("services.knowledge.approval.AuditLog.append", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                self.approvals(proposal), self.trust, self.audit, self.profile)
        self.assertTrue((self.manifest.parent / "approved-sources.json.pending").exists())
        with self.assertRaises(ValueError):
            read_manifest_bytes(self.manifest)
        with self.assertRaises(SourceManifestError):
            approved_rows(self.sources, self.manifest, database, "lab-chief_engineer-1")
        self.assertEqual(recover_promotion(self.sources, self.manifest, self.audit),
                         json.loads(proposal)["request_id"])
        self.assertEqual(self.manifest.read_bytes(), original)
        self.assertFalse((self.sources / "sources/ENG-999.txt").exists())
        self.assertEqual(verify(self.audit)[0], 1)
        self.assertFalse((self.manifest.parent / "approved-sources.json.pending").exists())
        self.assertTrue((self.manifest.parent / "document-approval-evidence" /
                         f"{json.loads(proposal)['request_id']}.json").is_file())

    def test_tampered_recovery_evidence_keeps_manifest_closed(self) -> None:
        proposal = self.proposal()
        with patch("services.knowledge.approval.AuditLog.append", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                self.approvals(proposal), self.trust, self.audit, self.profile)
        evidence = self.manifest.parent / "document-approval-evidence" / f"{json.loads(proposal)['request_id']}.json"
        evidence.write_bytes(b"tampered")
        with self.assertRaises(ApprovalError):
            recover_promotion(self.sources, self.manifest, self.audit)
        with self.assertRaises(ValueError):
            read_manifest_bytes(self.manifest)

    def test_exposed_recovery_marker_keeps_manifest_closed(self) -> None:
        proposal = self.proposal()
        with patch("services.knowledge.approval.AuditLog.append", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                self.approvals(proposal), self.trust, self.audit, self.profile)
        marker = self.manifest.parent / "approved-sources.json.pending"
        marker.chmod(0o644)
        with self.assertRaises(ApprovalError):
            recover_promotion(self.sources, self.manifest, self.audit)
        with self.assertRaises(ValueError):
            read_manifest_bytes(self.manifest)

    def test_inspection_rejects_detection_and_scanner_error(self) -> None:
        for marker in (b"synthetic-malware-marker", b"synthetic-scanner-error"):
            item = stage_upload(self.uploads, "lab-chief_engineer-1", "bad.txt", marker)
            with self.assertRaises(InspectionError):
                create_proposal(self.sources, self.uploads, self.manifest, str(item["id"]),
                                requester="lab-captain-1", document_id="ENG-998",
                                collection="engineering", classification="C0_SYNTHETIC_ENGINEERING",
                                owner="fictional engineering custodian", scan_profile=self.profile)
        self.assertFalse((self.sources / "sources/ENG-998.txt").exists())

    def test_signed_proposal_rejects_changed_database_at_apply(self) -> None:
        proposal = self.proposal()
        (self.database / "synthetic.hdb").write_bytes(b"changed-signatures")
        with self.assertRaises(InspectionError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                            self.approvals(proposal), self.trust, self.audit, self.profile)
        self.assertFalse((self.sources / "sources/ENG-999.txt").exists())

    def test_profile_builder_rejects_stale_database(self) -> None:
        fresh = create_profile(self.scanner, self.database, datetime.now(timezone.utc).isoformat())
        self.assertEqual(json.loads(fresh)["database_files"],
                         json.loads(self.profile.read_text())["database_files"])
        with self.assertRaises(InspectionError):
            create_profile(self.scanner, self.database,
                           (datetime.now(timezone.utc) - timedelta(days=31)).isoformat())
