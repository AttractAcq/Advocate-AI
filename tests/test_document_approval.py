from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.knowledge.approval import ApprovalError, apply_promotion, create_proposal, sign_proposal
from services.knowledge.manifest_io import load_manifest
from services.knowledge.ingestion import sync_manifest
from services.knowledge.indexed_retrieval import approved_rows
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

    def tearDown(self) -> None:
        self.temp.cleanup()

    def proposal(self) -> bytes:
        return create_proposal(self.sources, self.uploads, self.manifest, str(self.item["id"]),
                               requester="lab-captain-1", document_id="ENG-999",
                               collection="engineering", classification="C0_SYNTHETIC_ENGINEERING",
                               owner="fictional engineering custodian")

    def approvals(self, proposal: bytes) -> tuple[bytes, bytes]:
        return (sign_proposal(proposal, "lab-captain-1", self.keys[0]),
                sign_proposal(proposal, "lab-chief_engineer-1", self.keys[1]))

    def test_two_person_promotion_and_replay_denial(self) -> None:
        proposal = self.proposal()
        self.assertEqual(apply_promotion(self.sources, self.uploads, self.manifest, proposal,
                                        self.approvals(proposal), self.trust, self.audit), "ENG-999")
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
                            self.approvals(proposal), self.trust, self.audit)

    def test_changed_blob_manifest_and_signatures_fail_closed(self) -> None:
        proposal = self.proposal()
        approvals = self.approvals(proposal)
        bad = (approvals[0], approvals[0])
        with self.assertRaises(ValueError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal, bad,
                            self.trust, self.audit)
        blob = self.uploads / f"{self.item['id']}.blob"
        blob.write_bytes(b"replaced")
        with self.assertRaises(ApprovalError):
            apply_promotion(self.sources, self.uploads, self.manifest, proposal, approvals,
                            self.trust, self.audit)
        self.assertFalse((self.sources / "sources/ENG-999.txt").exists())
        self.assertFalse(any(row["document_id"] == "ENG-999" for row in load_manifest(self.manifest)["sources"]))

    def test_unmapped_collection_and_existing_id_rejected(self) -> None:
        for collection, document_id in (("owner", "NEW-001"), ("engineering", "ENG-001")):
            with self.assertRaises(ApprovalError):
                create_proposal(self.sources, self.uploads, self.manifest, str(self.item["id"]),
                                requester="lab-captain-1", document_id=document_id,
                                collection=collection, classification="C0_SYNTHETIC_ENGINEERING",
                                owner="fictional engineering custodian")
