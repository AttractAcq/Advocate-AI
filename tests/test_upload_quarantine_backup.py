from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.upload_quarantine_backup import (
    MAX_ARCHIVE, MAX_TOTAL, UploadBackupError, _extract_archive, _read_inventory,
    _scan_inventory, _write_archive, _write_archive_from_root,
    create_upload_snapshot, restore_upload_snapshot,
)
from services.knowledge.ingestion import MAX_BYTES
from services.knowledge.upload_staging import stage_upload


class UploadQuarantineBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.uploads = self.root / "uploads"
        self.uploads.mkdir(mode=0o700)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        self.record = stage_upload(self.uploads, "lab-engineer", "fictional.txt",
                                   b"Fictional engineering notes.\n")

    def test_archive_round_trip_and_clean_destination(self) -> None:
        files, rows = _read_inventory(self.uploads)
        archive = self.staging / "quarantine.zip"
        _write_archive(archive, files, rows)
        restored = self.root / "restored"
        self.assertEqual(_extract_archive(archive, restored), 2)
        self.assertEqual(_read_inventory(restored), (files, rows))
        with self.assertRaisesRegex(UploadBackupError, "new destination"):
            _extract_archive(archive, restored)

    def test_tampered_or_orphaned_upload_rejected(self) -> None:
        blob = self.uploads / f"{self.record['id']}.blob"
        blob.write_bytes(b"different")
        with self.assertRaisesRegex(UploadBackupError, "do not match"):
            _read_inventory(self.uploads)
        blob.unlink()
        with self.assertRaisesRegex(UploadBackupError, "do not match"):
            _read_inventory(self.uploads)

    def test_unexpected_link_and_unsafe_permissions_rejected(self) -> None:
        link = self.uploads / "extra"
        link.symlink_to(self.root)
        with self.assertRaisesRegex(UploadBackupError, "unexpected"):
            _read_inventory(self.uploads)
        link.unlink()
        metadata = self.uploads / f"{self.record['id']}.json"
        metadata.chmod(0o644)
        with self.assertRaisesRegex(UploadBackupError, "unsafe"):
            _read_inventory(self.uploads)

    def test_approved_metadata_has_no_blob(self) -> None:
        blob = self.uploads / f"{self.record['id']}.blob"
        blob.unlink()
        metadata = self.uploads / f"{self.record['id']}.json"
        record = {**self.record, "status": "approved"}
        metadata.write_text(json.dumps(record))
        self.assertEqual(len(_read_inventory(self.uploads)[1]), 1)
        blob.write_bytes(b"Fictional engineering notes.\n")
        blob.chmod(0o600)
        with self.assertRaisesRegex(UploadBackupError, "retains"):
            _read_inventory(self.uploads)

    def test_restic_adapter_uses_only_private_single_archive(self) -> None:
        def fake_create(spec: Path, repository: Path, password: Path, restic: Path,
                        digest: str, staging: Path, *, max_file: int) -> dict[str, object]:
            self.assertEqual(max_file, MAX_ARCHIVE)
            definition = json.loads(spec.read_text())
            self.assertEqual(len(definition["files"]), 1)
            self.assertEqual(definition["files"][0]["name"], "upload-quarantine.zip")
            self.assertEqual(_extract_archive(spec.parent / "upload-quarantine.zip",
                                              self.root / "checked"), 2)
            return {"status": "snapshot-verified", "snapshot_id": "a" * 64, "files": 1}

        with patch("infrastructure.upload_quarantine_backup.create_snapshot",
                   side_effect=fake_create):
            created = create_upload_snapshot(self.uploads, self.root / "repo",
                self.root / "password", self.root / "restic", "b" * 64, self.staging)
        self.assertEqual(created["quarantine_files"], 2)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_streaming_profile_covers_full_pending_queue_and_detects_change(self) -> None:
        self.assertGreaterEqual(MAX_TOTAL, 100 * MAX_BYTES)
        payload = b"x" * MAX_BYTES
        for number in range(3):
            stage_upload(self.uploads, "lab-engineer", f"fictional-{number}.txt", payload)
        rows = _scan_inventory(self.uploads)
        self.assertEqual(len(rows), 8)
        archive = self.staging / "streamed.zip"
        _write_archive_from_root(archive, self.uploads, rows)
        restored = self.root / "streamed-restore"
        self.assertEqual(_extract_archive(archive, restored), 8)
        self.assertEqual(_scan_inventory(restored), rows)
        blob = self.uploads / f"{self.record['id']}.blob"
        blob.write_bytes(b"changed")
        with self.assertRaisesRegex(UploadBackupError, "changed"):
            _write_archive_from_root(self.staging / "denied.zip", self.uploads, rows)

    def test_restore_rejects_non_quarantine_snapshot(self) -> None:
        def fake_restore(snapshot: str, repository: Path, password: Path,
                         restic: Path, digest: str, target: Path) -> dict[str, object]:
            target.mkdir()
            (target / "other.txt").write_text("wrong scope")
            return {"files": 1}

        destination = self.root / "restored"
        with patch("infrastructure.upload_quarantine_backup.restore_snapshot",
                   side_effect=fake_restore):
            with self.assertRaisesRegex(UploadBackupError, "not an upload"):
                restore_upload_snapshot("a" * 64, self.root / "repo",
                    self.root / "password", self.root / "restic", "b" * 64,
                    destination)
        self.assertFalse(destination.exists())

    def test_restore_accepts_restic_manifest_only_alongside_archive(self) -> None:
        files, rows = _read_inventory(self.uploads)

        def fake_restore(snapshot: str, repository: Path, password: Path,
                         restic: Path, digest: str, target: Path) -> dict[str, object]:
            target.mkdir()
            _write_archive(target / "upload-quarantine.zip", files, rows)
            (target / "sovereign-snapshot-manifest.json").write_text("checked by adapter")
            return {"files": 1}

        destination = self.root / "restored"
        with patch("infrastructure.upload_quarantine_backup.restore_snapshot",
                   side_effect=fake_restore):
            result = restore_upload_snapshot("a" * 64, self.root / "repo",
                self.root / "password", self.root / "restic", "b" * 64,
                destination)
        self.assertEqual(result["quarantine_files"], 2)
        self.assertEqual(_read_inventory(destination), (files, rows))


if __name__ == "__main__":
    unittest.main()
