"""Core audit writes must fail closed if the log path changes."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from services.policy.audit import AuditLog, MAX_RECORD_BYTES, verify


class AuditFileBoundaryTests(unittest.TestCase):
    def test_symlink_replacement_cannot_redirect_an_audit_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "audit.jsonl"
            target = root / "other.txt"
            target.write_text("sentinel", encoding="utf-8")
            audit = AuditLog(path)
            audit.append(actor="crew", action="read", resource="DOC-1",
                         decision="allow", policy_version="synthetic")
            saved = root / "saved.jsonl"
            path.rename(saved)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                verify(path)
            with self.assertRaises(OSError):
                audit.append(actor="crew", action="read", resource="DOC-2",
                             decision="allow", policy_version="synthetic")
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")
            path.unlink()
            saved.rename(path)
            audit.append(actor="crew", action="read", resource="DOC-2",
                         decision="allow", policy_version="synthetic")
            self.assertEqual(verify(path)[0], 2)

    def test_same_content_replacement_and_ambiguous_records_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "audit.jsonl"
            audit = AuditLog(path)
            audit.append(actor="crew", action="read", resource="DOC-1",
                         decision="allow", policy_version="synthetic")
            copied = root / "copied.jsonl"
            copied.write_bytes(path.read_bytes())
            copied.replace(path)
            with self.assertRaisesRegex(ValueError, "changed externally"):
                audit.append(actor="crew", action="read", resource="DOC-2",
                             decision="allow", policy_version="synthetic")
            self.assertEqual(verify(path)[0], 1)
            path.write_text('{"sequence":1,"sequence":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify(path)
            path.write_bytes(b"x" * (MAX_RECORD_BYTES + 1) + b"\n")
            with self.assertRaisesRegex(ValueError, "size limit"):
                verify(path)

    def test_nonregular_audit_path_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                verify(path)


if __name__ == "__main__":
    unittest.main()
