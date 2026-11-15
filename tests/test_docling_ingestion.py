from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from services.knowledge.ingestion import parse_local, sync_manifest

ROOT = Path(__file__).resolve().parents[1]


class DoclingIngestionTests(unittest.TestCase):
    def test_pdf_docx_xlsx_and_quarantine(self) -> None:
        root = ROOT / "fixtures"
        with tempfile.TemporaryDirectory() as temporary:
            result = sync_manifest(root, root / "phase-3/approved-sources.json",
                                   Path(temporary) / "index.sqlite3")
        self.assertEqual(len(result["indexed"]), 109)
        self.assertEqual(set(result["quarantined"]),
                         {"ENG-P2-DUP", "MALFORMED", "OVERSIZED-DECLARATION"})
        self.assertIn("Cooling pump", parse_local(root / "phase-1/artifacts/ENG-P1.pdf"))
        self.assertIn("maintenance record", parse_local(root / "phase-1/artifacts/ENG-P2.docx"))
        self.assertIn("Test filter", parse_local(root / "phase-1/artifacts/ENG-P3.xlsx"))


if __name__ == "__main__":
    unittest.main()
