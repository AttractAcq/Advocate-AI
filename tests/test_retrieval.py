from __future__ import annotations

import csv
from pathlib import Path
import shutil
import tempfile
import unittest

from services.knowledge.retrieval import search_fixture_documents

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


class SyntheticRetrievalTests(unittest.TestCase):
    def test_fixed_question_set_retrieval_and_denials(self) -> None:
        with (ROOT / "fixtures/evaluation.csv").open(newline="") as stream:
            cases = list(csv.DictReader(stream))
        users = {"captain": "lab-captain-1", "deckhand": "lab-deckhand-1"}
        self.assertEqual(len(cases), 50)
        for case in cases:
            hits = search_fixture_documents(FIXTURES, users[case["user_role"]], case["question"])
            if case["expected_document_id"] == "DENY":
                self.assertEqual(hits, [], case["question_id"])
            else:
                self.assertTrue(hits, case["question_id"])
                self.assertEqual(hits[0]["document_id"], case["expected_document_id"], case["question_id"])

    def test_selected_source_is_filtered_before_ranking(self) -> None:
        hits = search_fixture_documents(FIXTURES, "lab-captain-1", "verification marker",
                                        document_ids={"ENG-001"}, collections={"engineering"})
        self.assertEqual([hit["document_id"] for hit in hits], ["ENG-001"])

    def test_generic_question_requires_selected_source(self) -> None:
        question = "What actions are required?"
        self.assertEqual(search_fixture_documents(FIXTURES, "lab-captain-1", question), [])
        hits = search_fixture_documents(FIXTURES, "lab-captain-1", question,
                                        document_ids={"ENG-001"})
        self.assertEqual([hit["document_id"] for hit in hits], ["ENG-001"])
        self.assertEqual(search_fixture_documents(FIXTURES, "lab-captain-1", question,
                                                  document_ids={"ENG-001", "DEC-001"}), [])
        self.assertEqual(search_fixture_documents(FIXTURES, "lab-captain-1",
                                                  "Summarize this"), [])
        overview = search_fixture_documents(FIXTURES, "lab-captain-1",
                                            "Summarize this", document_ids={"ENG-001"})
        self.assertEqual([hit["document_id"] for hit in overview], ["ENG-001"])
        self.assertEqual(search_fixture_documents(FIXTURES, "lab-deckhand-1",
                                                  "Summarize this", document_ids={"ENG-001"}), [])

    def test_allowed_source_has_verifiable_citation(self) -> None:
        hits = search_fixture_documents(FIXTURES, "lab-chief_engineer-1", "generator inspection")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["document_id"], "ENG-001")
        self.assertEqual(hits[0]["version"], "1")
        self.assertEqual(len(hits[0]["sha256"]), 64)
        self.assertIn("SYN-ENGINEERING-001-ALPHA", hits[0]["excerpt"])

    def test_unauthorised_and_revoked_users_get_no_text(self) -> None:
        for user in ("lab-deckhand-1", "lab-removed-1", "unknown"):
            hits = search_fixture_documents(FIXTURES, user, "SYN-ENGINEERING-001-ALPHA")
            self.assertEqual(hits, [], user)

    def test_tamper_and_path_escape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            shutil.copy(FIXTURES / "roles.json", base / "roles.json")
            shutil.copy(FIXTURES / "manifest.csv", base / "manifest.csv")
            shutil.copytree(FIXTURES / "sources", base / "sources")
            (base / "sources/ENG-001.txt").write_text("generator inspection injected")
            hits = search_fixture_documents(base, "lab-chief_engineer-1", "generator inspection")
            self.assertNotIn("ENG-001", [hit["document_id"] for hit in hits])

            with (base / "manifest.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            rows[20]["relative_path"] = "../escape.txt"
            with (base / "manifest.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            hits = search_fixture_documents(base, "lab-chief_engineer-1", "generator inspection")
            self.assertNotIn("ENG-001", [hit["document_id"] for hit in hits])

    def test_invalid_query_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            search_fixture_documents(FIXTURES, "lab-captain-1", "")
        with self.assertRaises(ValueError):
            search_fixture_documents(FIXTURES, "lab-captain-1", "x" * 1001)

    def test_symlinked_fixture_is_not_retrieved_even_with_matching_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            shutil.copy(FIXTURES / "roles.json", base / "roles.json")
            shutil.copy(FIXTURES / "manifest.csv", base / "manifest.csv")
            shutil.copytree(FIXTURES / "sources", base / "sources")
            original = base / "sources/ENG-001.txt"
            target = base / "sources/ENG-001-copy.txt"
            original.rename(target)
            original.symlink_to(target)
            hits = search_fixture_documents(base, "lab-chief_engineer-1", "generator inspection")
            self.assertNotIn("ENG-001", [hit["document_id"] for hit in hits])


if __name__ == "__main__":
    unittest.main()
