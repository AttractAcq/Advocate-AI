from __future__ import annotations

import unittest

from scripts.phase3_procedure_answers import require_expected_outcomes


def case(identifier: str, expected: str | None, citations: list[str],
         *, denied: bool | None = None) -> dict[str, object]:
    return {"case_id": identifier, "expected_document_id": expected,
            "citations": [{"citation": {"document_id": source}} for source in citations],
            "expected_source_cited": expected in citations if expected else None,
            "no_answer_denial": denied}


class ProcedureEvaluationTests(unittest.TestCase):
    def test_accepts_exact_source_and_no_answer_denial(self) -> None:
        require_expected_outcomes([case("allowed", "ENG-006", ["ENG-006"]),
                                   case("denied", None, [], denied=True)])

    def test_rejects_missing_or_extra_citation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "missing, extra"):
            require_expected_outcomes([case("missing", "ENG-006", []),
                                       case("extra", "ENG-006", ["ENG-006", "DEC-001"])])

    def test_rejects_denial_with_answer_or_citation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "answer, citation"):
            require_expected_outcomes([case("answer", None, [], denied=False),
                                       case("citation", None, ["ENG-006"], denied=True)])
