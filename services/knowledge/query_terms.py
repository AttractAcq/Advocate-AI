"""Small, deterministic query normalization shared by guarded search paths."""

from __future__ import annotations

import re

_WORDS = re.compile(r"[a-z0-9]{3,}")
_STOP = {"what", "which", "who", "when", "where", "why", "how", "the", "and", "for",
         "with", "from", "into", "about", "that", "this", "are", "can", "does", "did",
         "tell", "show", "find", "list", "give", "provide", "describe", "explain",
         "summarize", "summary", "overview", "recap", "outline", "please", "there", "their", "your",
         "according", "should", "done"}
_FORMS = {"actions": "action", "required": "require", "requires": "require",
          "requiring": "require", "procedures": "procedure", "documents": "document",
          "manuals": "manual", "sops": "sop", "steps": "step",
          "instructions": "instruction"}
_GENERIC = {"action", "require", "procedure", "document", "manual", "sop",
            "step", "instruction"}


def terms(value: str) -> set[str]:
    """Drop question framing and match common action/require word forms."""
    return {_FORMS.get(word, word) for word in _WORDS.findall(value.casefold())
            if word not in _STOP}


def search_terms(value: str) -> set[str]:
    """Keep a query only when it identifies more than generic document framing."""
    wanted = terms(value)
    return wanted if wanted - _GENERIC else set()


def selected_overview(wanted: set[str], document_ids: set[str] | None) -> bool:
    """An otherwise generic request may inspect one explicitly selected source."""
    return not wanted and document_ids is not None and len(document_ids) == 1
