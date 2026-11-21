"""Small, deterministic query normalization shared by guarded search paths."""

from __future__ import annotations

import re

_WORDS = re.compile(r"[a-z0-9]{3,}")
_STOP = {"what", "which", "who", "when", "where", "why", "how", "the", "and", "for",
         "with", "from", "into", "about", "that", "this", "are", "can", "does", "did",
         "tell", "please", "there", "their", "your", "according", "should", "done"}
_FORMS = {"actions": "action", "required": "require", "requires": "require",
          "requiring": "require"}


def terms(value: str) -> set[str]:
    """Drop question framing and match common action/require word forms."""
    return {_FORMS.get(word, word) for word in _WORDS.findall(value.casefold())
            if word not in _STOP}
