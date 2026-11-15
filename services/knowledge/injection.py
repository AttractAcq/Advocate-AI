"""Conservative screen for instruction-like text in untrusted passages."""

from __future__ import annotations

import base64
import re

_PHRASES = (
    "ignore previous instructions", "ignore all instructions", "reveal ",
    "system prompt", "developer message", "execute this", "do not execute",
    "untrusted text", "override policy", "send to http", "send to https",
)
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def instruction_like(text: str) -> bool:
    folded = text.casefold()
    if any(phrase in folded for phrase in _PHRASES):
        return True
    for match in _HEX.finditer(text):
        try:
            decoded = bytes.fromhex(match.group()).decode("utf-8").casefold()
        except (ValueError, UnicodeError):
            continue
        if any(phrase in decoded for phrase in _PHRASES):
            return True
    for match in _B64.finditer(text):
        try:
            decoded = base64.b64decode(match.group(), validate=True).decode("utf-8").casefold()
        except (ValueError, UnicodeError):
            continue
        if any(phrase in decoded for phrase in _PHRASES):
            return True
    return False
