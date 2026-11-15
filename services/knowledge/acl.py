"""Synthetic manifest mapping and fail-closed source access check."""

from __future__ import annotations

from collections.abc import Mapping
import re

from services.policy.decision import may_read, may_read_document


def source_access(user_id: str, source: Mapping[str, str],
                  policy: Mapping[str, object]) -> bool:
    document_id = source.get("document_id")
    collection = source.get("collection")
    digest = source.get("sha256")
    if not document_id or not collection or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    if not may_read(user_id, collection, policy):
        return False
    return may_read_document(user_id, source, policy)
