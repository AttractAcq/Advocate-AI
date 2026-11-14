"""Synthetic role decision used only for Phase 1 test fixtures."""

from __future__ import annotations

from collections.abc import Mapping


def may_read(user_id: str, collection: str, policy: Mapping[str, object]) -> bool:
    if collection == "restricted" or not user_id or not collection:
        return False
    users = policy.get("users", [])
    if not isinstance(users, list):
        return False
    user = next((item for item in users
                 if isinstance(item, dict) and item.get("id") == user_id), None)
    if user is None or user.get("status") != "active":
        return False
    allowed = policy.get("allow", {})
    if not isinstance(allowed, dict):
        return False
    role = user.get("role")
    if not isinstance(role, str):
        return False
    collections = allowed.get(role, [])
    return isinstance(collections, list) and collection in collections
