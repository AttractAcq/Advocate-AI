"""Synthetic role decision used only for Phase 1 test fixtures."""

from __future__ import annotations

from collections.abc import Mapping

from services.policy.policy_file import active_user


def may_read_document(user_id: str, source: Mapping[str, str], policy: Mapping[str, object]) -> bool:
    """Apply source classification and vessel-approved per-document overrides.

    Unknown labels and malformed rules deny access. This lab policy accepts only
    synthetic records; a vessel policy must be explicitly approved separately.
    """
    classification = source.get("classification", "")
    collection = source.get("collection", "")
    if classification != f"C0_SYNTHETIC_{collection.upper()}":
        return False
    document_id = source.get("document_id", "")
    rules = policy.get("document_rules", {})
    if not isinstance(rules, dict):
        return False
    rule = rules.get(document_id)
    if rule is None:
        return True
    if not isinstance(rule, dict):
        return False
    user = active_user(dict(policy), user_id)
    if user is None:
        return False
    denied = rule.get("deny_users", [])
    allowed = rule.get("allow_roles")
    if not isinstance(denied, list) or any(not isinstance(value, str) for value in denied):
        return False
    if allowed is not None and (not isinstance(allowed, list) or
                                any(not isinstance(value, str) for value in allowed)):
        return False
    return user_id not in denied and (allowed is None or user.get("role") in allowed)


def may_read(user_id: str, collection: str, policy: Mapping[str, object]) -> bool:
    if collection == "restricted" or not user_id or not collection:
        return False
    user = active_user(dict(policy), user_id)
    if user is None:
        return False
    allowed = policy.get("allow", {})
    if not isinstance(allowed, dict):
        return False
    role = user.get("role")
    if not isinstance(role, str):
        return False
    collections = allowed.get(role, [])
    return isinstance(collections, list) and collection in collections
