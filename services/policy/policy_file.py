"""Bounded, fail-closed role policy intake for synthetic Core."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from services.policy.regular_file import read_regular_file

MAX_POLICY_BYTES = 4 * 1024 * 1024


class PolicyUnavailable(ValueError):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyUnavailable("duplicate role policy key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise PolicyUnavailable(f"invalid role policy constant: {value}")


def read_policy_bytes(path: Path) -> bytes:
    try:
        return read_regular_file(path, MAX_POLICY_BYTES)
    except (OSError, ValueError) as exc:
        raise PolicyUnavailable("role policy unavailable") from exc


def load_policy(path: Path) -> dict[str, object]:
    try:
        policy = json.loads(read_policy_bytes(path), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant)
    except PolicyUnavailable:
        raise
    except (ValueError, UnicodeError) as exc:
        raise PolicyUnavailable("role policy unavailable") from exc
    if not isinstance(policy, dict):
        raise PolicyUnavailable("role policy unavailable")
    return policy


def active_user(policy: dict[str, object], user_id: str, *,
                now: datetime | None = None) -> dict[str, object] | None:
    """Resolve exactly one active, unexpired user from the current policy."""
    users = policy.get("users")
    if not isinstance(users, list):
        return None
    matches = [item for item in users if isinstance(item, dict) and item.get("id") == user_id]
    if len(matches) != 1:
        return None
    user = matches[0]
    if user.get("status") != "active" or not isinstance(user.get("role"), str) or not user["role"]:
        return None
    expiry = user.get("expires_at")
    if expiry is not None:
        if not isinstance(expiry, str):
            return None
        try:
            deadline = datetime.fromisoformat(expiry)
        except ValueError:
            return None
        if deadline.tzinfo is None or (now or datetime.now(timezone.utc)) >= deadline:
            return None
    return user
