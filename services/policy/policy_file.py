"""Bounded, fail-closed role policy intake for synthetic Core."""

from __future__ import annotations

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


def read_policy_bytes(path: Path) -> bytes:
    try:
        return read_regular_file(path, MAX_POLICY_BYTES)
    except (OSError, ValueError) as exc:
        raise PolicyUnavailable("role policy unavailable") from exc


def load_policy(path: Path) -> dict[str, object]:
    try:
        policy = json.loads(read_policy_bytes(path), object_pairs_hook=_unique_pairs)
    except PolicyUnavailable:
        raise
    except (ValueError, UnicodeError) as exc:
        raise PolicyUnavailable("role policy unavailable") from exc
    if not isinstance(policy, dict):
        raise PolicyUnavailable("role policy unavailable")
    return policy
