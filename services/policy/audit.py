"""Minimal hash-chained audit trail for the synthetic local lab."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from threading import RLock
import uuid

ZERO = "0" * 64


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verified_state(path: Path) -> tuple[int, str, datetime | None]:
    previous = ZERO
    count = 0
    latest: datetime | None = None
    if not path.exists():
        return count, previous, latest
    with path.open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                raise ValueError("audit record was truncated")
            item = json.loads(line)
            if not isinstance(item, dict) or item.get("sequence") != count + 1 or item.get("previous_hash") != previous:
                raise ValueError("audit sequence or previous hash changed")
            try:
                timestamp = datetime.fromisoformat(item["timestamp"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("audit timestamp is invalid") from exc
            if timestamp.tzinfo is None or (latest is not None and timestamp < latest):
                raise ValueError("audit timestamp regressed")
            digest = item.pop("record_hash", None)
            expected = hashlib.sha256(previous.encode() + _canonical(item)).hexdigest()
            if digest != expected:
                raise ValueError("audit record changed")
            previous = expected
            count += 1
            latest = timestamp
    return count, previous, latest


def verify(path: Path, *, require_current_clock: bool = False) -> tuple[int, str]:
    count, previous, latest = _verified_state(path)
    if require_current_clock and latest is not None and datetime.now(timezone.utc) < latest:
        raise ValueError("local clock precedes the last audit event")
    return count, previous


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count, self._previous, self._latest = _verified_state(path)

    def check_clock(self) -> None:
        """Quick health probe; audited requests still verify the whole chain."""
        with self._lock:
            if self._latest is not None and datetime.now(timezone.utc) < self._latest:
                raise ValueError("local clock precedes the last audit event")

    def append(self, *, actor: str, action: str, resource: str, decision: str,
               policy_version: str, correlation_id: str | None = None) -> str:
        with self._lock:
            count, previous, latest = _verified_state(self.path)
            if (count, previous, latest) != (self._count, self._previous, self._latest):
                raise ValueError("audit trail changed externally")
            now = datetime.now(timezone.utc)
            if latest is not None and now < latest:
                raise ValueError("local clock precedes the last audit event")
            correlation_id = correlation_id or str(uuid.uuid4())
            event: dict[str, object] = {
                "sequence": count + 1, "previous_hash": previous,
                "timestamp": now.isoformat(),
                "actor": actor[:80], "action": action[:80], "resource": resource[:80],
                "decision": decision, "policy_version": policy_version,
                "correlation_id": correlation_id,
            }
            digest = hashlib.sha256(previous.encode() + _canonical(event)).hexdigest()
            event["record_hash"] = digest
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, _canonical(event) + b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._count, self._previous, self._latest = count + 1, digest, now
            return correlation_id
