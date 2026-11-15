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


def verify(path: Path) -> tuple[int, str]:
    previous = ZERO
    count = 0
    if not path.exists():
        return count, previous
    with path.open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                raise ValueError("audit record was truncated")
            item = json.loads(line)
            if not isinstance(item, dict) or item.get("sequence") != count + 1 or item.get("previous_hash") != previous:
                raise ValueError("audit sequence or previous hash changed")
            digest = item.pop("record_hash", None)
            expected = hashlib.sha256(previous.encode() + _canonical(item)).hexdigest()
            if digest != expected:
                raise ValueError("audit record changed")
            previous = expected
            count += 1
    return count, previous


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count, self._previous = verify(path)

    def append(self, *, actor: str, action: str, resource: str, decision: str,
               policy_version: str, correlation_id: str | None = None) -> str:
        with self._lock:
            count, previous = verify(self.path)
            if (count, previous) != (self._count, self._previous):
                raise ValueError("audit trail changed externally")
            correlation_id = correlation_id or str(uuid.uuid4())
            event: dict[str, object] = {
                "sequence": count + 1, "previous_hash": previous,
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
            self._count, self._previous = count + 1, digest
            return correlation_id
