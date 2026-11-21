"""Offline, signed threat-feed metadata for AV/IT situational awareness.

Indicators stay out of Core responses and model context. A snapshot is advisory;
it never changes an incident decision or equipment configuration.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_PACKAGE_BYTES = 256 * 1024
MAX_INDICATORS = 500
MAX_AGE = timedelta(days=7)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ThreatSnapshotError(ValueError):
    """The offline feed package or its local store is not trustworthy."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ThreatSnapshotError("duplicate snapshot field")
        result[key] = value
    return result


def _read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ThreatSnapshotError("snapshot input must be a regular single-link file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ThreatSnapshotError("snapshot input is empty or oversized")
    return raw


def _json(raw: bytes) -> dict[str, object]:
    def reject_constant(value: str) -> None:
        raise ThreatSnapshotError("non-finite snapshot value")
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object,
                            parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ThreatSnapshotError("invalid snapshot JSON") from exc
    if not isinstance(result, dict):
        raise ThreatSnapshotError("snapshot must be an object")
    return result


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ThreatSnapshotError("invalid snapshot timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ThreatSnapshotError("invalid snapshot timestamp") from exc
    if result.tzinfo is None:
        raise ThreatSnapshotError("snapshot timestamp needs timezone")
    return result.astimezone(timezone.utc)


def _payload(value: object) -> tuple[dict[str, object], datetime, datetime]:
    if not isinstance(value, dict) or set(value) != {
            "schema", "feed_id", "publisher", "issued_at", "expires_at", "indicators"}:
        raise ThreatSnapshotError("invalid snapshot payload fields")
    if value["schema"] != 1 or isinstance(value["schema"], bool):
        raise ThreatSnapshotError("unsupported snapshot schema")
    for name in ("feed_id", "publisher"):
        if not isinstance(value[name], str) or not _ID.fullmatch(value[name]):
            raise ThreatSnapshotError("invalid snapshot provenance")
    issued = _time(value["issued_at"])
    expires = _time(value["expires_at"])
    if not issued < expires or expires - issued > timedelta(days=30):
        raise ThreatSnapshotError("invalid snapshot validity window")
    rows = value["indicators"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_INDICATORS:
        raise ThreatSnapshotError("invalid snapshot indicator count")
    seen: set[tuple[str, str]] = set()
    ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "kind", "value"}:
            raise ThreatSnapshotError("invalid snapshot indicator")
        identifier, kind, item = row["id"], row["kind"], row["value"]
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or identifier in ids:
            raise ThreatSnapshotError("duplicate or invalid indicator id")
        if (not isinstance(item, str) or len(item) > 253 or
                not isinstance(kind, str) or kind not in {"ipv4", "domain", "sha256"}):
            raise ThreatSnapshotError("invalid indicator value")
        if kind == "ipv4":
            try:
                valid = str(ipaddress.IPv4Address(item)) == item
            except ipaddress.AddressValueError:
                valid = False
        elif kind == "domain":
            valid = bool(_DOMAIN.fullmatch(item) and "." in item and ".." not in item)
        else:
            valid = bool(_HASH.fullmatch(item))
        if not valid or (kind, item) in seen:
            raise ThreatSnapshotError("duplicate or invalid indicator value")
        ids.add(identifier)
        seen.add((kind, item))
    return value, issued, expires


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def trusted_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(_read(path, 4096))
    except (ValueError, TypeError) as exc:
        raise ThreatSnapshotError("invalid trusted snapshot key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ThreatSnapshotError("snapshot key must be Ed25519")
    return key


def sign_payload(payload_path: Path, private_key_path: Path, output: Path) -> None:
    payload, _, _ = _payload(_json(_read(payload_path, MAX_PACKAGE_BYTES)))
    if output.exists() or output.is_symlink():
        raise ThreatSnapshotError("signed snapshot output already exists")
    key_info = private_key_path.stat()
    if (private_key_path.is_symlink() or key_info.st_nlink != 1 or
            stat.S_IMODE(key_info.st_mode) & 0o077):
        raise ThreatSnapshotError("signing key must be private")
    try:
        key = serialization.load_pem_private_key(_read(private_key_path, 4096), password=None)
    except (ValueError, TypeError) as exc:
        raise ThreatSnapshotError("invalid snapshot signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ThreatSnapshotError("snapshot signing key must be Ed25519")
    envelope = {"payload": payload, "signature": base64.b64encode(
        key.sign(_canonical(payload))).decode("ascii")}
    raw = _canonical(envelope) + b"\n"
    if len(raw) > MAX_PACKAGE_BYTES:
        raise ThreatSnapshotError("signed snapshot exceeds size limit")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def verify_package(raw: bytes, key: Ed25519PublicKey) -> tuple[dict[str, object], datetime, datetime]:
    envelope = _json(raw)
    if set(envelope) != {"payload", "signature"} or not isinstance(envelope["signature"], str):
        raise ThreatSnapshotError("invalid signed snapshot envelope")
    payload, issued, expires = _payload(envelope["payload"])
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        key.verify(signature, _canonical(payload))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise ThreatSnapshotError("snapshot signature mismatch") from exc
    return payload, issued, expires


def _store_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir() or
            path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ThreatSnapshotError("snapshot store must be an owner-only directory")


def import_package(package: Path, store: Path, key: Ed25519PublicKey,
                   *, now: datetime | None = None) -> dict[str, object]:
    """Verify local media and replace the current snapshot atomically."""
    _store_directory(store)
    now = now or datetime.now(timezone.utc)
    raw = _read(package, MAX_PACKAGE_BYTES)
    payload, issued, _ = verify_package(raw, key)
    if issued > now.astimezone(timezone.utc) + timedelta(minutes=5):
        raise ThreatSnapshotError("snapshot issue time is in the future")
    target = store / "snapshot.json"
    if target.exists() or target.is_symlink():
        prior, prior_issued, _ = verify_package(_read(target, MAX_PACKAGE_BYTES), key)
        if issued <= prior_issued or payload["feed_id"] != prior["feed_id"]:
            raise ThreatSnapshotError("snapshot rollback or feed change")
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=store)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return {"feed_id": payload["feed_id"], "sha256": hashlib.sha256(raw).hexdigest(),
            "indicator_count": len(payload["indicators"])}


class ThreatSnapshotReader:
    def __init__(self, store: Path, key_path: Path):
        _store_directory(store)
        self.store = store
        self.key = trusted_key(key_path)

    def status(self, *, now: datetime | None = None) -> dict[str, object]:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        path = self.store / "snapshot.json"
        if not path.exists() and not path.is_symlink():
            return {"status": "missing", "warning": "No signed offline threat snapshot is installed."}
        raw = _read(path, MAX_PACKAGE_BYTES)
        payload, issued, expires = verify_package(raw, self.key)
        if issued > now + timedelta(minutes=5):
            raise ThreatSnapshotError("snapshot issue time is in the future")
        age = max(0, int((now - issued).total_seconds() // 3600))
        stale = now >= expires or now - issued > MAX_AGE
        return {"status": "stale" if stale else "current",
                "warning": "Offline threat intelligence is stale; do not treat it as live coverage." if stale else None,
                "feed_id": payload["feed_id"], "publisher": payload["publisher"],
                "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
                "age_hours": age, "indicator_count": len(payload["indicators"]),
                "sha256": hashlib.sha256(raw).hexdigest()}
