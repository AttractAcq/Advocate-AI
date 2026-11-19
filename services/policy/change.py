"""Two-person, offline role-policy replacement for the synthetic lab."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from services.policy.audit import AuditLog
from services.policy.policy_file import MAX_POLICY_BYTES, parse_policy_bytes, read_policy_bytes
from services.policy.regular_file import read_regular_file

MAX_PROPOSAL_BYTES = 8192
MAX_APPROVAL_BYTES = 2048
MAX_TRUST_BYTES = 64 * 1024
MAX_PENDING_BYTES = 6 * 1024 * 1024
MAX_EVIDENCE_BYTES = 6 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class PolicyChangeError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyChangeError("duplicate policy change key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise PolicyChangeError(f"invalid policy change constant: {value}")


def _parse(raw: bytes, maximum: int) -> dict[str, object]:
    if len(raw) > maximum:
        raise PolicyChangeError("policy change record exceeds size limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs,
                           parse_constant=_reject_constant)
    except (ValueError, UnicodeError) as exc:
        raise PolicyChangeError("invalid policy change JSON") from exc
    if not isinstance(value, dict):
        raise PolicyChangeError("invalid policy change record")
    return value


def _read(path: Path, maximum: int) -> bytes:
    try:
        return read_regular_file(path, maximum)
    except (OSError, ValueError) as exc:
        raise PolicyChangeError("policy change input unavailable") from exc


def _read_trust(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            details = os.fstat(stream.fileno())
            if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                    stat.S_IMODE(details.st_mode) & 0o077):
                raise PolicyChangeError("policy change trust store must be owner-only")
            payload = stream.read(MAX_TRUST_BYTES + 1)
        if len(payload) > MAX_TRUST_BYTES:
            raise PolicyChangeError("policy change trust store exceeds size limit")
        return payload
    except OSError as exc:
        raise PolicyChangeError("policy change trust store unavailable") from exc


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise PolicyChangeError("policy change timestamp missing")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PolicyChangeError("invalid policy change timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyChangeError("policy change timestamp must be aware")
    return parsed.astimezone(timezone.utc)


def _validate_policy(policy: dict[str, object]) -> None:
    users = policy.get("users")
    allowed = policy.get("allow")
    rules = policy.get("document_rules", {})
    if not isinstance(users, list) or not isinstance(allowed, dict) or not isinstance(rules, dict):
        raise PolicyChangeError("candidate role policy has invalid structure")
    identifiers: set[str] = set()
    for user in users:
        if not isinstance(user, dict) or not isinstance(user.get("id"), str) or not _IDENTIFIER.fullmatch(user["id"]):
            raise PolicyChangeError("candidate role policy has invalid user")
        status = user.get("status")
        if user["id"] in identifiers or not isinstance(status, str) or status not in {"active", "revoked"}:
            raise PolicyChangeError("candidate role policy has duplicate or invalid user")
        identifiers.add(user["id"])
        if not isinstance(user.get("role"), str) or user["role"] not in allowed:
            raise PolicyChangeError("candidate role policy has unmapped role")
        if "expires_at" in user:
            _timestamp(user["expires_at"])
    for role, collections in allowed.items():
        if (not isinstance(role, str) or not isinstance(collections, list) or
                any(not isinstance(collection, str) for collection in collections)):
            raise PolicyChangeError("candidate role policy has invalid collection mapping")
        if role == "emergency_recovery" and collections:
            raise PolicyChangeError("emergency role cannot read documents")
    for document_id, rule in rules.items():
        if (not isinstance(document_id, str) or not isinstance(rule, dict) or
                set(rule) - {"deny_users", "allow_roles"}):
            raise PolicyChangeError("candidate role policy has invalid document rule")
        for key in ("deny_users", "allow_roles"):
            if key in rule and (not isinstance(rule[key], list) or
                                any(not isinstance(value, str) for value in rule[key])):
                raise PolicyChangeError("candidate role policy has invalid document rule")


def _proposal(raw: bytes, now: datetime) -> dict[str, object]:
    if now.tzinfo is None:
        raise PolicyChangeError("policy change clock must be aware")
    item = _parse(raw, MAX_PROPOSAL_BYTES)
    if raw != _canonical(item) or set(item) != {
            "schema", "request_id", "requested_by", "reason", "issued_at", "expires_at",
            "current_sha256", "candidate_sha256"} or item["schema"] != 1:
        raise PolicyChangeError("invalid policy change proposal")
    if (not isinstance(item["request_id"], str) or
            not re.fullmatch(r"[0-9a-f]{32}", item["request_id"]) or
            not isinstance(item["requested_by"], str) or
            not _IDENTIFIER.fullmatch(item["requested_by"]) or
            not isinstance(item["reason"], str) or
            not 10 <= len(item["reason"]) <= 500 or
            not all(isinstance(item[key], str) and _DIGEST.fullmatch(item[key])
                    for key in ("current_sha256", "candidate_sha256"))):
        raise PolicyChangeError("invalid policy change proposal")
    issued = _timestamp(item["issued_at"])
    expiry = _timestamp(item["expires_at"])
    if not issued <= now < expiry or expiry - issued > timedelta(hours=24):
        raise PolicyChangeError("policy change proposal is not current")
    return item


def create_proposal(current_path: Path, candidate_path: Path, requester: str,
                    reason: str, *, ttl_minutes: int = 60,
                    now: datetime | None = None) -> bytes:
    if (not isinstance(requester, str) or not _IDENTIFIER.fullmatch(requester) or
            not isinstance(reason, str) or not 10 <= len(reason) <= 500 or
            not isinstance(ttl_minutes, int) or not 1 <= ttl_minutes <= 24 * 60):
        raise PolicyChangeError("invalid policy change request")
    current = read_policy_bytes(current_path)
    candidate = _read(candidate_path, MAX_POLICY_BYTES)
    _validate_policy(parse_policy_bytes(candidate))
    issued = now or datetime.now(timezone.utc)
    if issued.tzinfo is None:
        raise PolicyChangeError("policy change timestamp must be aware")
    issued = issued.astimezone(timezone.utc)
    return _canonical({
        "schema": 1, "request_id": secrets.token_hex(16), "requested_by": requester,
        "reason": reason, "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=ttl_minutes)).isoformat(),
        "current_sha256": hashlib.sha256(current).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
    })


def sign_proposal(raw: bytes, signer_id: str, key: Ed25519PrivateKey,
                  *, now: datetime | None = None) -> bytes:
    if not isinstance(signer_id, str) or not _IDENTIFIER.fullmatch(signer_id):
        raise PolicyChangeError("invalid policy change signer")
    _proposal(raw, now or datetime.now(timezone.utc))
    return _canonical({"signer_id": signer_id,
                       "signature": base64.b64encode(key.sign(raw)).decode("ascii")})


def _verify_approvals(raw: bytes, approvals: tuple[Path, Path], trust_path: Path,
                      requester: str) -> tuple[tuple[str, str], tuple[bytes, bytes], bytes]:
    trust_raw = _read_trust(trust_path)
    trust = _parse(trust_raw, MAX_TRUST_BYTES)
    signers = trust.get("signers")
    if trust.get("schema") != 1 or not isinstance(signers, dict):
        raise PolicyChangeError("invalid policy change trust store")
    names: list[str] = []
    approval_records: list[bytes] = []
    for path in approvals:
        approval_raw = _read(path, MAX_APPROVAL_BYTES)
        approval = _parse(approval_raw, MAX_APPROVAL_BYTES)
        if set(approval) != {"signer_id", "signature"}:
            raise PolicyChangeError("invalid policy change approval")
        name = approval["signer_id"]
        if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name) or name not in signers:
            raise PolicyChangeError("untrusted policy change signer")
        try:
            public = base64.b64decode(signers[name], validate=True)
            signature = base64.b64decode(approval["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise PolicyChangeError("invalid policy change signature") from exc
        names.append(name)
        approval_records.append(approval_raw)
    if len(set(names)) != 2 or requester not in names:
        raise PolicyChangeError("two distinct approved signers are required")
    return (names[0], names[1]), (approval_records[0], approval_records[1]), trust_raw


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_policy(path: Path, payload: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".sovereign-policy-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _create_pending(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_PENDING_BYTES:
        raise PolicyChangeError("policy change recovery record exceeds size limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def _record_evidence(policy_path: Path, request_id: str, proposal: bytes,
                     approvals: tuple[bytes, bytes], trust: bytes, candidate: bytes) -> None:
    directory = policy_path.parent / "policy-change-evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    details = directory.lstat()
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or
            stat.S_IMODE(details.st_mode) & 0o077):
        raise PolicyChangeError("policy change evidence directory must be owner-only")
    payload = _canonical({
        "schema": 1, "request_id": request_id,
        "proposal": base64.b64encode(proposal).decode("ascii"),
        "approvals": [base64.b64encode(item).decode("ascii") for item in approvals],
        "trust": base64.b64encode(trust).decode("ascii"),
        "candidate": base64.b64encode(candidate).decode("ascii"),
    })
    if len(payload) > MAX_EVIDENCE_BYTES:
        raise PolicyChangeError("policy change evidence exceeds size limit")
    try:
        _create_pending(directory / f"{request_id}.json", payload)
    except FileExistsError as exc:
        raise PolicyChangeError("policy change request was already recorded") from exc


def apply_change(policy_path: Path, candidate_path: Path, proposal_path: Path,
                 approvals: tuple[Path, Path], trust_path: Path, audit_path: Path,
                 *, now: datetime | None = None) -> str:
    """Apply an approved synthetic policy; leave a recovery marker on interruption."""
    current_time = now or datetime.now(timezone.utc)
    proposal_raw = _read(proposal_path, MAX_PROPOSAL_BYTES)
    proposal = _proposal(proposal_raw, current_time)
    names, approval_records, trust_raw = _verify_approvals(
        proposal_raw, approvals, trust_path, proposal["requested_by"])
    old = read_policy_bytes(policy_path)
    candidate = _read(candidate_path, MAX_POLICY_BYTES)
    _validate_policy(parse_policy_bytes(candidate))
    old_hash = hashlib.sha256(old).hexdigest()
    new_hash = hashlib.sha256(candidate).hexdigest()
    if old_hash != proposal["current_sha256"] or new_hash != proposal["candidate_sha256"]:
        raise PolicyChangeError("policy change hashes no longer match")
    if old_hash == new_hash:
        raise PolicyChangeError("policy change has no effect")
    pending_path = policy_path.with_name(policy_path.name + ".pending")
    pending = _canonical({
        "schema": 1, "request_id": proposal["request_id"],
        "old_sha256": old_hash, "new_sha256": new_hash,
        "proposal_sha256": hashlib.sha256(proposal_raw).hexdigest(),
        "old_policy": base64.b64encode(old).decode("ascii"),
    })
    audit = AuditLog(audit_path)
    audit.check_clock()
    _record_evidence(policy_path, proposal["request_id"], proposal_raw,
                     approval_records, trust_raw, candidate)
    audit.append(actor=proposal["requested_by"], action="policy-change-authorized",
                 resource=proposal["request_id"], decision="allow:" + ",".join(names),
                 policy_version=old_hash)
    _create_pending(pending_path, pending)
    # A crash after this point leaves Core fail-closed until recover_change runs.
    if hashlib.sha256(_read(policy_path, MAX_POLICY_BYTES)).hexdigest() != old_hash:
        raise PolicyChangeError("role policy changed during activation")
    _replace_policy(policy_path, candidate)
    audit.append(actor=proposal["requested_by"], action="policy-change-applied",
                 resource=proposal["request_id"], decision="allow",
                 policy_version=new_hash)
    os.unlink(pending_path)
    _sync_directory(policy_path.parent)
    return proposal["request_id"]


def recover_change(policy_path: Path, audit_path: Path) -> str:
    """Restore the prior policy from an interrupted change and clear its marker."""
    pending_path = policy_path.with_name(policy_path.name + ".pending")
    record = _parse(_read(pending_path, MAX_PENDING_BYTES), MAX_PENDING_BYTES)
    if set(record) != {"schema", "request_id", "old_sha256", "new_sha256",
                       "proposal_sha256", "old_policy"} or record["schema"] != 1:
        raise PolicyChangeError("invalid policy change recovery record")
    try:
        old = base64.b64decode(record["old_policy"], validate=True)
    except (ValueError, TypeError) as exc:
        raise PolicyChangeError("invalid policy change recovery bytes") from exc
    if (len(old) > MAX_POLICY_BYTES or hashlib.sha256(old).hexdigest() != record["old_sha256"] or
            not isinstance(record["request_id"], str) or
            not re.fullmatch(r"[0-9a-f]{32}", record["request_id"])):
        raise PolicyChangeError("invalid policy change recovery digest")
    current = _read(policy_path, MAX_POLICY_BYTES)
    if hashlib.sha256(current).hexdigest() not in {record["old_sha256"], record["new_sha256"]}:
        raise PolicyChangeError("unexpected policy state during recovery")
    audit = AuditLog(audit_path)
    audit.check_clock()
    _replace_policy(policy_path, old)
    audit.append(actor="offline-recovery", action="policy-change-recovered",
                 resource=record["request_id"], decision="rollback",
                 policy_version=record["old_sha256"])
    os.unlink(pending_path)
    _sync_directory(policy_path.parent)
    return record["request_id"]
