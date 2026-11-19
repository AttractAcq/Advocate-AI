"""Offline, signed synthetic upload promotion into the approved manifest."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.knowledge.ingestion import MAX_BYTES, SUPPORTED, _valid_source
from services.knowledge.inspection import inspect_document
from services.knowledge.manifest_io import MAX_MANIFEST_BYTES, load_manifest, read_manifest_bytes
from services.knowledge.upload_staging import _directory, _metadata, quarantine_directory_lock
from services.policy.audit import AuditLog
from services.policy.change import _canonical, _read_trust, _verify_approvals
from services.policy.policy_file import load_policy, policy_directory_lock, read_policy_bytes
from services.policy.regular_file import read_regular_file

_ID = re.compile(r"[A-Z0-9][A-Z0-9_-]{2,79}\Z")
_UPLOAD_ID = re.compile(r"[0-9a-f]{32}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,119}\Z")


class ApprovalError(ValueError):
    pass


def _staged(upload_root: Path, upload_id: str) -> tuple[dict[str, object], bytes]:
    if not _UPLOAD_ID.fullmatch(upload_id):
        raise ApprovalError("invalid upload id")
    _directory(upload_root)
    item = _metadata(upload_root, f"{upload_id}.json")
    if item.get("id") != upload_id or item.get("status") != "pending":
        raise ApprovalError("upload is not pending")
    raw = read_regular_file(upload_root / f"{upload_id}.blob", MAX_BYTES)
    if (not raw or len(raw) != item.get("size") or
            hashlib.sha256(raw).hexdigest() != item.get("sha256")):
        raise ApprovalError("staged content changed")
    return item, raw


def _separate_roots(source_root: Path, upload_root: Path) -> None:
    if (not upload_root.is_absolute() or upload_root.is_symlink() or
            upload_root.resolve() == source_root.resolve() or
            upload_root.resolve() in source_root.resolve().parents or
            source_root.resolve() in upload_root.resolve().parents):
        raise ApprovalError("upload area overlaps approved sources")


def _proposal(raw: bytes, *, require_current: bool = True,
              allow_legacy: bool = False) -> dict[str, object]:
    if len(raw) > 4096:
        raise ApprovalError("approval proposal too large")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ApprovalError("invalid approval proposal") from exc
    expected = {"schema", "operation", "request_id", "requested_by", "upload_id",
                "upload_sha256", "manifest_sha256", "document_id", "collection",
                "classification", "owner", "version", "suffix", "issued_at", "expires_at"}
    if isinstance(value, dict) and value.get("schema") == 2:
        expected.add("inspection_profile_sha256")
    if not isinstance(value, dict) or set(value) != expected or raw != _canonical(value):
        raise ApprovalError("invalid approval proposal")
    if (value["schema"] != 2 and not (allow_legacy and value["schema"] == 1)) or value["operation"] != "synthetic-document-promotion":
        raise ApprovalError("invalid approval domain")
    for key, pattern in (("request_id", _UPLOAD_ID), ("upload_id", _UPLOAD_ID),
                         ("document_id", _ID)):
        if not isinstance(value[key], str) or not pattern.fullmatch(value[key]):
            raise ApprovalError("invalid approval identifier")
    for key in ("requested_by", "collection", "classification", "owner", "version"):
        if not isinstance(value[key], str) or not _LABEL.fullmatch(value[key]):
            raise ApprovalError("invalid approval metadata")
    if value["suffix"] not in SUPPORTED:
        raise ApprovalError("unsupported source type")
    for key in ("upload_sha256", "manifest_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ApprovalError("invalid approval digest")
    if value["schema"] == 2 and (not isinstance(value["inspection_profile_sha256"], str) or
                                   not re.fullmatch(r"[0-9a-f]{64}", value["inspection_profile_sha256"])):
        raise ApprovalError("invalid inspection profile digest")
    try:
        issued = datetime.fromisoformat(value["issued_at"])
        expires = datetime.fromisoformat(value["expires_at"])
    except (ValueError, TypeError) as exc:
        raise ApprovalError("invalid approval time") from exc
    now = datetime.now(timezone.utc)
    if (issued.tzinfo is None or expires.tzinfo is None or
            not issued < expires or expires - issued > timedelta(hours=24) or
            (require_current and not issued <= now < expires)):
        raise ApprovalError("approval proposal expired or invalid")
    return value


def create_proposal(source_root: Path, upload_root: Path, manifest: Path,
                    upload_id: str, *, requester: str, document_id: str,
                    collection: str, classification: str, owner: str,
                    scan_profile: Path,
                    version: str = "1") -> bytes:
    _separate_roots(source_root, upload_root)
    with quarantine_directory_lock(upload_root, exclusive=False):
        item, payload = _staged(upload_root, upload_id)
    suffix = Path(str(item["filename"])).suffix.lower()
    inspection_profile_sha256 = inspect_document(payload, suffix, scan_profile)
    now = datetime.now(timezone.utc)
    raw = _canonical({
        "schema": 2, "operation": "synthetic-document-promotion",
        "request_id": uuid4().hex, "requested_by": requester,
        "upload_id": upload_id, "upload_sha256": item["sha256"],
        "manifest_sha256": hashlib.sha256(read_manifest_bytes(manifest)).hexdigest(),
        "document_id": document_id, "collection": collection,
        "classification": classification, "owner": owner, "version": version,
        "suffix": suffix, "issued_at": now.isoformat(),
        "inspection_profile_sha256": inspection_profile_sha256,
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    })
    proposal = _proposal(raw)
    _validate_destination(source_root, manifest, proposal)
    return raw


def sign_proposal(raw: bytes, signer_id: str, key: Ed25519PrivateKey) -> bytes:
    _proposal(raw)
    if not _LABEL.fullmatch(signer_id):
        raise ApprovalError("invalid signer")
    return _canonical({"signer_id": signer_id,
                       "signature": base64.b64encode(key.sign(raw)).decode("ascii")})


def _validate_destination(source_root: Path, manifest: Path,
                          proposal: dict[str, object]) -> tuple[dict[str, object], Path]:
    if not source_root.is_absolute() or source_root.is_symlink():
        raise ApprovalError("invalid source root")
    if (not manifest.is_absolute() or manifest.is_symlink() or
            source_root.resolve() not in manifest.resolve().parents):
        raise ApprovalError("manifest must be inside approved source root")
    source_dir = source_root / "sources"
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise ApprovalError("invalid approved source directory")
    policy = load_policy(source_root / "roles.json")
    allowed = policy.get("allow", {})
    if (not isinstance(allowed, dict) or
            proposal["collection"] not in {name for names in allowed.values()
                                           if isinstance(names, list) for name in names}):
        raise ApprovalError("collection has no policy mapping")
    payload = load_manifest(manifest)
    if not isinstance(payload, dict) or payload.get("schema") != 1 or not isinstance(payload.get("sources"), list):
        raise ApprovalError("invalid approved manifest")
    if (any(not isinstance(row, dict) or row.get("document_id") == proposal["document_id"]
            or row.get("sha256") == proposal["upload_sha256"] for row in payload["sources"])):
        raise ApprovalError("duplicate source id or content")
    target = source_dir / f"{proposal['document_id']}{proposal['suffix']}"
    if os.path.lexists(target):
        raise ApprovalError("approved source path exists")
    return payload, target


def _atomic_bytes(path: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".sovereign-approved-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, value: object) -> None:
    _atomic_bytes(path, _canonical(value))


def _write_new(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_private(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) & 0o077):
            raise ApprovalError("approval recovery file must be owner-only")
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ApprovalError("approval recovery file too large")
    return content


def _evidence_path(manifest: Path, request_id: str) -> Path:
    directory = manifest.parent / "document-approval-evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    details = directory.lstat()
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or
            stat.S_IMODE(details.st_mode) & 0o077):
        raise ApprovalError("approval evidence directory must be owner-only")
    return directory / f"{request_id}.json"


def _pending_path(manifest: Path) -> Path:
    return manifest.with_name(manifest.name + ".pending")


def _parse_record(raw: bytes, expected: set[str], maximum: int) -> dict[str, object]:
    if len(raw) > maximum:
        raise ApprovalError("approval recovery record too large")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ApprovalError("invalid approval recovery record") from exc
    if not isinstance(value, dict) or set(value) != expected or raw != _canonical(value):
        raise ApprovalError("invalid approval recovery record")
    return value


def _decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 4 // 3 + 8:
        raise ApprovalError("invalid approval recovery encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ApprovalError("invalid approval recovery encoding") from exc
    if len(raw) > maximum:
        raise ApprovalError("approval recovery field too large")
    return raw


def apply_promotion(source_root: Path, upload_root: Path, manifest: Path,
                    proposal_raw: bytes, approvals: tuple[bytes, bytes],
                    trust_path: Path, audit_path: Path, scan_profile: Path) -> str:
    proposal = _proposal(proposal_raw)
    _separate_roots(source_root, upload_root)
    trust = _read_trust(trust_path)
    _verify_approvals(proposal_raw, approvals, trust, str(proposal["requested_by"]))
    with quarantine_directory_lock(upload_root, exclusive=False):
        staged_item, staged_bytes = _staged(upload_root, str(proposal["upload_id"]))
    if (staged_item["sha256"] != proposal["upload_sha256"] or
            inspect_document(staged_bytes, str(proposal["suffix"]), scan_profile) !=
            proposal["inspection_profile_sha256"]):
        raise ApprovalError("signed inspection inputs changed")
    audit = AuditLog(audit_path)
    audit.check_clock()
    with policy_directory_lock(source_root / "roles.json", exclusive=True), \
            quarantine_directory_lock(upload_root, exclusive=True):
        item, raw = _staged(upload_root, str(proposal["upload_id"]))
        old_manifest = read_manifest_bytes(manifest)
        if (item["sha256"] != proposal["upload_sha256"] or
                Path(str(item["filename"])).suffix.lower() != proposal["suffix"] or
                hashlib.sha256(old_manifest).hexdigest() != proposal["manifest_sha256"]):
            raise ApprovalError("approval inputs changed")
        payload, target = _validate_destination(source_root, manifest, proposal)
        row = {"document_id": proposal["document_id"], "relative_path": f"sources/{target.name}",
               "sha256": item["sha256"], "collection": proposal["collection"],
               "classification": proposal["classification"], "owner": proposal["owner"],
               "version": proposal["version"], "source_type": "synthetic-approved-upload"}
        updated = {**payload, "sources": [*payload["sources"], row]}
        updated_raw = _canonical(updated)
        if len(updated_raw) > MAX_MANIFEST_BYTES:
            raise ApprovalError("approved manifest would exceed size limit")
        evidence = _canonical({
            "schema": 1, "request_id": proposal["request_id"],
            "proposal": base64.b64encode(proposal_raw).decode("ascii"),
            "approvals": [base64.b64encode(value).decode("ascii") for value in approvals],
            "trust": base64.b64encode(trust).decode("ascii"),
        })
        _write_new(_evidence_path(manifest, str(proposal["request_id"])), evidence)
        pending = _pending_path(manifest)
        _write_new(pending, _canonical({
            "schema": 1, "request_id": proposal["request_id"],
            "old_manifest": base64.b64encode(old_manifest).decode("ascii"),
            "old_sha256": proposal["manifest_sha256"],
            "new_sha256": hashlib.sha256(updated_raw).hexdigest(),
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        }))
        audit_recorded = False
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _valid_source(source_root, row)
            # The Core request lock prevents a partial promotion from reaching a reader.
            _atomic_bytes(manifest, updated_raw)
            audit.append(actor=str(proposal["requested_by"]), action="document-promoted",
                         resource=str(proposal["request_id"]), decision="allow",
                         policy_version=hashlib.sha256(read_policy_bytes(source_root / "roles.json")).hexdigest())
            audit_recorded = True
            pending.unlink()
            try:
                _atomic_json(upload_root / f"{proposal['upload_id']}.json", {**item, "status": "approved"})
                (upload_root / f"{proposal['upload_id']}.blob").unlink(missing_ok=True)
            except Exception:
                # The signed manifest and audit are authoritative; stale staging
                # metadata can be repaired without granting any extra access.
                pass
            return str(proposal["document_id"])
        except Exception:
            if audit_recorded:
                # Leave the marker in place if finalisation failed after the
                # allow event. Recovery records an explicit rollback event.
                raise
            # Ordinary failures restore the exact previous manifest. A process
            # interruption leaves the marker for investigated offline recovery.
            _atomic_bytes(manifest, old_manifest)
            target.unlink(missing_ok=True)
            pending.unlink()
            raise


def recover_promotion(source_root: Path, manifest: Path, audit_path: Path) -> str:
    """Fail-closed rollback of an interrupted signed promotion."""
    pending_path = _pending_path(manifest)
    marker = _parse_record(_read_private(pending_path, 12 * 1024 * 1024),
                           {"schema", "request_id", "old_manifest", "old_sha256",
                            "new_sha256", "evidence_sha256"}, 12 * 1024 * 1024)
    request_id = marker["request_id"]
    if marker["schema"] != 1 or not isinstance(request_id, str) or not _UPLOAD_ID.fullmatch(request_id):
        raise ApprovalError("invalid approval recovery marker")
    old_manifest = _decode(marker["old_manifest"], MAX_MANIFEST_BYTES)
    if hashlib.sha256(old_manifest).hexdigest() != marker["old_sha256"]:
        raise ApprovalError("approval recovery manifest digest mismatch")
    evidence = _read_private(_evidence_path(manifest, request_id), 96 * 1024)
    if hashlib.sha256(evidence).hexdigest() != marker["evidence_sha256"]:
        raise ApprovalError("approval recovery evidence changed")
    packet = _parse_record(evidence, {"schema", "request_id", "proposal", "approvals", "trust"}, 96 * 1024)
    if packet["schema"] != 1 or packet["request_id"] != request_id or not isinstance(packet["approvals"], list) or len(packet["approvals"]) != 2:
        raise ApprovalError("invalid approval recovery evidence")
    proposal_raw = _decode(packet["proposal"], 4096)
    proposal = _proposal(proposal_raw, require_current=False, allow_legacy=True)
    approvals = tuple(_decode(value, 2048) for value in packet["approvals"])
    trust = _decode(packet["trust"], 64 * 1024)
    _verify_approvals(proposal_raw, approvals, trust, str(proposal["requested_by"]))
    if (proposal["request_id"] != request_id or proposal["manifest_sha256"] != marker["old_sha256"]):
        raise ApprovalError("approval recovery proposal mismatch")
    target = source_root / "sources" / f"{proposal['document_id']}{proposal['suffix']}"
    audit = AuditLog(audit_path)
    audit.check_clock()
    with policy_directory_lock(source_root / "roles.json", exclusive=True):
        current = read_regular_file(manifest, MAX_MANIFEST_BYTES)
        if hashlib.sha256(current).hexdigest() not in {marker["old_sha256"], marker["new_sha256"]}:
            raise ApprovalError("unexpected manifest during recovery")
        if os.path.lexists(target):
            if hashlib.sha256(read_regular_file(target, MAX_BYTES)).hexdigest() != proposal["upload_sha256"]:
                raise ApprovalError("approved source changed during recovery")
        _atomic_bytes(manifest, old_manifest)
        target.unlink(missing_ok=True)
        audit.append(actor="offline-recovery", action="document-promotion-recovered",
                     resource=request_id, decision="rollback",
                     policy_version=hashlib.sha256(read_policy_bytes(source_root / "roles.json")).hexdigest())
        pending_path.unlink()
    return request_id
