"""Offline, signed synthetic upload promotion into the approved manifest."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.knowledge.ingestion import MAX_BYTES, SUPPORTED, _valid_source
from services.knowledge.manifest_io import MAX_MANIFEST_BYTES, load_manifest, read_manifest_bytes
from services.knowledge.upload_staging import _directory, _metadata
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


def _proposal(raw: bytes) -> dict[str, object]:
    if len(raw) > 4096:
        raise ApprovalError("approval proposal too large")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ApprovalError("invalid approval proposal") from exc
    expected = {"schema", "operation", "request_id", "requested_by", "upload_id",
                "upload_sha256", "manifest_sha256", "document_id", "collection",
                "classification", "owner", "version", "suffix", "issued_at", "expires_at"}
    if not isinstance(value, dict) or set(value) != expected or raw != _canonical(value):
        raise ApprovalError("invalid approval proposal")
    if value["schema"] != 1 or value["operation"] != "synthetic-document-promotion":
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
    try:
        issued = datetime.fromisoformat(value["issued_at"])
        expires = datetime.fromisoformat(value["expires_at"])
    except (ValueError, TypeError) as exc:
        raise ApprovalError("invalid approval time") from exc
    now = datetime.now(timezone.utc)
    if (issued.tzinfo is None or expires.tzinfo is None or
            not issued <= now < expires or expires - issued > timedelta(hours=24)):
        raise ApprovalError("approval proposal expired or invalid")
    return value


def create_proposal(source_root: Path, upload_root: Path, manifest: Path,
                    upload_id: str, *, requester: str, document_id: str,
                    collection: str, classification: str, owner: str,
                    version: str = "1") -> bytes:
    _separate_roots(source_root, upload_root)
    item, _ = _staged(upload_root, upload_id)
    suffix = Path(str(item["filename"])).suffix.lower()
    now = datetime.now(timezone.utc)
    raw = _canonical({
        "schema": 1, "operation": "synthetic-document-promotion",
        "request_id": uuid4().hex, "requested_by": requester,
        "upload_id": upload_id, "upload_sha256": item["sha256"],
        "manifest_sha256": hashlib.sha256(read_manifest_bytes(manifest)).hexdigest(),
        "document_id": document_id, "collection": collection,
        "classification": classification, "owner": owner, "version": version,
        "suffix": suffix, "issued_at": now.isoformat(),
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


def apply_promotion(source_root: Path, upload_root: Path, manifest: Path,
                    proposal_raw: bytes, approvals: tuple[bytes, bytes],
                    trust_path: Path, audit_path: Path) -> str:
    proposal = _proposal(proposal_raw)
    _separate_roots(source_root, upload_root)
    _verify_approvals(proposal_raw, approvals, _read_trust(trust_path), str(proposal["requested_by"]))
    audit = AuditLog(audit_path)
    audit.check_clock()
    with policy_directory_lock(source_root / "roles.json", exclusive=True):
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
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        published = False
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _valid_source(source_root, row)
            updated = {**payload, "sources": [*payload["sources"], row]}
            if len(_canonical(updated)) > MAX_MANIFEST_BYTES:
                raise ApprovalError("approved manifest would exceed size limit")
            # The Core request lock prevents a partial promotion from reaching a reader.
            _atomic_json(manifest, updated)
            published = True
            try:
                audit.append(actor=str(proposal["requested_by"]), action="document-promoted",
                             resource=str(proposal["document_id"]), decision="allow",
                             policy_version=hashlib.sha256(read_policy_bytes(source_root / "roles.json")).hexdigest())
            except Exception:
                _atomic_bytes(manifest, old_manifest)
                published = False
                raise
            try:
                _atomic_json(upload_root / f"{proposal['upload_id']}.json", {**item, "status": "approved"})
                (upload_root / f"{proposal['upload_id']}.blob").unlink(missing_ok=True)
            except OSError:
                # The signed manifest and audit are authoritative; stale staging
                # metadata can be repaired without granting any extra access.
                pass
            return str(proposal["document_id"])
        except Exception:
            if not published:
                target.unlink(missing_ok=True)
            raise
