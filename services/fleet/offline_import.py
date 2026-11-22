"""Verify a metadata-only deployment receipt signed by an offline issuer."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from services.fleet.catalog import DeploymentReceipt, Metadata


DOMAIN = b"SOVEREIGN-FLEET-DEPLOYMENT-RECEIPT-V1\n"


class SignedDeploymentReceipt(Metadata):
    schema_version: Literal[1]
    key_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt: DeploymentReceipt
    signature: str = Field(min_length=88, max_length=88)


def load_import_key(path: Path) -> Ed25519PublicKey:
    """Load an owner-controlled trust anchor without following a link."""
    if not path.is_absolute():
        raise ValueError("offline import trust key path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 4096):
            raise ValueError("offline import trust key must be an owner-only regular file")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(raw) > 4096:
        raise ValueError("offline import trust key is too large")
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("offline import trust key must be Ed25519")
    return key


def load_import_trust(path: Path) -> tuple[Ed25519PublicKey, ...]:
    """Load a bounded, owner-controlled issuer set for an overlap window."""
    if not path.is_absolute():
        raise ValueError("offline import trust manifest path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 4096):
            raise ValueError("offline import trust manifest must be owner-only")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(raw) > 4096:
        raise ValueError("offline import trust manifest is too large")
    try:
        paths = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid offline import trust manifest") from exc
    if (not isinstance(paths, list) or not 1 <= len(paths) <= 4
            or any(not isinstance(item, str) or not item for item in paths)
            or len(set(paths)) != len(paths)):
        raise ValueError("offline import trust manifest requires 1-4 distinct paths")
    keys = tuple(load_import_key(Path(item)) for item in paths)
    if len({key_id(key) for key in keys}) != len(keys):
        raise ValueError("offline import trust manifest repeats an issuer")
    return keys


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def receipt_bytes(receipt: DeploymentReceipt) -> bytes:
    payload = {"schema_version": 1, "receipt": receipt.model_dump(mode="json")}
    return DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii")


def verify_signed_receipt(envelope: SignedDeploymentReceipt,
                          key: Ed25519PublicKey) -> DeploymentReceipt:
    if envelope.key_id != key_id(key):
        raise ValueError("offline import issuer is untrusted")
    try:
        signature = base64.b64decode(envelope.signature, validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid offline import signature") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode() != envelope.signature:
        raise ValueError("invalid offline import signature encoding")
    try:
        key.verify(signature, receipt_bytes(envelope.receipt))
    except InvalidSignature as exc:
        raise ValueError("invalid offline import signature") from exc
    return envelope.receipt
