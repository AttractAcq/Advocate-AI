"""Issue a metadata-only Fleet deployment receipt on an offline workstation."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.fleet.catalog import DeploymentReceipt
from services.fleet.offline_import import (
    SignedDeploymentReceipt, key_id, receipt_bytes, verify_signed_receipt,
)


def _owner_bytes(path: Path, maximum: int) -> bytes:
    if not path.is_absolute():
        raise ValueError("offline receipt input path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > maximum):
            raise ValueError("offline receipt input must be an owner-only regular file")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise ValueError("offline receipt input is too large")
    return raw


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate offline receipt field")
        value[name] = item
    return value


def issue_receipt(record_path: Path, signing_key: Path, output: Path) -> dict[str, str]:
    """Sign strict coded fields and create a new owner-only JSON envelope."""
    record = DeploymentReceipt.model_validate(json.loads(
        _owner_bytes(record_path, 4096), object_pairs_hook=_unique))
    key = serialization.load_pem_private_key(_owner_bytes(signing_key, 4096),
                                             password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("offline receipt signing key must be Ed25519")
    public = key.public_key()
    envelope = SignedDeploymentReceipt(
        schema_version=1, key_id=key_id(public), receipt=record,
        signature=base64.b64encode(key.sign(receipt_bytes(record))).decode("ascii"))
    verify_signed_receipt(envelope, public)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("offline receipt output must be a new absolute path")
    parent = output.parent
    info = parent.stat()
    if (not parent.is_dir() or parent.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("offline receipt output directory must be owner-only")
    raw = (json.dumps(envelope.model_dump(mode="json"), sort_keys=True,
                      separators=(",", ":")) + "\n").encode("ascii")
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {"code": record.code, "key_id": key_id(public)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign a coded Fleet receipt offline")
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = issue_receipt(args.record, args.signing_key, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"offline receipt issuance rejected: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
