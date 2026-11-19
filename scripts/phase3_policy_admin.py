"""Offline two-person role-policy change for the synthetic lab only."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.policy.change import (PolicyChangeError, apply_change, create_proposal,
                                    recover_change, sign_proposal)
from services.policy.regular_file import read_regular_file


def _private_key(path: Path) -> Ed25519PrivateKey:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                stat.S_IMODE(details.st_mode) & 0o077 or details.st_size > 4096):
            raise PolicyChangeError("signer key must be an owner-only regular file")
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise PolicyChangeError("signer key exceeds size limit")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise PolicyChangeError("invalid signer private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyChangeError("signer key must be Ed25519")
    return key


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    propose = sub.add_parser("propose")
    propose.add_argument("--current", type=Path, required=True)
    propose.add_argument("--candidate", type=Path, required=True)
    propose.add_argument("--requester", required=True)
    propose.add_argument("--reason", required=True)
    propose.add_argument("--ttl-minutes", type=int, default=60)
    propose.add_argument("--out", type=Path, required=True)
    approve = sub.add_parser("approve")
    approve.add_argument("--proposal", type=Path, required=True)
    approve.add_argument("--signer-id", required=True)
    approve.add_argument("--key", type=Path, required=True)
    approve.add_argument("--out", type=Path, required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--current", type=Path, required=True)
    apply.add_argument("--candidate", type=Path, required=True)
    apply.add_argument("--proposal", type=Path, required=True)
    apply.add_argument("--approval", type=Path, action="append", required=True)
    apply.add_argument("--trust", type=Path, required=True)
    apply.add_argument("--audit", type=Path, required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--current", type=Path, required=True)
    recover.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "propose":
        _write_new(args.out, create_proposal(args.current, args.candidate,
                                             args.requester, args.reason,
                                             ttl_minutes=args.ttl_minutes))
    elif args.operation == "approve":
        _write_new(args.out, sign_proposal(read_regular_file(args.proposal, 8192),
                                           args.signer_id, _private_key(args.key)))
    elif args.operation == "apply":
        if len(args.approval) != 2:
            parser.error("exactly two --approval files are required")
        print(apply_change(args.current, args.candidate, args.proposal,
                           tuple(args.approval), args.trust, args.audit))
    else:
        print(recover_change(args.current, args.audit))


if __name__ == "__main__":
    main()
