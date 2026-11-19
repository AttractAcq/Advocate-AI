"""Offline signed promotion of a synthetic staged document."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.phase3_policy_admin import _private_key, _write_new
from services.knowledge.approval import apply_promotion, create_proposal, recover_promotion, sign_proposal
from services.policy.regular_file import read_regular_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    propose = sub.add_parser("propose")
    propose.add_argument("--sources", type=Path, required=True)
    propose.add_argument("--uploads", type=Path, required=True)
    propose.add_argument("--manifest", type=Path, required=True)
    propose.add_argument("--upload-id", required=True)
    propose.add_argument("--requester", required=True)
    propose.add_argument("--document-id", required=True)
    propose.add_argument("--collection", required=True)
    propose.add_argument("--classification", required=True)
    propose.add_argument("--owner", required=True)
    propose.add_argument("--version", default="1")
    propose.add_argument("--out", type=Path, required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("--proposal", type=Path, required=True)
    sign.add_argument("--signer-id", required=True)
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--sources", type=Path, required=True)
    apply.add_argument("--uploads", type=Path, required=True)
    apply.add_argument("--manifest", type=Path, required=True)
    apply.add_argument("--proposal", type=Path, required=True)
    apply.add_argument("--approval", type=Path, action="append", required=True)
    apply.add_argument("--trust", type=Path, required=True)
    apply.add_argument("--audit", type=Path, required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--sources", type=Path, required=True)
    recover.add_argument("--manifest", type=Path, required=True)
    recover.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "propose":
        _write_new(args.out, create_proposal(args.sources, args.uploads, args.manifest,
                   args.upload_id, requester=args.requester, document_id=args.document_id,
                   collection=args.collection, classification=args.classification,
                   owner=args.owner, version=args.version))
    elif args.operation == "sign":
        _write_new(args.out, sign_proposal(read_regular_file(args.proposal, 4096),
                                           args.signer_id, _private_key(args.key)))
    elif args.operation == "apply":
        if len(args.approval) != 2:
            parser.error("exactly two --approval files are required")
        print(apply_promotion(args.sources, args.uploads, args.manifest,
              read_regular_file(args.proposal, 4096),
              tuple(read_regular_file(path, 2048) for path in args.approval),
              args.trust, args.audit))
    else:
        print(recover_promotion(args.sources, args.manifest, args.audit))


if __name__ == "__main__":
    main()
