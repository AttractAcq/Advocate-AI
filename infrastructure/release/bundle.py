"""Create and verify a detached-signed, offline release directory.

The signing key stays with the release custodian. The verifier accepts only
public keys supplied out of band and never executes or installs payloads.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MANIFEST = "release-manifest.json"
SIGNATURE = "release-manifest.sig"
MAX_MANIFEST_BYTES = 1024 * 1024


class BundleError(ValueError):
    """A bundle failed validation or verification."""


def _relative_path(name: str) -> PurePosixPath:
    if not isinstance(name, str) or not name or "\\" in name:
        raise BundleError("invalid payload path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise BundleError("unsafe payload path")
    if path.parts[0] in (MANIFEST, SIGNATURE):
        raise BundleError("reserved payload path")
    return path


def _files(root: Path, *, allow_control: bool = False) -> list[tuple[str, Path]]:
    if not root.is_dir() or root.is_symlink():
        raise BundleError("payload directory is missing or linked")
    result: list[tuple[str, Path]] = []
    for item in root.rglob("*"):
        if item.is_symlink():
            raise BundleError("linked payload path")
        if not item.is_file():
            if not item.is_dir():
                raise BundleError("unsupported payload type")
            continue
        name = item.relative_to(root).as_posix()
        if not (allow_control and name in (MANIFEST, SIGNATURE)):
            _relative_path(name)
        result.append((name, item))
    result.sort(key=lambda pair: pair[0])
    if not result:
        raise BundleError("empty payload")
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("duplicate manifest key")
        result[key] = value
    return result


def create_bundle(payload: Path, output: Path, signing_key: Path, version: str) -> dict[str, object]:
    """Copy an approved payload and sign its exact manifest bytes."""
    if not isinstance(version, str) or not version or len(version) > 80 or any(c.isspace() for c in version):
        raise BundleError("invalid release version")
    source_files = _files(payload)
    output = output.absolute()
    if output.exists() or output.is_relative_to(payload.resolve()):
        raise BundleError("output must be new and outside payload")
    if signing_key.resolve().is_relative_to(payload.resolve()):
        raise BundleError("signing key must be outside payload")
    key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleError("signing key must be Ed25519")
    output.mkdir(parents=True)
    try:
        rows = []
        for name, source in source_files:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            rows.append({"path": name, "sha256": _sha256(target), "size": target.stat().st_size})
        manifest: dict[str, object] = {
            "schema": 2, "version": version, "key_id": _key_id(key.public_key()), "files": rows,
        }
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        (output / MANIFEST).write_bytes(raw)
        (output / SIGNATURE).write_bytes(base64.b64encode(key.sign(raw)))
        return manifest
    except Exception:
        shutil.rmtree(output)
        raise


def verify_bundle(bundle: Path, trusted_key: Path) -> dict[str, object]:
    """Verify signature, exact file inventory, size and SHA-256 before use."""
    if not bundle.is_dir() or bundle.is_symlink():
        raise BundleError("bundle directory is missing or linked")
    if any((bundle / name).is_symlink() for name in (MANIFEST, SIGNATURE)):
        raise BundleError("linked control file")
    raw = (bundle / MANIFEST).read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BundleError("manifest is too large")
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
        signature = base64.b64decode((bundle / SIGNATURE).read_bytes(), validate=True)
        key = serialization.load_pem_public_key(trusted_key.read_bytes())
    except (ValueError, TypeError) as exc:
        raise BundleError("invalid manifest, signature or public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BundleError("trusted key must be Ed25519")
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "version", "key_id", "files"}:
        raise BundleError("invalid manifest fields")
    if manifest["schema"] != 2 or manifest["key_id"] != _key_id(key):
        raise BundleError("untrusted bundle schema or key")
    if not isinstance(manifest["version"], str) or not manifest["version"]:
        raise BundleError("invalid release version")
    try:
        key.verify(signature, raw)
    except InvalidSignature as exc:
        raise BundleError("invalid release signature") from exc
    rows = manifest["files"]
    if not isinstance(rows, list) or not rows:
        raise BundleError("empty manifest inventory")
    expected = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            raise BundleError("invalid payload record")
        name = row["path"]
        _relative_path(name)
        if name in expected:
            raise BundleError("duplicate payload path")
        expected.add(name)
        if (not isinstance(row["size"], int) or isinstance(row["size"], bool)
                or row["size"] < 0 or not isinstance(row["sha256"], str)
                or len(row["sha256"]) != 64):
            raise BundleError("invalid payload metadata")
        target = bundle / name
        if not target.is_file() or target.is_symlink() or target.stat().st_size != row["size"]:
            raise BundleError("missing, linked or altered payload")
        if _sha256(target) != row["sha256"]:
            raise BundleError("payload hash mismatch")
    actual = {name for name, _ in _files(bundle, allow_control=True)} - {MANIFEST, SIGNATURE}
    if actual != expected:
        raise BundleError("unlisted or missing payload")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or verify an offline release directory")
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("payload", type=Path)
    pack.add_argument("output", type=Path)
    pack.add_argument("--signing-key", required=True, type=Path)
    pack.add_argument("--version", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--trusted-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (create_bundle(args.payload, args.output, args.signing_key, args.version)
                  if args.command == "pack" else verify_bundle(args.bundle, args.trusted_key))
    except (BundleError, OSError, ValueError) as exc:
        parser.exit(1, f"bundle: {exc}\n")
    print(f"Verified release {result['version']} ({len(result['files'])} files)" if args.command == "verify"
          else f"Created release {result['version']} ({len(result['files'])} files)")


if __name__ == "__main__":
    main()
