"""Create and verify a detached-signed, offline release directory.

The signing key stays with the release custodian. The verifier accepts only
public keys supplied out of band and never executes or installs payloads.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.upstream import UpstreamError, validate_image_archive

MANIFEST = "release-manifest.json"
SIGNATURE = "release-manifest.sig"
MAX_MANIFEST_BYTES = 1024 * 1024
SUPPORTED_VESSEL_COMPATIBILITY = {"knowledge_schema": 1, "core_state_schema": 1}


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


def _create_bundle(payload: Path, output: Path, signing_key: Path, version: str,
                   *, evidence: dict[str, str] | None = None,
                   images: dict[str, dict[str, str]] | None = None,
                   fleet: bool = False, knowledge: bool = False,
                   vessel_compatibility: dict[str, int] | None = None) -> dict[str, object]:
    """Copy an approved payload and sign its exact manifest bytes."""
    if not isinstance(version, str) or not version or len(version) > 80 or any(c.isspace() for c in version):
        raise BundleError("invalid release version")
    source_files = _files(payload)
    if evidence is not None and images is not None:
        raise BundleError("ambiguous release evidence")
    if fleet and knowledge:
        raise BundleError("ambiguous image bundle target")
    if knowledge:
        _validate_vessel_compatibility(vessel_compatibility)
    elif vessel_compatibility is not None:
        raise BundleError("vessel compatibility applies only to vessel bundles")
    if evidence is not None:
        _validate_evidence(evidence, {name for name, _ in source_files})
    if images is not None:
        _validate_image_set(images, {name for name, _ in source_files},
                            ("fleet-api", "fleet-portal") if fleet else
                            ("core", "console", "knowledge") if knowledge else
                            ("core", "console"))
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
            "schema": (5 if fleet else 6 if knowledge else 4) if images is not None else
                      (3 if evidence is not None else 2),
            "version": version, "key_id": _key_id(key.public_key()), "files": rows,
        }
        if evidence is not None:
            manifest["signed_at"] = datetime.now(timezone.utc).isoformat()
            manifest["evidence"] = evidence
        if images is not None:
            manifest["signed_at"] = datetime.now(timezone.utc).isoformat()
            manifest["images"] = images
            if fleet or knowledge:
                manifest["target"] = "fleet" if fleet else "vessel"
            if knowledge:
                manifest["compatibility"] = vessel_compatibility
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        (output / MANIFEST).write_bytes(raw)
        (output / SIGNATURE).write_bytes(base64.b64encode(key.sign(raw)))
        return manifest
    except Exception:
        shutil.rmtree(output)
        raise


def create_bundle(payload: Path, output: Path, signing_key: Path, version: str) -> dict[str, object]:
    """Create a schema-2 synthetic bundle without release evidence."""
    return _create_bundle(payload, output, signing_key, version)


def _validate_evidence(evidence: object, files: set[str]) -> None:
    required = {"image_ref", "scan_path", "scan_sha256", "sbom_path", "sbom_sha256"}
    archive_fields = {"archive_path", "archive_sha256", "crane_sha256"}
    if (not isinstance(evidence, dict) or
            set(evidence) not in (required, required | archive_fields)):
        raise BundleError("invalid release evidence descriptor")
    path_fields = ["scan_path", "sbom_path"]
    if archive_fields <= set(evidence):
        path_fields.append("archive_path")
    for name in path_fields:
        value = evidence[name]
        _relative_path(value)
        if value not in files:
            raise BundleError("release evidence is not in the signed file inventory")
    if evidence["scan_path"] == evidence["sbom_path"]:
        raise BundleError("scan and SBOM must be distinct files")
    if len({evidence[name] for name in path_fields}) != len(path_fields):
        raise BundleError("evidence and image archive must be distinct files")
    hash_fields = ["scan_sha256", "sbom_sha256"]
    if archive_fields <= set(evidence):
        hash_fields += ["archive_sha256", "crane_sha256"]
    for name in hash_fields:
        value = evidence[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise BundleError("invalid evidence digest")
    if not isinstance(evidence["image_ref"], str):
        raise BundleError("invalid image reference")


def _validate_image_set(images: object, files: set[str], roles: tuple[str, ...]) -> None:
    """Require the exact evidenced image roles for one product boundary."""
    if not isinstance(images, dict) or set(images) != set(roles):
        raise BundleError("bundle image roles do not match its target")
    paths: set[str] = set()
    for role in roles:
        item = images[role]
        _validate_evidence(item, files)
        if (set(item) != {"image_ref", "scan_path", "scan_sha256", "sbom_path",
                          "sbom_sha256", "archive_path", "archive_sha256", "crane_sha256"} or
                item["archive_path"] != f"images/{role}.tar" or
                item["image_ref"].split("@", 1)[0].rsplit("/", 1)[-1] != role):
            raise BundleError("product image role or archive evidence mismatch")
        for name in ("scan_path", "sbom_path", "archive_path"):
            if item[name] in paths:
                raise BundleError("product images share an evidence path")
            paths.add(item[name])
    if {name for name in files if name.startswith("images/")} != \
            {f"images/{role}.tar" for role in roles}:
        raise BundleError("unreviewed image archive")


def _validate_product_images(images: object, files: set[str]) -> None:
    _validate_image_set(images, files, ("core", "console"))


def _validate_vessel_compatibility(value: object) -> None:
    if (not isinstance(value, dict) or
            set(value) != {"knowledge_schema", "core_state_schema"} or
            any(type(item) is not int or not 1 <= item <= 65535
                for item in value.values())):
        raise BundleError("invalid vessel compatibility contract")


def require_supported_vessel_compatibility(manifest: dict[str, object]) -> None:
    """Refuse a signed vessel release this installed software cannot run."""
    if (manifest.get("schema") != 6 or manifest.get("target") != "vessel" or
            manifest.get("compatibility") != SUPPORTED_VESSEL_COMPATIBILITY):
        raise BundleError("unsupported vessel compatibility contract")


def _preflight_image(payload: Path, evidence: dict[str, str], crane: Path) -> None:
    result = verify_intake(payload / evidence["scan_path"], payload / evidence["sbom_path"],
                           evidence["image_ref"], evidence["scan_sha256"], evidence["sbom_sha256"])
    if "archive_sha256" not in result or result["archive_sha256"] != evidence["archive_sha256"]:
        raise BundleError("product image lacks matching generated archive evidence")
    identity = validate_image_archive(payload / evidence["archive_path"],
                                      evidence["image_ref"], crane, evidence["crane_sha256"])
    if identity["archive_sha256"] != evidence["archive_sha256"]:
        raise BundleError("product image archive changed after evidence generation")


def create_product_bundle(payload: Path, output: Path, signing_key: Path,
                          version: str, images: dict[str, dict[str, str]],
                          *, crane: Path) -> dict[str, object]:
    """Sign Core and Console only after both exact archives pass intake."""
    files = {name for name, _ in _files(payload)}
    _validate_product_images(images, files)
    for role in ("core", "console"):
        _preflight_image(payload, images[role], crane)
    manifest = _create_bundle(payload, output, signing_key, version, images=images)
    try:
        for role in ("core", "console"):
            item = images[role]
            copied = verify_intake(output / item["scan_path"], output / item["sbom_path"],
                                   item["image_ref"], item["scan_sha256"], item["sbom_sha256"])
            if copied.get("archive_sha256") != item["archive_sha256"] or \
                    _sha256(output / item["archive_path"]) != item["archive_sha256"]:
                raise BundleError("copied product archive does not match signed evidence")
    except (IntakeError, BundleError, OSError):
        shutil.rmtree(output)
        raise
    return manifest


def create_knowledge_bundle(payload: Path, output: Path, signing_key: Path,
                            version: str, images: dict[str, dict[str, str]],
                            compatibility: dict[str, int], *, crane: Path) -> dict[str, object]:
    """Sign Core, Console and Knowledge only after all three archives pass intake."""
    _validate_vessel_compatibility(compatibility)
    roles = ("core", "console", "knowledge")
    _validate_image_set(images, {name for name, _ in _files(payload)}, roles)
    for role in roles:
        _preflight_image(payload, images[role], crane)
    manifest = _create_bundle(payload, output, signing_key, version,
                              images=images, knowledge=True,
                              vessel_compatibility=compatibility)
    try:
        for role in roles:
            item = images[role]
            copied = verify_intake(output / item["scan_path"], output / item["sbom_path"],
                                   item["image_ref"], item["scan_sha256"], item["sbom_sha256"])
            if copied.get("archive_sha256") != item["archive_sha256"] or \
                    _sha256(output / item["archive_path"]) != item["archive_sha256"]:
                raise BundleError("copied knowledge product archive does not match signed evidence")
    except (IntakeError, BundleError, OSError):
        shutil.rmtree(output)
        raise
    return manifest


def create_fleet_bundle(payload: Path, output: Path, signing_key: Path,
                        version: str, images: dict[str, dict[str, str]],
                        *, crane: Path) -> dict[str, object]:
    """Sign separate company-side images only after both archives pass intake."""
    roles = ("fleet-api", "fleet-portal")
    _validate_image_set(images, {name for name, _ in _files(payload)}, roles)
    for role in roles:
        _preflight_image(payload, images[role], crane)
    manifest = _create_bundle(payload, output, signing_key, version,
                              images=images, fleet=True)
    try:
        for role in roles:
            item = images[role]
            copied = verify_intake(output / item["scan_path"], output / item["sbom_path"],
                                   item["image_ref"], item["scan_sha256"], item["sbom_sha256"])
            if copied.get("archive_sha256") != item["archive_sha256"] or \
                    _sha256(output / item["archive_path"]) != item["archive_sha256"]:
                raise BundleError("copied Fleet archive does not match signed evidence")
    except (IntakeError, BundleError, OSError):
        shutil.rmtree(output)
        raise
    return manifest


def create_candidate_bundle(payload: Path, output: Path, signing_key: Path,
                            version: str, evidence: dict[str, str],
                            *, crane: Path | None = None) -> dict[str, object]:
    """Preflight evidence inside a payload, then bind it into a signed bundle."""
    files = {name for name, _ in _files(payload)}
    _validate_evidence(evidence, files)
    result = verify_intake(payload / evidence["scan_path"], payload / evidence["sbom_path"],
                           evidence["image_ref"], evidence["scan_sha256"], evidence["sbom_sha256"])
    if "archive_sha256" in result:
        if "archive_path" not in evidence or crane is None or \
                result["archive_sha256"] != evidence["archive_sha256"]:
            raise BundleError("generated SBOM requires matching image archive evidence")
        identity = validate_image_archive(payload / evidence["archive_path"],
                                          evidence["image_ref"], crane,
                                          evidence["crane_sha256"])
        if identity["archive_sha256"] != evidence["archive_sha256"]:
            raise BundleError("image archive changed after SBOM generation")
    elif "archive_path" in evidence:
        raise BundleError("image archive requires a generated SBOM")
    manifest = _create_bundle(payload, output, signing_key, version, evidence=evidence)
    try:
        copied = verify_intake(output / evidence["scan_path"], output / evidence["sbom_path"],
                               evidence["image_ref"], evidence["scan_sha256"],
                               evidence["sbom_sha256"])
        if "archive_sha256" in copied and \
                _sha256(output / evidence["archive_path"]) != copied["archive_sha256"]:
            raise BundleError("copied image archive does not match the signed SBOM")
    except (IntakeError, BundleError, OSError):
        shutil.rmtree(output)
        raise
    return manifest


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
    if not isinstance(manifest, dict) or manifest.get("schema") not in (2, 3, 4, 5, 6):
        raise BundleError("invalid manifest fields")
    required = {"schema", "version", "key_id", "files"}
    if manifest["schema"] == 3:
        required |= {"signed_at", "evidence"}
    elif manifest["schema"] in (4, 5, 6):
        required |= {"signed_at", "images"}
        if manifest["schema"] in (5, 6):
            required.add("target")
        if manifest["schema"] == 6:
            required.add("compatibility")
    if set(manifest) != required:
        raise BundleError("invalid manifest fields")
    if manifest["key_id"] != _key_id(key):
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
    if manifest["schema"] in (3, 4, 5, 6):
        try:
            signed_at = datetime.fromisoformat(manifest["signed_at"])
        except (TypeError, ValueError) as exc:
            raise BundleError("invalid signing timestamp") from exc
        if (signed_at.tzinfo is None or
                signed_at > datetime.now(timezone.utc) + timedelta(minutes=5)):
            raise BundleError("invalid signing timestamp")
    if manifest["schema"] == 3:
        evidence = manifest["evidence"]
        _validate_evidence(evidence, expected)
        try:
            intake = verify_intake(bundle / evidence["scan_path"], bundle / evidence["sbom_path"],
                                   evidence["image_ref"], evidence["scan_sha256"],
                                   evidence["sbom_sha256"], now=signed_at)
        except IntakeError as exc:
            raise BundleError("signed release evidence failed preflight") from exc
        if "archive_sha256" in intake:
            if "archive_path" not in evidence or \
                    intake["archive_sha256"] != evidence["archive_sha256"] or \
                    _sha256(bundle / evidence["archive_path"]) != evidence["archive_sha256"]:
                raise BundleError("signed image archive does not match the SBOM")
        elif "archive_path" in evidence:
            raise BundleError("signed image archive lacks generated inventory")
    elif manifest["schema"] in (4, 5, 6):
        images = manifest["images"]
        roles = (("core", "console") if manifest["schema"] == 4 else
                 ("fleet-api", "fleet-portal") if manifest["schema"] == 5 else
                 ("core", "console", "knowledge"))
        if manifest["schema"] == 5 and manifest["target"] != "fleet":
            raise BundleError("signed Fleet bundle target is invalid")
        if manifest["schema"] == 6 and manifest["target"] != "vessel":
            raise BundleError("signed knowledge bundle target is invalid")
        if manifest["schema"] == 6:
            _validate_vessel_compatibility(manifest["compatibility"])
        _validate_image_set(images, expected, roles)
        for role in roles:
            item = images[role]
            try:
                intake = verify_intake(bundle / item["scan_path"], bundle / item["sbom_path"],
                                       item["image_ref"], item["scan_sha256"],
                                       item["sbom_sha256"], now=signed_at)
            except IntakeError as exc:
                raise BundleError("signed product evidence failed preflight") from exc
            if intake.get("archive_sha256") != item["archive_sha256"] or \
                    _sha256(bundle / item["archive_path"]) != item["archive_sha256"]:
                raise BundleError("signed product image archive does not match the SBOM")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or verify an offline release directory")
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("payload", type=Path)
    pack.add_argument("output", type=Path)
    pack.add_argument("--signing-key", required=True, type=Path)
    pack.add_argument("--version", required=True)
    candidate = commands.add_parser("pack-candidate")
    candidate.add_argument("payload", type=Path)
    candidate.add_argument("output", type=Path)
    candidate.add_argument("--signing-key", required=True, type=Path)
    candidate.add_argument("--version", required=True)
    candidate.add_argument("--image-ref", required=True)
    candidate.add_argument("--scan-path", required=True)
    candidate.add_argument("--scan-sha256", required=True)
    candidate.add_argument("--sbom-path", required=True)
    candidate.add_argument("--sbom-sha256", required=True)
    candidate.add_argument("--archive-path")
    candidate.add_argument("--archive-sha256")
    candidate.add_argument("--crane", type=Path)
    candidate.add_argument("--crane-sha256")
    product = commands.add_parser("pack-product")
    product.add_argument("payload", type=Path)
    product.add_argument("output", type=Path)
    product.add_argument("--signing-key", required=True, type=Path)
    product.add_argument("--version", required=True)
    product.add_argument("--images-json", required=True, type=Path)
    product.add_argument("--crane", required=True, type=Path)
    knowledge = commands.add_parser("pack-knowledge")
    knowledge.add_argument("payload", type=Path)
    knowledge.add_argument("output", type=Path)
    knowledge.add_argument("--signing-key", required=True, type=Path)
    knowledge.add_argument("--version", required=True)
    knowledge.add_argument("--images-json", required=True, type=Path)
    knowledge.add_argument("--knowledge-schema", required=True, type=int)
    knowledge.add_argument("--core-state-schema", required=True, type=int)
    knowledge.add_argument("--crane", required=True, type=Path)
    fleet = commands.add_parser("pack-fleet")
    fleet.add_argument("payload", type=Path)
    fleet.add_argument("output", type=Path)
    fleet.add_argument("--signing-key", required=True, type=Path)
    fleet.add_argument("--version", required=True)
    fleet.add_argument("--images-json", required=True, type=Path)
    fleet.add_argument("--crane", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--trusted-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "pack":
            result = create_bundle(args.payload, args.output, args.signing_key, args.version)
        elif args.command == "pack-candidate":
            evidence = {"image_ref": args.image_ref, "scan_path": args.scan_path,
                        "scan_sha256": args.scan_sha256, "sbom_path": args.sbom_path,
                        "sbom_sha256": args.sbom_sha256}
            if any((args.archive_path, args.archive_sha256, args.crane_sha256)):
                evidence.update({"archive_path": args.archive_path,
                                 "archive_sha256": args.archive_sha256,
                                 "crane_sha256": args.crane_sha256})
            result = create_candidate_bundle(args.payload, args.output, args.signing_key,
                                             args.version, evidence, crane=args.crane)
        elif args.command == "pack-product":
            if args.images_json.is_symlink() or not args.images_json.is_file() or \
                    args.images_json.stat().st_size > MAX_MANIFEST_BYTES:
                raise BundleError("invalid product image descriptor")
            images = json.loads(args.images_json.read_text(), object_pairs_hook=_unique_object)
            result = create_product_bundle(args.payload, args.output, args.signing_key,
                                           args.version, images, crane=args.crane)
        elif args.command == "pack-knowledge":
            if args.images_json.is_symlink() or not args.images_json.is_file() or \
                    args.images_json.stat().st_size > MAX_MANIFEST_BYTES:
                raise BundleError("invalid knowledge image descriptor")
            images = json.loads(args.images_json.read_text(), object_pairs_hook=_unique_object)
            result = create_knowledge_bundle(args.payload, args.output, args.signing_key,
                                             args.version, images,
                                             {"knowledge_schema": args.knowledge_schema,
                                              "core_state_schema": args.core_state_schema},
                                             crane=args.crane)
        elif args.command == "pack-fleet":
            if args.images_json.is_symlink() or not args.images_json.is_file() or \
                    args.images_json.stat().st_size > MAX_MANIFEST_BYTES:
                raise BundleError("invalid Fleet image descriptor")
            images = json.loads(args.images_json.read_text(), object_pairs_hook=_unique_object)
            result = create_fleet_bundle(args.payload, args.output, args.signing_key,
                                         args.version, images, crane=args.crane)
        else:
            result = verify_bundle(args.bundle, args.trusted_key)
    except (BundleError, IntakeError, UpstreamError, OSError, ValueError) as exc:
        parser.exit(1, f"bundle: {exc}\n")
    print(f"Verified release {result['version']} ({len(result['files'])} files)" if args.command == "verify"
          else f"Created release {result['version']} ({len(result['files'])} files)")


if __name__ == "__main__":
    main()
