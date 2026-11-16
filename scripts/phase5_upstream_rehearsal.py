"""Exercise pinned crane, Syft and candidate signing on a fictional offline image."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import BundleError, create_candidate_bundle, verify_bundle
from infrastructure.release.upstream import UpstreamError, generate_resolved_sbom, validate_image_archive


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _docker(*argv: str) -> str:
    result = subprocess.run(["docker", *argv], check=True, capture_output=True, text=True,
                            timeout=180)
    return result.stdout.strip()


def rehearse(crane: Path, crane_sha256: str, syft: Path, syft_sha256: str) -> dict[str, object]:
    tag = f"sovereign-synthetic-release:{uuid.uuid4().hex[:12]}"
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = root / "context"
            context.mkdir()
            (context / "Dockerfile").write_text(
                "FROM scratch\nCOPY package.json /app/package.json\n"
                "COPY package-lock.json /app/package-lock.json\n")
            (context / "package.json").write_text(
                '{"name":"fictional-release","version":"1.0.0"}\n')
            (context / "package-lock.json").write_text(
                '{"name":"fictional-release","version":"1.0.0","lockfileVersion":3,'
                '"packages":{"":{"name":"fictional-release","version":"1.0.0"}}}\n')
            _docker("build", "--network=none", "-t", tag, str(context))
            payload = root / "payload"
            (payload / "images").mkdir(parents=True)
            (payload / "evidence").mkdir()
            archive = payload / "images" / "fictional.tar"
            _docker("save", tag, "-o", str(archive))
            digest = subprocess.run([str(crane), "digest", "--tarball", str(archive)],
                                    check=True, capture_output=True, text=True,
                                    timeout=120).stdout.strip()
            image_ref = f"registry.example.invalid/fictional/release@{digest}"
            sbom = payload / "evidence" / "sbom.json"
            generated = generate_resolved_sbom(archive, image_ref, sbom,
                                               crane, crane_sha256, syft, syft_sha256)
            scan = payload / "evidence" / "scan.json"
            scan.write_text(json.dumps({
                "SchemaVersion": 2, "ArtifactType": "container_image",
                "ArtifactName": image_ref, "CreatedAt": datetime.now(timezone.utc).isoformat(),
                "Trivy": {"Version": "0.76.2"}, "Metadata": {"RepoDigests": [image_ref]},
                "Results": [{"Target": "fictional", "Vulnerabilities": []}],
            }))
            key = Ed25519PrivateKey.generate()
            private = root / "signing-key.pem"
            trusted = root / "trusted-key.pem"
            private.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            trusted.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            evidence = {"image_ref": image_ref, "scan_path": "evidence/scan.json",
                        "scan_sha256": _hash(scan), "sbom_path": "evidence/sbom.json",
                        "sbom_sha256": _hash(sbom), "archive_path": "images/fictional.tar",
                        "archive_sha256": _hash(archive), "crane_sha256": crane_sha256}
            bundle = root / "bundle"
            create_candidate_bundle(payload, bundle, private, "0.1.0", evidence, crane=crane)
            verified = verify_bundle(bundle, trusted)
            if verified["evidence"] != evidence:
                raise AssertionError("verified evidence differs from the signed descriptor")
            with (bundle / "images" / "fictional.tar").open("ab") as stream:
                stream.write(b"tampered")
            try:
                verify_bundle(bundle, trusted)
            except BundleError:
                pass
            else:
                raise AssertionError("altered image archive passed signature verification")
            try:
                validate_image_archive(archive, image_ref[:-64] + "0" * 64,
                                       crane, crane_sha256)
            except UpstreamError:
                pass
            else:
                raise AssertionError("wrong image digest passed crane verification")
            return {"status": "pass", "source": "fictional-offline-docker-archive",
                    "components": generated["components"], "archive_sha256": generated["archive_sha256"]}
    finally:
        subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True,
                       text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic upstream release rehearsal")
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--crane-sha256", required=True)
    parser.add_argument("--syft", required=True, type=Path)
    parser.add_argument("--syft-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
