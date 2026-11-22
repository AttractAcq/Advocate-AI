"""Qualify the pinned pgvector image archive used by the synthetic vessel lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive

_IMAGE = re.compile(r"docker\.io/pgvector/pgvector@sha256:[0-9a-f]{64}\Z")


def _docker(*arguments: str) -> str:
    completed = subprocess.run(["docker", *arguments], check=True,
                               capture_output=True, text=True, timeout=300)
    return completed.stdout.strip()


def rehearse(image: str, output: Path, crane: Path, crane_sha256: str,
             syft: Path, syft_sha256: str, trivy: Path, trivy_sha256: str,
             trivy_cache: Path) -> dict[str, object]:
    if not _IMAGE.fullmatch(image):
        raise ValueError("Knowledge image must be the digest-pinned official pgvector repository")
    if output.exists() or output.is_symlink():
        raise ValueError("Knowledge evidence output must be new")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="sovereign-knowledge-intake-") as directory:
        archive = Path(directory) / "knowledge.tar"
        _docker("pull", image)
        upstream_image_id = _docker("image", "inspect", image, "--format", "{{.Id}}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", upstream_image_id):
            raise ValueError("invalid pinned upstream image ID")
        local_tag = "sovereign-knowledge:synthetic-intake"
        _docker("tag", image, local_tag)
        if _docker("image", "inspect", local_tag, "--format", "{{.Id}}") != upstream_image_id:
            raise AssertionError("locally tagged Knowledge image differs from pinned pull")
        _docker("save", "-o", str(archive), local_tag)
        digest = subprocess.run([str(crane), "digest", "--tarball", str(archive)],
                                check=True, capture_output=True, text=True,
                                timeout=300).stdout.strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid saved Knowledge image manifest digest")
        # This local archive digest can differ from the registry digest after Docker
        # serializes the image. Preserve both identities; the alias is never published.
        image_ref = f"registry.example.invalid/sovereign/knowledge@{digest}"
        identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
        sbom = output / "knowledge-sbom.json"
        scan = output / "knowledge-scan.json"
        inventory = generate_resolved_sbom(archive, image_ref, sbom,
                                           crane, crane_sha256, syft, syft_sha256)
        generated = generate_archive_scan(archive, image_ref, scan, crane,
                                          crane_sha256, trivy, trivy_sha256,
                                          trivy_cache)
        findings = [item for section in json.loads(scan.read_text())["Results"]
                    for item in section.get("Vulnerabilities", [])
                    if item.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
        result: dict[str, object] = {
            "source": "digest-pinned-official-pgvector-image",
            "upstream_image": image,
            "upstream_image_id": upstream_image_id,
            "local_archive_ref": image_ref,
            "archive_sha256": identity["archive_sha256"],
            "sbom_sha256": inventory["sbom_sha256"],
            "scan_sha256": generated["scan_sha256"],
            "components": inventory["components"],
            "unresolved_findings": len(findings),
        }
        try:
            verify_intake(scan, sbom, image_ref, generated["scan_sha256"],
                          inventory["sbom_sha256"])
        except IntakeError as exc:
            if not findings or "unresolved high, critical or unknown findings" not in str(exc):
                raise
            result["intake"] = "denied-findings"
        else:
            result["intake"] = "preflight-pass"
        (output / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Qualify a pinned pgvector image archive")
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--crane-sha256", required=True)
    parser.add_argument("--syft", required=True, type=Path)
    parser.add_argument("--syft-sha256", required=True)
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--trivy-sha256", required=True)
    parser.add_argument("--trivy-cache", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.image, args.output, args.crane,
                             args.crane_sha256, args.syft, args.syft_sha256,
                             args.trivy, args.trivy_sha256, args.trivy_cache),
                     sort_keys=True))


if __name__ == "__main__":
    main()
