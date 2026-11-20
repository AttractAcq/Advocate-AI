"""Sign and verify the exact built Core, Console and Knowledge image archives."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle, _image_id, stop_runtime
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.postgres_socket import sql as postgres_sql
from infrastructure.deploy.vessel_runtime import start_signed_vessel_services
from infrastructure.deploy.vessel_installer import (
    finish_vessel_stop, install_vessel, reconcile_vessel, recover_vessel,
    status_vessel,
)
from infrastructure.release.bundle import create_knowledge_bundle, verify_bundle
from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive
from scripts.phase3_pgvector_core_socket import (
    _BOOTSTRAP, _rehearse_verified_images,
)
from scripts.synthetic_pg_fixture import fixture as synthetic_fixture, put as private_put

ROLES = ("core", "console", "knowledge")


def _rehearse_persistent_knowledge(bundle: Path, trusted: Path,
                                   crane: Path, root: Path,
                                   core_image: str) -> dict[str, str]:
    """Restart signed Knowledge and attach signed Core and Console to it."""
    installation_id = uuid.uuid4().hex
    install_root = root / "knowledge-install"
    install_root.mkdir(mode=0o700)
    data_volume = f"sovereign-{installation_id}-knowledge-data"
    active = None
    services = None
    try:
        active = start_signed_knowledge(bundle, trusted, crane, install_root,
                                        installation_id, initialize=True)
        state = root / "vessel-state"
        state.mkdir(mode=0o700)
        synthetic_fixture(state)
        lab_password = root / "lab-password"
        private_put(lab_password, (secrets.token_urlsafe(24) + "\n").encode())
        config = root / "console-config.json"
        config.write_text('{"schema":1,"oidc_issuer":null}\n')
        config.chmod(0o644)
        writer = install_root / "knowledge-secrets/writer.pgpass"
        _run("docker", "run", "--rm", "--pull", "never",
             "--network", "none", "--read-only",
             "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
             "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
             "--user", f"{state.stat().st_uid}:{state.stat().st_gid}",
             "--mount", (f"type=volume,source={active.socket_volume},"
                         "target=/run/postgresql,readonly"),
             "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign,readonly",
             "--mount", (f"type=bind,source={writer.resolve()},"
                         "target=/run/secrets/pgpass,readonly"),
             "-e", "SOVEREIGN_KNOWLEDGE_DB=postgresql://sovereign_ingest@/postgres?host=/run/postgresql",
             "-e", "PGPASSFILE=/run/secrets/pgpass", core_image,
             "python", "-c", _BOOTSTRAP)
        postgres_sql(active.container_id,
                     "GRANT SELECT ON knowledge_sources, knowledge_passages, "
                     "knowledge_quarantine, knowledge_vectors TO sovereign_read")
        postgres_sql(active.container_id,
                     "CREATE TABLE synthetic_persistence_probe (id integer PRIMARY KEY)")
        postgres_sql(active.container_id,
                     "INSERT INTO synthetic_persistence_probe VALUES (1)")
        first_socket = active.socket_volume
        stop_knowledge(active)
        active = None
        active = start_signed_knowledge(bundle, trusted, crane, install_root,
                                        installation_id, initialize=False)
        if (active.socket_volume == first_socket or
                postgres_sql(active.container_id,
                             "SELECT count(*) FROM synthetic_persistence_probe") != "1" or
                not postgres_sql(active.container_id,
                                 "SELECT extversion FROM pg_extension WHERE extname='vector'")):
            raise AssertionError("signed Knowledge database did not survive restart")
        services = start_signed_vessel_services(bundle, trusted, crane, config,
                                                state, lab_password, install_root,
                                                active, installation_id)
        return {"result": "pass", "database_state": "persisted",
                "socket": "recreated", "network_mode": "none",
                "signed_core_console": "healthy", "core_database_role": "sovereign_read"}
    finally:
        if services is not None:
            stop_runtime(services)
        if active is not None:
            stop_knowledge(active)
        subprocess.run(["docker", "volume", "rm", data_volume],
                       capture_output=True, text=True, timeout=30)


def _rehearse_first_install(bundle: Path, trusted: Path, crane: Path,
                            root: Path) -> dict[str, str]:
    """Activate from signed media and check the recorded three-image state."""
    state = root / "vessel-state"
    lab_password = root / "lab-password"
    config = root / "console-config.json"
    install_root = root / "installed-vessel"
    orphan_knowledge = None
    orphan_services = None
    try:
        activated = install_vessel(bundle, trusted, crane, config, install_root,
                                   state, lab_password)
        status = status_vessel(install_root, trusted, crane)
        if (activated.get("result") != "activated" or
                status.get("result") != "healthy" or
                (install_root / "vessel-intent.json").exists() or
                activated.get("active") != status.get("active")):
            raise AssertionError("signed first installation did not become healthy")
        record = json.loads((install_root / "vessel-state.json").read_text())
        runtime = record["runtime"]
        stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                                   runtime["console_id"]))
        stopped = finish_vessel_stop(install_root, trusted, crane)
        stage = install_root / "vessel-releases" / record["active"]
        orphan_knowledge = start_signed_knowledge(
            stage / "bundle", trusted, crane, install_root,
            record["installation_id"], initialize=False)
        orphan_services = start_signed_vessel_services(
            stage / "bundle", trusted, crane, stage / "console-config.json",
            state, lab_password, install_root, orphan_knowledge,
            record["installation_id"])
        reconciled = reconcile_vessel(install_root, trusted, crane)
        recovered = recover_vessel(install_root, trusted, crane)
        restored_status = status_vessel(install_root, trusted, crane)
        if (stopped.get("result") != "stopped" or
                reconciled != {"result": "reconciled", "containers": 3,
                               "networks": 1, "sockets": 1} or
                recovered.get("result") != "recovered" or
                restored_status.get("result") != "healthy" or
                recovered.get("active") != activated.get("active")):
            raise AssertionError("signed stopped-runtime recovery did not become healthy")
        return {"result": "pass", "activation": "signed-and-healthy",
                "state": "recorded-after-health", "recovery": "stopped-and-recovered",
                "interrupted_recovery": "orphan-runtime-reconciled",
                "interrupted_stop": "knowledge-stop-completed"}
    finally:
        if orphan_services is not None:
            stop_runtime(orphan_services)
        if orphan_knowledge is not None:
            try:
                stop_knowledge(orphan_knowledge)
            except Exception:
                pass
        path = install_root / "vessel-state.json"
        if path.exists():
            record = json.loads(path.read_text())
            runtime = record["runtime"]
            stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                                       runtime["console_id"]))
            try:
                stop_knowledge(KnowledgeVolumeHandle(
                    runtime["knowledge_id"], runtime["socket_volume"],
                    runtime["data_volume"], runtime["knowledge_run"],
                    record["installation_id"]))
            except Exception:
                pass
            subprocess.run(["docker", "volume", "rm", runtime["data_volume"]],
                           capture_output=True, text=True, timeout=30)


def _run(*argv: str) -> str:
    complete = subprocess.run(argv, check=True, capture_output=True,
                              text=True, timeout=300)
    return complete.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rehearse(output: Path, crane: Path, crane_sha256: str, syft: Path,
             syft_sha256: str, trivy: Path, trivy_sha256: str,
             trivy_cache: Path) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise ValueError("three-image evidence output must be new")
    output.mkdir(parents=True)
    result: dict[str, object] = {"source": "locally-built-synthetic-vessel-images",
                                 "images": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="sovereign-three-image-") as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "images").mkdir(parents=True)
            (payload / "evidence").mkdir()
            descriptors: dict[str, dict[str, str]] = {}
            for role in ROLES:
                tag = f"sovereign-{role}:synthetic"
                image_id = _run("docker", "image", "inspect", tag,
                                "--format", "{{.Id}}")
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                    raise ValueError("invalid built product image ID")
                archive = payload / "images" / f"{role}.tar"
                _run("docker", "save", "-o", str(archive), tag)
                digest = _run(str(crane), "digest", "--tarball", str(archive))
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    raise ValueError("invalid product archive manifest digest")
                image_ref = f"registry.example.invalid/sovereign/{role}@{digest}"
                identity = validate_image_archive(archive, image_ref,
                                                  crane, crane_sha256)
                scan = payload / "evidence" / f"{role}-scan.json"
                sbom = payload / "evidence" / f"{role}-sbom.json"
                inventory = generate_resolved_sbom(archive, image_ref, sbom,
                                                   crane, crane_sha256,
                                                   syft, syft_sha256)
                generated = generate_archive_scan(archive, image_ref, scan,
                                                  crane, crane_sha256,
                                                  trivy, trivy_sha256,
                                                  trivy_cache)
                shutil.copyfile(scan, output / scan.name)
                shutil.copyfile(sbom, output / sbom.name)
                findings = [item for section in json.loads(scan.read_text())["Results"]
                            for item in section.get("Vulnerabilities", [])
                            if item.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
                entry = {"image_id": image_id, "image_ref": image_ref,
                         "archive_sha256": identity["archive_sha256"],
                         "scan_sha256": generated["scan_sha256"],
                         "sbom_sha256": inventory["sbom_sha256"],
                         "components": inventory["components"],
                         "unresolved_findings": len(findings)}
                try:
                    verify_intake(scan, sbom, image_ref,
                                  generated["scan_sha256"],
                                  inventory["sbom_sha256"])
                except IntakeError as exc:
                    if not findings or "unresolved high, critical or unknown findings" not in str(exc):
                        raise
                    entry["intake"] = "denied-findings"
                else:
                    entry["intake"] = "preflight-pass"
                result["images"][role] = entry
                descriptors[role] = {
                    "image_ref": image_ref,
                    "archive_path": f"images/{role}.tar",
                    "archive_sha256": identity["archive_sha256"],
                    "crane_sha256": crane_sha256,
                    "scan_path": f"evidence/{role}-scan.json",
                    "scan_sha256": generated["scan_sha256"],
                    "sbom_path": f"evidence/{role}-sbom.json",
                    "sbom_sha256": inventory["sbom_sha256"],
                }
            if any(result["images"][role]["intake"] != "preflight-pass"
                   for role in ROLES):
                result["three_image_bundle"] = "denied-findings"
            else:
                key = Ed25519PrivateKey.generate()
                private = root / "synthetic-private.pem"
                trusted = root / "synthetic-trusted.pem"
                private.write_bytes(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
                private.chmod(0o600)
                trusted.write_bytes(key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
                bundle = root / "signed-three-image-trial"
                created = create_knowledge_bundle(payload, bundle, private,
                                                  "synthetic-three-image-trial",
                                                  descriptors, crane=crane)
                verified = verify_bundle(bundle, trusted)
                if (verified != created or verified.get("schema") != 6 or
                        verified.get("target") != "vessel" or
                        set(verified.get("images", {})) != set(ROLES)):
                    raise AssertionError("three-image vessel bundle verification failed")
                result["three_image_bundle"] = "signed-and-verified"
                result["bundle_manifest_sha256"] = _sha256(bundle / "release-manifest.json")
                ids = {role: _image_id(bundle, role, verified["images"][role], crane)
                       for role in ROLES}
                runtime = _rehearse_verified_images(ids["knowledge"], ids["core"],
                                                     ids["console"])
                if (runtime.get("result") != "pass" or
                        runtime.get("database_role") != "sovereign_read" or
                        runtime.get("console_runtime") != "healthy" or
                        runtime.get("network_mode") != "internal" or
                        runtime.get("knowledge_network_mode") != "none"):
                    raise AssertionError("signed three-image socket runtime failed")
                result["signed_three_image_runtime"] = {
                    "result": "pass", "transport": runtime["database_transport"],
                    "network_mode": runtime["network_mode"],
                    "knowledge_network_mode": runtime["knowledge_network_mode"],
                    "console_runtime": runtime["console_runtime"],
                    "database_role": runtime["database_role"],
                    "database_write": runtime["database_write"],
                    "writer_auth": runtime["writer_auth"],
                    "revocation": runtime["revocation"],
                }
                result["persistent_knowledge_restart"] = \
                    _rehearse_persistent_knowledge(bundle, trusted, crane, root,
                                                  ids["core"])
                result["signed_vessel_first_install"] = \
                    _rehearse_first_install(bundle, trusted, crane, root)
            (output / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
            return result
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--crane-sha256", required=True)
    parser.add_argument("--syft", required=True, type=Path)
    parser.add_argument("--syft-sha256", required=True)
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--trivy-sha256", required=True)
    parser.add_argument("--trivy-cache", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.output, args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256, args.trivy,
                             args.trivy_sha256, args.trivy_cache), sort_keys=True))


if __name__ == "__main__":
    main()
