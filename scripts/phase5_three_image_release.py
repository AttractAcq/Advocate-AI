"""Sign and verify the exact built Core, Console and Knowledge image archives."""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle, _image_id, stop_runtime
from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeError, KnowledgeVolumeHandle, _volume,
    start_signed_knowledge, stop_knowledge,
)
from infrastructure.deploy.postgres_socket import sql as postgres_sql
from infrastructure.deploy.vessel_runtime import start_signed_vessel_services
from infrastructure.deploy.vessel_recovery_set import (
    abandon_incomplete_vessel_restore, activate_vessel_recovery_set,
    create_vessel_recovery_set, restore_vessel_recovery_files,
    retry_abandoned_vessel_restore,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _ingest, _release_id, _stage, _write_intent, _write_private_record,
    finish_vessel_stop, install_vessel,
    reconcile_first_install, reconcile_vessel, recover_vessel,
    reset_first_install, resume_first_install, status_vessel,
    stop_vessel,
)
from infrastructure.deploy.vessel_release_switch import (
    discard_stopped_vessel_stage, rollback_stopped_vessel_release,
    switch_stopped_vessel_release,
)
from infrastructure.release.bundle import (
    BundleError, SUPPORTED_VESSEL_COMPATIBILITY, create_knowledge_bundle,
    verify_bundle,
)
from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive
from scripts.phase3_pgvector_core_socket import _rehearse_verified_images
from scripts.synthetic_pg_fixture import fixture as synthetic_fixture, put as private_put
from scripts.phase5_postgres_rehearsal import _restore as restore_postgres_dump
from infrastructure.deploy.postgres_socket import ready as postgres_ready
from services.policy.audit import verify as verify_audit

ROLES = ("core", "console", "knowledge")

_VESSEL_HISTORY_PROBE = """\
import json,sys
from pathlib import Path
import httpx
with httpx.Client(base_url='http://127.0.0.1:18100',trust_env=False,timeout=5) as client:
 password=Path('/run/secrets/lab-password').read_text().strip()
 login=client.post('/api/login',json={'user_id':'engineer','password':password})
 assert login.status_code==200,login.text
 headers={'Authorization':'Bearer '+login.json()['access_token']}
 conversation_id=sys.argv[1]
 if conversation_id=='-':
  chat=client.post('/api/chat',headers=headers,json={'mode':'documents','message':'unfindable quasar zebra procedure'})
  assert chat.status_code==200,chat.text
  assert chat.json()['answer'].startswith('No matching permitted source'),chat.text
  conversation_id=chat.json()['conversation_id']
 result=client.get('/api/conversations/'+conversation_id,headers=headers)
 assert result.status_code==200,result.text
 assert len(result.json()['turns'])==1,result.text
 print(json.dumps({'conversation_id':conversation_id,'turns':len(result.json()['turns'])}))
"""


def _probe_vessel_history(core_id: str, conversation_id: str | None = None) -> dict[str, object]:
    return json.loads(_run("docker", "exec", core_id, "python", "-c",
                           _VESSEL_HISTORY_PROBE, conversation_id or "-"))


_VESSEL_PERMISSION_PROBE = """\
import json
from pathlib import Path
import httpx
with httpx.Client(base_url='http://127.0.0.1:18100',trust_env=False,timeout=5) as client:
 password=Path('/run/secrets/lab-password').read_text().strip()
 def auth(user):
  reply=client.post('/api/login',json={'user_id':user,'password':password})
  assert reply.status_code==200,(user,reply.text)
  return {'Authorization':'Bearer '+reply.json()['access_token']}
 engineer=auth('engineer')
 deckhand=auth('deckhand')
 def sources(headers):
  reply=client.get('/api/sources',headers=headers)
  assert reply.status_code==200,reply.text
  return {row['document_id'] for row in reply.json()['sources']}
 engineer_sources=sources(engineer)
 deckhand_sources=sources(deckhand)
 allowed=client.post('/api/search',headers=engineer,json={'query':'generator inspection'})
 denied=client.post('/api/search',headers=deckhand,json={'query':'generator inspection'})
 allowed_preview=client.get('/api/sources/ENG-001/preview',headers=engineer)
 preview=client.get('/api/sources/ENG-001/preview',headers=deckhand)
 assert allowed.status_code==200,allowed.text
 assert denied.status_code==200,denied.text
 allowed_ids={row['document_id'] for row in allowed.json()['results']}
 denied_ids={row['document_id'] for row in denied.json()['results']}
 assert {'ENG-001','DEC-001'}<=engineer_sources,engineer_sources
 assert 'ENG-001' not in deckhand_sources,deckhand_sources
 assert 'ENG-001' in allowed_ids,allowed_ids
 assert 'ENG-001' not in denied_ids,denied_ids
 assert allowed_preview.status_code==200,allowed_preview.text
 assert allowed_preview.json()['excerpt']=='generator inspection secret marker',allowed_preview.text
 assert preview.status_code==404,preview.text
 print(json.dumps({'engineer':'ENG-001-visible','deckhand':'ENG-001-denied'}))
"""


def _probe_vessel_permissions(core_id: str) -> dict[str, str]:
    return json.loads(_run("docker", "exec", core_id, "python", "-c",
                           _VESSEL_PERMISSION_PROBE))


def _rehearse_restored_knowledge(bundle: Path, trusted: Path, crane: Path,
                                 restored: Path, sources: int, passages: int) -> None:
    """Verify the recovered dump against recovered files on isolated clean PG."""
    manifest = verify_bundle(bundle, trusted)
    knowledge_image = _image_id(bundle, "knowledge", manifest["images"]["knowledge"], crane)
    core_image = _image_id(bundle, "core", manifest["images"]["core"], crane)
    token = uuid.uuid4().hex[:12]
    data_volume = f"sovereign-recovery-{token}-data"
    socket_volume = f"sovereign-recovery-{token}-socket"
    container = None
    try:
        _run("docker", "volume", "create", data_volume)
        _run("docker", "volume", "create", socket_volume)
        container = _run(
            "docker", "run", "-d", "--pull", "never", "--network", "none",
            "--name", f"sovereign-recovery-{token}",
            "--mount", f"type=volume,source={data_volume},target=/var/lib/postgresql/data",
            "--mount", f"type=volume,source={socket_volume},target=/run/postgresql",
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust", knowledge_image,
            "postgres", "-c", "listen_addresses=", "-c",
            "unix_socket_directories=/run/postgresql")
        postgres_ready(container)
        restore_postgres_dump(container, restored / "postgres.dump")
        program = """\
import json
from pathlib import Path
from services.knowledge.postgres_index import verify_knowledge_snapshot
root=Path('/var/lib/sovereign')
print(json.dumps(verify_knowledge_snapshot(root,root/'approved.json',
 'postgresql://postgres@/postgres?host=/run/postgresql')))
"""
        evidence = json.loads(_run(
            "docker", "run", "--rm", "--pull", "never", "--network", "none",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--mount", f"type=volume,source={socket_volume},target=/run/postgresql,readonly",
            "--mount", f"type=bind,source={restored.resolve()},target=/var/lib/sovereign,readonly",
            core_image, "python", "-c", program))
        if evidence != {"sources": sources, "passages": passages}:
            raise AssertionError("clean Knowledge restore differs from signed receipt")
    finally:
        if container is not None:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                           text=True, timeout=30)
        for volume in (socket_volume, data_volume):
            subprocess.run(["docker", "volume", "rm", volume], capture_output=True,
                           text=True, timeout=30)


def _rehearse_persistent_knowledge(bundle: Path, trusted: Path,
                                   crane: Path, root: Path) -> dict[str, str]:
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
        _ingest(bundle, trusted, crane, state, install_root, active)
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


def _rehearse_first_install(bundle: Path, update_bundle: Path,
                            trusted: Path, crane: Path,
                            root: Path, restic: Path,
                            restic_sha256: str) -> dict[str, str]:
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
        base_core_image = _run("docker", "inspect", runtime["core_id"],
                               "--format", "{{.Image}}")
        schema_rights = postgres_sql(
            runtime["knowledge_id"],
            "SELECT has_schema_privilege('sovereign_migrate','public','CREATE')::int || ':' || "
            "has_schema_privilege('sovereign_ingest','public','CREATE')::int || ':' || "
            "has_schema_privilege('sovereign_read','public','CREATE')::int")
        if schema_rights != "1:0:0":
            raise AssertionError("Knowledge migration and application roles are not separated")
        try:
            postgres_sql(runtime["knowledge_id"],
                         "UPDATE public.knowledge_schema_version SET version=2")
            try:
                status_vessel(install_root, trusted, crane)
            except VesselInstallError as exc:
                if "schema version" not in str(exc):
                    raise
            else:
                raise AssertionError("unknown Knowledge schema version was accepted")
        finally:
            postgres_sql(runtime["knowledge_id"],
                         "UPDATE public.knowledge_schema_version SET version=1")
        first_history = _probe_vessel_history(runtime["core_id"])
        first_permissions = _probe_vessel_permissions(runtime["core_id"])
        audit_path = state / "audit.jsonl"
        initial_audit = audit_path.read_bytes()
        initial_count, _ = verify_audit(audit_path, require_current_clock=True)
        if (not (state / "history.db").is_file() or
                first_history.get("turns") != 1 or initial_count < 1):
            raise AssertionError("vessel audit or conversation state was not persisted")
        stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                                   runtime["console_id"]))
        stopped = finish_vessel_stop(install_root, trusted, crane)
        recovery_root = root / "vessel-recovery"
        recovery_root.mkdir(mode=0o700)
        staging = recovery_root / "staging"
        staging.mkdir(mode=0o700)
        receipt = recovery_root / "receipt.json"
        password = recovery_root / "restic-password"
        private_put(password, (secrets.token_urlsafe(48) + "\n").encode())
        receipt_key = Ed25519PrivateKey.generate()
        receipt_private = recovery_root / "receipt-private.pem"
        receipt_public = recovery_root / "receipt-public.pem"
        private_put(receipt_private, receipt_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        private_put(receipt_public, receipt_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        captured = create_vessel_recovery_set(
            install_root, trusted, crane, recovery_root / "repository", password,
            restic, restic_sha256, staging, receipt_private, receipt)
        if verify_vessel_recovery_receipt(receipt, receipt_public) != captured:
            raise AssertionError("signed vessel recovery receipt changed")
        restored = recovery_root / "restored"
        restored_result = restore_vessel_recovery_files(
            receipt, receipt_public, password, restic, restic_sha256, restored)
        if (restored_result["audit_count"] != initial_count or
                (restored / "audit.jsonl").read_bytes() != initial_audit):
            raise AssertionError("restored vessel Core audit checkpoint changed")
        _rehearse_restored_knowledge(
            bundle, trusted, crane, restored, captured["sources"], captured["passages"])
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
        restored_record = json.loads((install_root / "vessel-state.json").read_text())
        restored_history = _probe_vessel_history(restored_record["runtime"]["core_id"],
                                                  first_history["conversation_id"])
        final_audit = audit_path.read_bytes()
        final_count, _ = verify_audit(audit_path, require_current_clock=True)
        if (stopped.get("result") != "stopped" or
                reconciled != {"result": "reconciled", "containers": 3,
                               "networks": 1, "sockets": 1} or
                recovered.get("result") != "recovered" or
                restored_status.get("result") != "healthy" or
                recovered.get("active") != activated.get("active") or
                restored_history != first_history or
                not final_audit.startswith(initial_audit) or
                final_count <= initial_count):
            raise AssertionError("signed stopped-runtime recovery did not become healthy")
        stop_vessel(install_root, trusted, crane)
        pre_switch_receipt = recovery_root / "pre-switch-receipt.json"
        pre_switch_capture = create_vessel_recovery_set(
            install_root, trusted, crane, recovery_root / "repository", password,
            restic, restic_sha256, staging, receipt_private,
            pre_switch_receipt)
        if (pre_switch_capture["release"] != activated["active"] or
                pre_switch_capture["audit_count"] < final_count):
            raise AssertionError("fresh pre-switch recovery set changed")
        staged_id = _release_id(update_bundle, config)
        partial_stage = install_root / "vessel-releases" / staged_id
        partial_stage.mkdir(mode=0o700)
        (partial_stage / "interrupted.tmp").write_text("synthetic partial stage\n")
        try:
            switch_stopped_vessel_release(
                install_root, trusted, crane, update_bundle, config,
                pre_switch_receipt, receipt_public, password, restic, restic_sha256,
                staging)
        except VesselInstallError as exc:
            if "invalid staged vessel release" not in str(exc):
                raise
        else:
            raise AssertionError("partial staged vessel release was accepted")
        discarded = discard_stopped_vessel_stage(
            install_root, trusted, update_bundle, config, discard_stage=True)
        if (discarded != {"result": "staged-candidate-discarded",
                          "release": staged_id} or partial_stage.exists()):
            raise AssertionError("partial vessel stage was not safely discarded")
        switched = switch_stopped_vessel_release(
            install_root, trusted, crane, update_bundle, config,
            pre_switch_receipt, receipt_public, password, restic, restic_sha256,
            staging)
        switched_status = status_vessel(install_root, trusted, crane)
        switched_record = json.loads((install_root / "vessel-state.json").read_text())
        switched_core_image = _run(
            "docker", "inspect", switched_record["runtime"]["core_id"],
            "--format", "{{.Image}}")
        switched_history = _probe_vessel_history(
            switched_record["runtime"]["core_id"], first_history["conversation_id"])
        switched_permissions = _probe_vessel_permissions(
            switched_record["runtime"]["core_id"])
        if (switched["result"] != "upgraded" or
                switched["previous"] != activated["active"] or
                switched["active"] == activated["active"] or
                switched_core_image == base_core_image or
                switched_status["active"] != switched["active"] or
                switched_history != first_history or
                switched_permissions != first_permissions or
                not audit_path.read_bytes().startswith(final_audit)):
            raise AssertionError("stopped signed vessel release switch failed")
        stop_vessel(install_root, trusted, crane)
        updated_recovery = recovery_root / "updated"
        updated_recovery.mkdir(mode=0o700)
        updated_staging = updated_recovery / "staging"
        updated_staging.mkdir(mode=0o700)
        updated_receipt = updated_recovery / "receipt.json"
        updated_capture = create_vessel_recovery_set(
            install_root, trusted, crane, updated_recovery / "repository",
            password, restic, restic_sha256, updated_staging,
            receipt_private, updated_receipt)
        if (verify_vessel_recovery_receipt(updated_receipt, receipt_public)
                != updated_capture or
                updated_capture["release"] != switched["active"] or
                updated_capture["audit_count"] <= captured["audit_count"] or
                updated_capture["sources"] != captured["sources"] or
                updated_capture["passages"] != captured["passages"]):
            raise AssertionError("post-switch vessel recovery set changed")
        rolled = rollback_stopped_vessel_release(
            install_root, trusted, crane, updated_receipt, receipt_public,
            password, restic, restic_sha256, updated_staging)
        rolled_status = status_vessel(install_root, trusted, crane)
        rolled_record = json.loads((install_root / "vessel-state.json").read_text())
        rolled_core_image = _run(
            "docker", "inspect", rolled_record["runtime"]["core_id"],
            "--format", "{{.Image}}")
        rolled_history = _probe_vessel_history(
            rolled_record["runtime"]["core_id"], first_history["conversation_id"])
        rolled_permissions = _probe_vessel_permissions(
            rolled_record["runtime"]["core_id"])
        if (rolled["result"] != "rolled-back" or
                rolled["active"] != activated["active"] or
                rolled["previous"] != switched["active"] or
                rolled_core_image != base_core_image or
                rolled_status["active"] != activated["active"] or
                rolled_history != first_history or
                rolled_permissions != first_permissions):
            raise AssertionError("stopped signed vessel rollback failed")
        return {"result": "pass", "activation": "signed-and-healthy",
                "schema_authority": "migration-role-only",
                "schema_version": 1, "unknown_schema": "denied",
                "audit_history": "persisted-across-recovery",
                "encrypted_recovery_set": "signed-restored-and-knowledge-verified",
                "state": "recorded-after-health", "recovery": "stopped-and-recovered",
                "interrupted_recovery": "orphan-runtime-reconciled",
                "interrupted_stop": "knowledge-stop-completed",
                "release_switch": "stopped-signed-and-healthy",
                "release_rollback": "stopped-signed-and-healthy",
                "core_image_change": "distinct-and-restored",
                "document_permissions": "preserved-across-switch-and-rollback",
                "partial_stage": "rejected-then-discarded",
                "post_switch_recovery_set": "signed-and-bound-to-updated-release"}
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


def _rehearse_secure_vessel_restore(bundle: Path, trusted: Path, crane: Path,
                                    root: Path, restic: Path,
                                    restic_sha256: str, *,
                                    updated: bool = False) -> dict[str, str]:
    """Activate the signed recovery set on clean, restricted synthetic data."""
    recovery_root = root / "vessel-recovery"
    recovery = recovery_root / "updated" if updated else recovery_root
    install_root = root / ("updated-recovered-install" if updated else "recovered-install")
    state = root / ("updated-recovered-state" if updated else "recovered-state")
    try:
        result = activate_vessel_recovery_set(
            bundle, trusted, crane, root / "console-config.json",
            recovery / "receipt.json", recovery_root / "receipt-public.pem",
            recovery_root / "restic-password", restic, restic_sha256,
            install_root, state, root / "lab-password", recovery / "staging")
        status = status_vessel(install_root, trusted, crane)
        record = json.loads((install_root / "vessel-state.json").read_text())
        runtime = record["runtime"]
        manifest = verify_bundle(bundle, trusted)
        expected_core = _image_id(bundle, "core", manifest["images"]["core"], crane)
        running_core = _run("docker", "inspect", runtime["core_id"],
                            "--format", "{{.Image}}")
        with closing(sqlite3.connect(state / "history.db")) as database:
            rows = database.execute("SELECT id FROM conversations").fetchall()
        if len(rows) != 1:
            raise AssertionError("clean restore lost conversation history")
        history = _probe_vessel_history(runtime["core_id"], rows[0][0])
        permissions = _probe_vessel_permissions(runtime["core_id"])
        if (result["result"] != "restored-and-activated" or
                status["result"] != "healthy" or
                result["active"] != status["active"] or
                result["installation_id"] != record["installation_id"] or
                result["sources"] < 1 or result["passages"] < 1 or
                running_core != expected_core or
                history["turns"] != 1 or
                permissions != {"engineer": "ENG-001-visible",
                                "deckhand": "ENG-001-denied"} or
                (state / "postgres.dump").exists() or
                (install_root / "vessel-intent.json").exists()):
            raise AssertionError("clean secure vessel restore did not activate")
        return {"result": "pass", "runtime": "signed-and-healthy",
                "database_roles": "scram-restricted",
                "document_permissions": "checked-after-restore",
                "history": "readable", "dump_exposure": "absent",
                "source_release": "post-switch" if updated else "initial"}
    finally:
        path = install_root / "vessel-state.json"
        if path.exists():
            record = json.loads(path.read_text())
            runtime = record["runtime"]
            stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                                       runtime["console_id"]))
            stop_knowledge(KnowledgeVolumeHandle(
                runtime["knowledge_id"], runtime["socket_volume"],
                runtime["data_volume"], runtime["knowledge_run"],
                record["installation_id"]))
            subprocess.run(["docker", "volume", "rm", runtime["data_volume"]],
                           capture_output=True, text=True, timeout=30)


def _rehearse_interrupted_restore_abandon(bundle: Path, trusted: Path,
                                          crane: Path, root: Path,
                                          restic: Path,
                                          restic_sha256: str) -> dict[str, str]:
    """Discard only a signed partial candidate volume, retaining evidence."""
    recovery = root / "vessel-recovery"
    receipt = recovery / "receipt.json"
    receipt_key = recovery / "receipt-public.pem"
    value = verify_vessel_recovery_receipt(receipt, receipt_key)
    install = root / "partial-recovery-install"
    install.mkdir(mode=0o700)
    state = root / "partial-recovery-state"
    state.mkdir(mode=0o700)
    release, _ = _stage(install, bundle, trusted, root / "console-config.json")
    if release != value["release"]:
        raise AssertionError("partial recovery signed stage changed")
    restore_attempt = uuid.uuid4().hex
    _write_private_record(install, "vessel-restore-intent.json", {
        "schema": 2, "snapshot_id": value["snapshot_id"],
        "release": release, "installation_id": value["installation_id"],
        "restore_attempt": restore_attempt})
    _write_intent(install, release, value["installation_id"], state,
                  root / "lab-password")
    created = False
    retry_root = root / "retried-recovery-install"
    retry_state = root / "retried-recovery-state"
    try:
        wrong_attempt = uuid.uuid4().hex
        _volume(value["data_volume"], value["installation_id"],
                "knowledge-data", create=True,
                restore_attempt=wrong_attempt)
        created = True
        try:
            abandon_incomplete_vessel_restore(
                install, trusted, receipt, receipt_key, discard_partial_data=True)
        except KnowledgeVolumeError as exc:
            if "identity mismatch" not in str(exc):
                raise
        else:
            raise AssertionError("wrong restore-attempt volume was removed")
        _volume(value["data_volume"], value["installation_id"],
                "knowledge-data", create=False,
                restore_attempt=wrong_attempt)
        _run("docker", "volume", "rm", value["data_volume"])
        created = False
        _volume(value["data_volume"], value["installation_id"],
                "knowledge-data", create=True,
                restore_attempt=restore_attempt)
        created = True
        try:
            resume_first_install(install, trusted, crane)
        except VesselInstallError as exc:
            if "restore candidate" not in str(exc):
                raise
        else:
            raise AssertionError("generic first-install resume accepted partial restore")
        result = abandon_incomplete_vessel_restore(
            install, trusted, receipt, receipt_key, discard_partial_data=True)
        created = False
        if (result["result"] != "abandoned" or
                result["snapshot_id"] != value["snapshot_id"] or
                not (install / "vessel-restore-intent.json").is_file() or
                not (install / "vessel-restore-abandoned.json").is_file() or
                not state.is_dir()):
            raise AssertionError("partial recovery evidence was not retained")
        retried = retry_abandoned_vessel_restore(
            install, bundle, trusted, crane, root / "console-config.json",
            receipt, receipt_key, recovery / "restic-password",
            restic, restic_sha256,
            retry_root, retry_state, root / "lab-password",
            recovery / "staging")
        retry_status = status_vessel(retry_root, trusted, crane)
        retry_record = json.loads((retry_root / "vessel-state.json").read_text())
        with closing(sqlite3.connect(retry_state / "history.db")) as database:
            history_ids = database.execute("SELECT id FROM conversations").fetchall()
        if (retried["result"] != "restored-and-activated" or
                retried["retry_of_attempt"] != restore_attempt or
                retry_status["result"] != "healthy" or
                retry_record["installation_id"] != value["installation_id"] or
                len(history_ids) != 1 or
                _probe_vessel_history(retry_record["runtime"]["core_id"],
                                      history_ids[0][0])["turns"] != 1 or
                (retry_state / "postgres.dump").exists()):
            raise AssertionError("receipt-verified retry did not restore healthy vessel")
        return {"result": "pass", "volume": "checked-and-discarded",
                "wrong_attempt": "denied",
                "generic_resume": "denied", "evidence": "retained",
                "retry": "signed-and-healthy"}
    finally:
        retry_record = retry_root / "vessel-state.json"
        if retry_record.exists():
            record = json.loads(retry_record.read_text())
            runtime = record["runtime"]
            stop_runtime(RuntimeHandle(runtime["network_id"], runtime["core_id"],
                                       runtime["console_id"]))
            stop_knowledge(KnowledgeVolumeHandle(
                runtime["knowledge_id"], runtime["socket_volume"],
                runtime["data_volume"], runtime["knowledge_run"],
                record["installation_id"]))
            subprocess.run(["docker", "volume", "rm", runtime["data_volume"]],
                           capture_output=True, text=True, timeout=30)
        if created:
            subprocess.run(["docker", "volume", "rm", value["data_volume"]],
                           capture_output=True, text=True, timeout=30)


def _rehearse_first_install_resume(bundle: Path, trusted: Path, crane: Path,
                                    root: Path) -> dict[str, str]:
    """Simulate process loss before first activation and resume from intent."""
    install_root = root / "interrupted-first-install"
    install_root.mkdir(mode=0o700)
    installation_id = uuid.uuid4().hex
    data_volume = f"sovereign-{installation_id}-knowledge-data"
    state = root / "vessel-state"
    lab_password = root / "lab-password"
    orphan_knowledge = None
    orphan_services = None
    try:
        identifier, stage = _stage(install_root, bundle, trusted,
                                   root / "console-config.json")
        _write_intent(install_root, identifier, installation_id, state,
                      lab_password)
        orphan_knowledge = start_signed_knowledge(
            stage / "bundle", trusted, crane, install_root, installation_id,
            initialize=True)
        _ingest(stage / "bundle", trusted, crane, state, install_root,
                orphan_knowledge)
        orphan_services = start_signed_vessel_services(
            stage / "bundle", trusted, crane, stage / "console-config.json",
            state, lab_password, install_root, orphan_knowledge,
            installation_id)
        if (install_root / "vessel-state.json").exists():
            raise AssertionError("interrupted first install wrote active state")
        reconciled = reconcile_first_install(install_root, trusted, crane)
        resumed = resume_first_install(install_root, trusted, crane)
        healthy = status_vessel(install_root, trusted, crane)
        _write_intent(install_root, identifier, installation_id, state,
                      lab_password)
        completed = resume_first_install(install_root, trusted, crane)
        if (reconciled != {"result": "reconciled", "containers": 3,
                           "networks": 1, "sockets": 1} or
                resumed.get("result") != "activated" or
                healthy.get("result") != "healthy" or
                healthy.get("active") != identifier or
                completed != {"result": "already-activated", "active": identifier} or
                (install_root / "vessel-intent.json").exists()):
            raise AssertionError("interrupted first install did not resume safely")
        return {"result": "pass", "reconciled": "three-service-orphan",
                "activation": "resumed-and-healthy", "data_volume": "preserved",
                "committed_intent": "healthy-active-reconciled"}
    finally:
        if orphan_services is not None:
            stop_runtime(orphan_services)
        if orphan_knowledge is not None:
            try:
                stop_knowledge(orphan_knowledge)
            except Exception:
                pass
        active = install_root / "vessel-state.json"
        if active.exists():
            record = json.loads(active.read_text())
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
        subprocess.run(["docker", "volume", "rm", data_volume],
                       capture_output=True, text=True, timeout=30)


def _rehearse_bootstrap_reset(bundle: Path, trusted: Path, crane: Path,
                              root: Path) -> dict[str, str]:
    """Discard a labelled synthetic bootstrap volume, then install afresh."""
    install_root = root / "bootstrap-reset-install"
    install_root.mkdir(mode=0o700)
    installation_id = uuid.uuid4().hex
    data_volume = f"sovereign-{installation_id}-knowledge-data"
    try:
        identifier, _ = _stage(install_root, bundle, trusted,
                                root / "console-config.json")
        _write_intent(install_root, identifier, installation_id,
                      root / "vessel-state", root / "lab-password")
        credentials = install_root / "knowledge-secrets"
        credentials.mkdir(mode=0o700)
        partial = credentials / "admin-password"
        partial.write_text("synthetic-incomplete-bootstrap\n")
        partial.chmod(0o600)
        _volume(data_volume, installation_id, "knowledge-data", create=True)
        reset = reset_first_install(install_root, trusted, crane)
        resumed = resume_first_install(install_root, trusted, crane)
        healthy = status_vessel(install_root, trusted, crane)
        if (reset != {"result": "bootstrap-reset", "data_volume": "removed"} or
                resumed.get("result") != "activated" or
                healthy.get("result") != "healthy" or
                healthy.get("active") != identifier or credentials.is_symlink()):
            raise AssertionError("synthetic bootstrap reset did not reinitialize")
        return {"result": "pass", "discard": "labelled-data-volume",
                "activation": "fresh-signed"}
    finally:
        active = install_root / "vessel-state.json"
        if active.exists():
            record = json.loads(active.read_text())
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
        subprocess.run(["docker", "volume", "rm", data_volume],
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


def _qualify_image(tag: str, role: str, payload: Path, output: Path,
                   crane: Path, crane_sha256: str, syft: Path,
                   syft_sha256: str, trivy: Path, trivy_sha256: str,
                   trivy_cache: Path) -> tuple[dict[str, object], dict[str, str]]:
    image_id = _run("docker", "image", "inspect", tag, "--format", "{{.Id}}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("invalid built product image ID")
    archive = payload / "images" / f"{role}.tar"
    _run("docker", "save", "-o", str(archive), tag)
    digest = _run(str(crane), "digest", "--tarball", str(archive))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid product archive manifest digest")
    image_ref = f"registry.example.invalid/sovereign/{role}@{digest}"
    identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
    scan = payload / "evidence" / f"{role}-scan.json"
    sbom = payload / "evidence" / f"{role}-sbom.json"
    inventory = generate_resolved_sbom(archive, image_ref, sbom, crane,
                                       crane_sha256, syft, syft_sha256)
    generated = generate_archive_scan(archive, image_ref, scan, crane,
                                      crane_sha256, trivy, trivy_sha256,
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
        verify_intake(scan, sbom, image_ref, generated["scan_sha256"],
                      inventory["sbom_sha256"])
    except IntakeError as exc:
        if not findings or "unresolved high, critical or unknown findings" not in str(exc):
            raise
        entry["intake"] = "denied-findings"
    else:
        entry["intake"] = "preflight-pass"
    descriptor = {
        "image_ref": image_ref,
        "archive_path": f"images/{role}.tar",
        "archive_sha256": identity["archive_sha256"],
        "crane_sha256": crane_sha256,
        "scan_path": f"evidence/{role}-scan.json",
        "scan_sha256": generated["scan_sha256"],
        "sbom_path": f"evidence/{role}-sbom.json",
        "sbom_sha256": inventory["sbom_sha256"],
    }
    return entry, descriptor


def rehearse(output: Path, crane: Path, crane_sha256: str, syft: Path,
             syft_sha256: str, trivy: Path, trivy_sha256: str,
             trivy_cache: Path, restic: Path, restic_sha256: str,
             update_core_image: str) -> dict[str, object]:
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
            (payload / "model").mkdir()
            (payload / "model" / "config.json").write_text(
                '{"model_type":"synthetic-release-fixture"}\n')
            (payload / "model" / "weights.bin").write_bytes(
                b"fictional model bytes for release-binding only")
            descriptors: dict[str, dict[str, str]] = {}
            for role in ROLES:
                tag = f"sovereign-{role}:synthetic"
                entry, descriptor = _qualify_image(
                    tag, role, payload, output, crane, crane_sha256, syft,
                    syft_sha256, trivy, trivy_sha256, trivy_cache)
                result["images"][role] = entry
                descriptors[role] = descriptor
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
                                                  descriptors,
                                                  SUPPORTED_VESSEL_COMPATIBILITY,
                                                  crane=crane,
                                                  model_id="synthetic-lab-model")
                verified = verify_bundle(bundle, trusted)
                if (verified != created or verified.get("schema") != 7 or
                        verified.get("target") != "vessel" or
                        verified.get("compatibility") != SUPPORTED_VESSEL_COMPATIBILITY or
                        set(verified.get("images", {})) != set(ROLES) or
                        verified.get("model", {}).get("id") != "synthetic-lab-model"):
                    raise AssertionError("three-image vessel bundle verification failed")
                result["three_image_bundle"] = "signed-and-verified"
                result["model_artifact"] = "synthetic-bytes-signed-not-served"
                model_file = bundle / "model" / "weights.bin"
                original_model = model_file.read_bytes()
                model_file.write_bytes(b"altered fictional model")
                try:
                    try:
                        verify_bundle(bundle, trusted)
                    except BundleError:
                        result["model_tamper"] = "denied"
                    else:
                        raise AssertionError("modified model bytes passed bundle verification")
                finally:
                    model_file.write_bytes(original_model)
                if verify_bundle(bundle, trusted) != verified:
                    raise AssertionError("restored model bytes failed bundle verification")
                result["core_image_compatibility"] = "matched-signed-contract"
                update_payload = root / "update-payload"
                shutil.copytree(payload, update_payload, copy_function=os.link)
                for name in ("images/core.tar", "evidence/core-scan.json",
                             "evidence/core-sbom.json", "model/weights.bin"):
                    (update_payload / name).unlink()
                (update_payload / "model" / "weights.bin").write_bytes(
                    b"different fictional model bytes for updated release")
                update_output = output / "updated-core"
                update_output.mkdir()
                # The signed vessel runtime accepts only this canonical archive tag.
                # Retagging changes neither the built image ID nor its configuration.
                _run("docker", "tag", update_core_image,
                     "sovereign-core:synthetic")
                update_entry, update_descriptor = _qualify_image(
                    "sovereign-core:synthetic", "core", update_payload,
                    update_output,
                    crane, crane_sha256, syft, syft_sha256, trivy,
                    trivy_sha256, trivy_cache)
                if (update_entry["intake"] != "preflight-pass" or
                        update_entry["image_id"] == result["images"]["core"]["image_id"] or
                        update_entry["image_ref"] == result["images"]["core"]["image_ref"]):
                    raise AssertionError("second Core image is not a distinct qualified release")
                result["updated_core_image"] = update_entry
                update_descriptors = {**descriptors, "core": update_descriptor}
                update_bundle = root / "signed-three-image-trial-v2"
                create_knowledge_bundle(update_payload, update_bundle, private,
                                        "synthetic-three-image-trial-v2",
                                        update_descriptors,
                                        SUPPORTED_VESSEL_COMPATIBILITY,
                                        crane=crane,
                                        model_id="synthetic-lab-model")
                update_verified = verify_bundle(update_bundle, trusted)
                if (update_verified.get("schema") != 7 or
                        update_verified.get("target") != "vessel" or
                        update_verified.get("compatibility") != SUPPORTED_VESSEL_COMPATIBILITY or
                        set(update_verified.get("images", {})) != set(ROLES) or
                        update_verified.get("model", {}).get("id") != "synthetic-lab-model" or
                        update_verified.get("model") == verified.get("model")):
                    raise AssertionError("second signed vessel bundle verification failed")
                result["model_update"] = "different-signed-bytes"
                if (_image_id(update_bundle, "core", update_verified["images"]["core"], crane)
                        == _image_id(bundle, "core", verified["images"]["core"], crane)):
                    raise AssertionError("signed Core image identity did not change")
                result["bundle_manifest_sha256"] = _sha256(bundle / "release-manifest.json")
                result["vessel_compatibility"] = SUPPORTED_VESSEL_COMPATIBILITY
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
                    _rehearse_persistent_knowledge(bundle, trusted, crane, root)
                result["signed_vessel_first_install"] = \
                    _rehearse_first_install(bundle, update_bundle, trusted, crane,
                                            root, restic,
                                            restic_sha256)
                result["signed_vessel_clean_restore"] = \
                    _rehearse_secure_vessel_restore(bundle, trusted, crane, root,
                                                    restic, restic_sha256)
                result["signed_vessel_updated_restore"] = \
                    _rehearse_secure_vessel_restore(update_bundle, trusted, crane,
                                                    root, restic, restic_sha256,
                                                    updated=True)
                result["interrupted_restore_abandon"] = \
                    _rehearse_interrupted_restore_abandon(
                        bundle, trusted, crane, root, restic, restic_sha256)
                result["interrupted_first_install"] = \
                    _rehearse_first_install_resume(bundle, trusted, crane, root)
                result["bootstrap_reset"] = \
                    _rehearse_bootstrap_reset(bundle, trusted, crane, root)
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
    parser.add_argument("--restic", required=True, type=Path)
    parser.add_argument("--restic-sha256", required=True)
    parser.add_argument("--update-core-image", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.output, args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256, args.trivy,
                             args.trivy_sha256, args.trivy_cache,
                             args.restic, args.restic_sha256,
                             args.update_core_image), sort_keys=True))


if __name__ == "__main__":
    main()
