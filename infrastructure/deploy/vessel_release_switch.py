"""Signed, stopped-only vessel release switch on an existing Knowledge volume."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat

from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, start_signed_knowledge,
)
from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _candidate_release_id, _cleanup_failed_install,
    _operation_lock, _owner_directory,
    _read_state, _recovery_inventory, _release_id, _stage, _state_payload,
    _verify_knowledge_schema, _verify_stage, _write_state,
)
from infrastructure.deploy.vessel_recovery_set import _verify_database
from infrastructure.deploy.vessel_runtime import _state_options, start_signed_vessel_services
from services.policy.policy_file import policy_directory_lock


def _discardable_stage(stage: Path) -> None:
    _owner_directory(stage)
    device = stage.stat().st_dev
    for item in stage.rglob("*"):
        details = item.lstat()
        if (details.st_uid != os.getuid() or details.st_dev != device or
                not (stat.S_ISREG(details.st_mode) or
                     stat.S_ISDIR(details.st_mode)) or
                stat.S_IMODE(details.st_mode) & 0o022):
            raise VesselInstallError("staged candidate contains unsafe entry")


def discard_stopped_vessel_stage(root: Path, trusted_key: Path, bundle: Path,
                                 console_config: Path,
                                 *, discard_stage: bool = False) -> dict[str, str]:
    """Remove one non-active stage after a clean stop and signed identity check."""
    if not discard_stage:
        raise VesselInstallError("explicit staged-candidate discard required")
    with _operation_lock(root):
        current = _read_state(root)
        active = current["active"]
        _verify_stage(root / "vessel-releases" / active, trusted_key, active)
        state = Path(current["core_state"])
        password = Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        identifier = _candidate_release_id(bundle, trusted_key, console_config)
        if identifier in (active, current.get("previous")):
            raise VesselInstallError("cannot discard active or rollback vessel release")
        releases = root / "vessel-releases"
        _owner_directory(releases)
        stage = releases / identifier
        _discardable_stage(stage)
        shutil.rmtree(stage)
        return {"result": "staged-candidate-discarded", "release": identifier}


def _activate_stopped(root: Path, trusted_key: Path, crane: Path,
                      current: dict[str, object], identifier: str,
                      stage: Path, result_name: str) -> dict[str, object]:
    state = Path(current["core_state"])
    password = Path(current["lab_password_file"])
    installation_id = current["installation_id"]
    data_volume = current["runtime"]["data_volume"]
    knowledge: KnowledgeVolumeHandle | None = None
    services: RuntimeHandle | None = None
    payload: dict[str, object] | None = None
    try:
        with policy_directory_lock(state / "roles.json"):
            knowledge = start_signed_knowledge(
                stage / "bundle", trusted_key, crane, root,
                installation_id, initialize=False)
            _verify_knowledge_schema(knowledge)
            inventory = _verify_database(stage / "bundle", trusted_key, crane,
                                         knowledge, state, root)
            services = start_signed_vessel_services(
                stage / "bundle", trusted_key, crane,
                stage / "console-config.json", state, password,
                root, knowledge, installation_id)
            payload = _state_payload(
                identifier, installation_id, state, password, services,
                knowledge, previous=current["active"])
            _write_state(root, payload)
        return {"result": result_name, "active": identifier,
                "previous": current["active"],
                "sources": inventory["sources"],
                "passages": inventory["passages"]}
    except Exception as exc:
        try:
            recorded = _read_state(root)
        except Exception:
            recorded = None
        if payload is not None and recorded != current:
            raise VesselInstallError(
                "release switch state may have changed; retain candidate for reconciliation"
            ) from exc
        if not _cleanup_failed_install(installation_id, services, knowledge,
                                       data_volume, retain_data=True):
            raise VesselInstallError(
                "release switch cleanup incomplete; prior state and data retained"
            ) from exc
        raise


def switch_stopped_vessel_release(root: Path, trusted_key: Path, crane: Path,
                                  bundle: Path,
                                  console_config: Path) -> dict[str, object]:
    """Activate a new signed release only after a clean vessel stop and health."""
    with _operation_lock(root):
        current = _read_state(root)
        old = current["active"]
        _verify_stage(root / "vessel-releases" / old, trusted_key, old)
        state, password = Path(current["core_state"]), Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        identifier = _release_id(bundle, console_config)
        if identifier == old:
            raise VesselInstallError("new vessel release equals active release")
        identifier, stage = _stage(root, bundle, trusted_key, console_config)
        return _activate_stopped(root, trusted_key, crane, current, identifier,
                                 stage, "upgraded")


def rollback_stopped_vessel_release(root: Path, trusted_key: Path,
                                    crane: Path) -> dict[str, object]:
    """Re-activate the previous signed release without changing Knowledge data."""
    with _operation_lock(root):
        current = _read_state(root)
        previous = current.get("previous")
        if previous is None:
            raise VesselInstallError("no previous vessel release")
        _verify_stage(root / "vessel-releases" / current["active"],
                      trusted_key, current["active"])
        stage = root / "vessel-releases" / previous
        _verify_stage(stage, trusted_key, previous)
        state, password = Path(current["core_state"]), Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        return _activate_stopped(root, trusted_key, crane, current, previous,
                                 stage, "rolled-back")
