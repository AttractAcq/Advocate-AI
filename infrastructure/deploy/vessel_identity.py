"""Validate the external identity resources required by a vessel OIDC runtime."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
import stat

from infrastructure.deploy.container_runtime import _docker, _validate_console_config


class VesselIdentityError(ValueError):
    """A vessel identity resource is missing or unsafe."""


@dataclass(frozen=True)
class VesselIdentity:
    issuer: str
    ca_file: Path
    revocations_file: Path
    network_name: str
    network_id: str


def _private_regular(path: Path, *, maximum: int) -> bytes:
    if not path.is_absolute():
        raise VesselIdentityError("identity file path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            details = os.fstat(stream.fileno())
            if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                    or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) & 0o077
                    or details.st_size > maximum):
                raise VesselIdentityError("unsafe vessel identity file")
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise VesselIdentityError("oversized vessel identity file")
        return content
    except OSError as exc:
        raise VesselIdentityError("vessel identity file unavailable") from exc


def _revocations(path: Path) -> None:
    raw = _private_regular(path, maximum=4 * 1024 * 1024)
    if raw and not raw.endswith(b"\n"):
        raise VesselIdentityError("truncated OIDC revocation log")
    try:
        for line in raw.splitlines():
            def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, item in pairs:
                    if key in value:
                        raise VesselIdentityError("duplicate OIDC revocation key")
                    value[key] = item
                return value
            record = json.loads(line, object_pairs_hook=unique)
            if (not isinstance(record, dict) or set(record) != {"sha256"}
                    or not isinstance(record["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
                raise VesselIdentityError("invalid OIDC revocation record")
    except (UnicodeError, ValueError) as exc:
        raise VesselIdentityError("invalid OIDC revocation log") from exc


def preflight_vessel_identity(config: Path, state: Path, network_name: str) -> VesselIdentity:
    """Check exact local OIDC material before any candidate runtime is created."""
    issuer = _validate_console_config(config, allow_oidc=True)
    if issuer is None:
        raise VesselIdentityError("vessel OIDC configuration requires an issuer")
    if (not state.is_absolute() or state.is_symlink() or not state.is_dir()
            or state.stat().st_uid != os.getuid()
            or stat.S_IMODE(state.stat().st_mode) & 0o077):
        raise VesselIdentityError("vessel Core state must be owner-only")
    ca = state / "oidc-ca.pem"
    revocations = state / "oidc-revocations.jsonl"
    ca_bytes = _private_regular(ca, maximum=64 * 1024)
    if not ca_bytes:
        raise VesselIdentityError("empty OIDC CA")
    try:
        ssl.create_default_context(cadata=ca_bytes.decode("ascii"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise VesselIdentityError("invalid OIDC CA") from exc
    _revocations(revocations)
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}", network_name)
            or network_name.startswith("sovereign-synthetic-")):
        raise VesselIdentityError("invalid vessel identity network name")
    network_id = _docker("network", "inspect", network_name, "--format", "{{.Id}}")
    if (not re.fullmatch(r"[0-9a-f]{64}", network_id)
            or _docker("network", "inspect", network_name, "--format", "{{.Internal}}") != "true"
            or _docker("network", "inspect", network_name, "--format",
                       '{{index .Labels "sovereign.vessel.identity"}}') != "true"):
        raise VesselIdentityError("vessel identity network must be labelled and internal")
    return VesselIdentity(issuer, ca, revocations, network_name, network_id)
