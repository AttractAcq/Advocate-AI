"""Strict Fleet metadata catalog and transaction-bound import audit."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FleetError(ValueError):
    """Fleet metadata, references or audit integrity failed validation."""


class FleetIntegrityError(FleetError):
    """The persisted record or audit chain changed outside the catalog."""


class Metadata(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Customer(Metadata):
    code: str = Field(pattern=r"^CUST-[A-Z0-9]{4,12}$")
    category: Literal["owner_manager", "charter_operator", "service_partner"]


class Release(Metadata):
    code: str = Field(pattern=r"^REL-[A-Z0-9]{4,16}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signing_key_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["candidate", "approved", "retired"]


class Deployment(Metadata):
    code: str = Field(pattern=r"^VSL-[A-Z0-9]{4,12}$")
    customer_code: str = Field(pattern=r"^CUST-[A-Z0-9]{4,12}$")
    release_code: str = Field(pattern=r"^REL-[A-Z0-9]{4,16}$")
    hardware_profile: Literal["reference_gpu", "pilot_gpu", "other_approved"]
    status: Literal["planned", "lab", "pilot", "active", "retired"]


class Licence(Metadata):
    code: str = Field(pattern=r"^LIC-[A-Z0-9]{4,12}$")
    customer_code: str = Field(pattern=r"^CUST-[A-Z0-9]{4,12}$")
    vessel_code: str = Field(pattern=r"^VSL-[A-Z0-9]{4,12}$")
    tier: Literal["pilot", "standard", "fleet"]
    valid_from: date
    valid_until: date
    status: Literal["pending", "active", "suspended", "expired"]

    @model_validator(mode="after")
    def valid_dates(self) -> "Licence":
        if self.valid_until <= self.valid_from:
            raise ValueError("licence end date must follow start date")
        return self


class Ticket(Metadata):
    code: str = Field(pattern=r"^TKT-[A-Z0-9]{4,12}$")
    vessel_code: str = Field(pattern=r"^VSL-[A-Z0-9]{4,12}$")
    category: Literal["installation", "update", "recovery", "access", "hardware"]
    priority: Literal["p1", "p2", "p3", "p4"]
    status: Literal["open", "triaged", "waiting", "resolved"]


class Maintenance(Metadata):
    code: str = Field(pattern=r"^MNT-[A-Z0-9]{4,12}$")
    vessel_code: str = Field(pattern=r"^VSL-[A-Z0-9]{4,12}$")
    kind: Literal["backup_rehearsal", "permission_review", "offline_update", "hardware_check"]
    due_on: date
    engineer_code: str = Field(pattern=r"^ENGR-[A-Z0-9]{3,12}$")
    status: Literal["planned", "completed", "deferred"]


class DeploymentReceipt(Metadata):
    code: str = Field(pattern=r"^RCP-[A-Z0-9]{4,12}$")
    vessel_code: str = Field(pattern=r"^VSL-[A-Z0-9]{4,12}$")
    release_code: str = Field(pattern=r"^REL-[A-Z0-9]{4,16}$")
    source: Literal["approved_offline_admin"]
    observed_on: date
    health: Literal["healthy", "degraded", "offline"]


class LicenceStatus(Metadata):
    status: Literal["active", "suspended", "expired"]


class ReleaseStatus(Metadata):
    status: Literal["approved", "retired"]


class TicketStatus(Metadata):
    status: Literal["triaged", "waiting", "resolved"]


class MaintenanceStatus(Metadata):
    status: Literal["planned", "completed", "deferred"]


KIND_MODELS = {"customer": Customer, "release": Release,
               "deployment": Deployment, "licence": Licence,
               "ticket": Ticket, "maintenance": Maintenance,
               "receipt": DeploymentReceipt}
KINDS = set(KIND_MODELS)
STATUS_TRANSITIONS = {
    "release": {"candidate": {"approved"}, "approved": {"retired"},
                "retired": set()},
    "licence": {"pending": {"active", "expired"},
                "active": {"suspended", "expired"},
                "suspended": {"active", "expired"}, "expired": set()},
    "ticket": {"open": {"triaged"}, "triaged": {"waiting", "resolved"},
               "waiting": {"triaged", "resolved"}, "resolved": set()},
    "maintenance": {"planned": {"completed", "deferred"},
                    "completed": set(), "deferred": {"planned"}},
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FleetIntegrityError("duplicate Fleet record field")
        value[key] = item
    return value


class FleetCatalog:
    """Single-host lab store with no vessel connection or free-text fields."""

    def __init__(self, path: Path):
        if not path.is_absolute() or path.is_symlink():
            raise FleetError("Fleet database path must be absolute and unlinked")
        parent = path.parent
        if (parent.is_symlink() or not parent.is_dir()
                or parent.stat().st_uid != os.getuid()
                or stat.S_IMODE(parent.stat().st_mode) & 0o077):
            raise FleetError("Fleet database parent must be owner-only")
        if not path.exists():
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                 0o600)
            os.close(descriptor)
        if (not path.is_file() or path.stat().st_uid != os.getuid()
                or stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise FleetError("Fleet database must be owner-only")
        self.path = path
        with self._connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS records ("
                               "kind TEXT NOT NULL, code TEXT NOT NULL, payload TEXT NOT NULL, "
                               "PRIMARY KEY (kind, code))")
            connection.execute("CREATE TABLE IF NOT EXISTS audit ("
                               "seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, "
                               "action TEXT NOT NULL, kind TEXT NOT NULL, code TEXT NOT NULL, "
                               "digest TEXT NOT NULL, prev_hash TEXT NOT NULL, "
                               "chain_hash TEXT NOT NULL)")
            self._verify(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _verify(connection: sqlite3.Connection) -> None:
        previous = "0" * 64
        latest: dict[tuple[str, str], str] = {}
        for row in connection.execute("SELECT at, action, kind, code, digest, prev_hash, "
                                      "chain_hash FROM audit ORDER BY seq"):
            event = {key: row[key] for key in ("at", "action", "kind", "code", "digest")}
            calculated = hashlib.sha256(previous.encode() + _canonical(event)).hexdigest()
            if row["prev_hash"] != previous or row["chain_hash"] != calculated:
                raise FleetIntegrityError("Fleet audit chain failed verification")
            previous = calculated
            latest[(row["kind"], row["code"])] = row["digest"]
        seen: set[tuple[str, str]] = set()
        for row in connection.execute("SELECT kind, code, payload FROM records"):
            key = row["kind"], row["code"]
            if key in seen or latest.get(key) != _digest(row["payload"]):
                raise FleetIntegrityError("Fleet record does not match import audit")
            if row["kind"] not in KIND_MODELS:
                raise FleetIntegrityError("unknown persisted Fleet record type")
            try:
                payload = json.loads(row["payload"], object_pairs_hook=_unique)
                parsed = KIND_MODELS[row["kind"]].model_validate(payload)
            except (ValueError, TypeError) as exc:
                raise FleetIntegrityError("invalid persisted Fleet metadata") from exc
            if parsed.code != row["code"]:
                raise FleetIntegrityError("Fleet record code changed")
            seen.add(key)
        if seen != set(latest):
            raise FleetIntegrityError("Fleet audit references a missing record")

    @staticmethod
    def _require(connection: sqlite3.Connection, kind: str, code: str) -> dict[str, object]:
        row = connection.execute("SELECT payload FROM records WHERE kind=? AND code=?",
                                 (kind, code)).fetchone()
        if row is None:
            raise FleetError(f"missing {kind} reference")
        return json.loads(row["payload"])

    @staticmethod
    def _append_audit(connection: sqlite3.Connection, action: str, kind: str,
                      code: str, payload: str) -> None:
        last = connection.execute("SELECT chain_hash FROM audit ORDER BY seq DESC "
                                  "LIMIT 1").fetchone()
        previous = last["chain_hash"] if last else "0" * 64
        at = datetime.now(timezone.utc).isoformat()
        event = {"at": at, "action": action, "kind": kind,
                 "code": code, "digest": _digest(payload)}
        chain = hashlib.sha256(previous.encode() + _canonical(event)).hexdigest()
        connection.execute("INSERT INTO audit(at, action, kind, code, digest, "
                           "prev_hash, chain_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (at, action, kind, code, event["digest"], previous, chain))

    def add(self, kind: str, record: Metadata) -> dict[str, object]:
        return self._add(kind, record, "create")

    def add_signed_receipt(self, record: DeploymentReceipt,
                           issuer_key_id: str) -> dict[str, object]:
        if len(issuer_key_id) != 64 or any(c not in "0123456789abcdef"
                                           for c in issuer_key_id):
            raise FleetError("invalid offline receipt issuer")
        return self._add("receipt", record, f"import-signed:{issuer_key_id}")

    def add_verified_release(self, record: Release) -> dict[str, object]:
        if record.status != "candidate":
            raise FleetError("signed release import must start as candidate")
        return self._add("release", record,
                         f"import-signed-release:{record.signing_key_id}")

    def _add(self, kind: str, record: Metadata, action: str) -> dict[str, object]:
        if kind not in KIND_MODELS or type(record) is not KIND_MODELS[kind]:
            raise FleetError("unknown Fleet record type")
        data = record.model_dump(mode="json")
        code = data["code"]
        payload = _canonical(data).decode()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection)
            if kind == "deployment":
                self._require(connection, "customer", data["customer_code"])
                release = self._require(connection, "release", data["release_code"])
                if release["status"] != "approved":
                    raise FleetError("deployment requires an approved release")
            elif kind == "licence":
                self._require(connection, "customer", data["customer_code"])
                vessel = self._require(connection, "deployment", data["vessel_code"])
                if vessel["customer_code"] != data["customer_code"]:
                    raise FleetError("licence customer and vessel differ")
            elif kind in {"ticket", "maintenance"}:
                self._require(connection, "deployment", data["vessel_code"])
            elif kind == "receipt":
                vessel = self._require(connection, "deployment", data["vessel_code"])
                self._require(connection, "release", data["release_code"])
                if vessel["release_code"] != data["release_code"]:
                    raise FleetError("receipt release differs from deployment")
            try:
                connection.execute("INSERT INTO records(kind, code, payload) VALUES (?, ?, ?)",
                                   (kind, code, payload))
            except sqlite3.IntegrityError as exc:
                raise FleetError("duplicate Fleet record code") from exc
            self._append_audit(connection, action, kind, code, payload)
        return data

    def transition(self, kind: str, code: str, status: str) -> dict[str, object]:
        if kind not in STATUS_TRANSITIONS:
            raise FleetError("unsupported Fleet lifecycle")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection)
            data = self._require(connection, kind, code)
            previous = data["status"]
            if status not in STATUS_TRANSITIONS[kind][previous]:
                raise FleetError("invalid Fleet status transition")
            if kind == "release":
                first = connection.execute(
                    "SELECT action FROM audit WHERE kind='release' AND code=? "
                    "ORDER BY seq LIMIT 1", (code,)).fetchone()
                expected = f"import-signed-release:{data['signing_key_id']}"
                if first is None or first["action"] != expected:
                    raise FleetError("release lacks verified import provenance")
            data["status"] = status
            validated = KIND_MODELS[kind].model_validate(data)
            payload = _canonical(validated.model_dump(mode="json")).decode()
            connection.execute("UPDATE records SET payload=? WHERE kind=? AND code=?",
                               (payload, kind, code))
            self._append_audit(connection, f"status:{previous}:{status}", kind,
                               code, payload)
        return validated.model_dump(mode="json")

    def list(self, kind: str, *, after: str = "", limit: int = 100) -> list[dict[str, object]]:
        if kind not in KINDS:
            raise FleetError("unknown Fleet record type")
        if not isinstance(after, str) or not 1 <= limit <= 100:
            raise FleetError("invalid Fleet page")
        with self._connect() as connection:
            self._verify(connection)
            rows = connection.execute("SELECT payload FROM records WHERE kind=? "
                                      "AND code>? ORDER BY code LIMIT ?",
                                      (kind, after, limit))
            return [json.loads(row["payload"]) for row in rows]

    def audit(self, *, after: int = 0, limit: int = 100) -> list[dict[str, object]]:
        if not isinstance(after, int) or after < 0 or not 1 <= limit <= 100:
            raise FleetError("invalid Fleet audit page")
        with self._connect() as connection:
            self._verify(connection)
            rows = connection.execute("SELECT seq, at, action, kind, code, digest, "
                                      "chain_hash FROM audit WHERE seq>? "
                                      "ORDER BY seq LIMIT ?", (after, limit))
            return [dict(row) for row in rows]
