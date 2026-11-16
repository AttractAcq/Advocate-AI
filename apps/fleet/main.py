"""Local synthetic Fleet API with explicit metadata-only request bodies."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, status

from services.fleet.catalog import (
    Customer, Deployment, FleetCatalog, FleetError,
    FleetIntegrityError, Licence, LicenceStatus, Maintenance, MaintenanceStatus,
    Release, Ticket, TicketStatus,
)
from services.fleet.offline_import import (
    SignedDeploymentReceipt, load_import_key, verify_signed_receipt,
)


@dataclass(frozen=True)
class FleetSettings:
    db_path: Path
    admin_token: str
    import_public_key: Ed25519PublicKey | None = None

    @classmethod
    def from_env(cls) -> "FleetSettings":
        database = os.environ.get("SOVEREIGN_FLEET_DB")
        filename = os.environ.get("SOVEREIGN_FLEET_TOKEN_FILE")
        if not database or not filename:
            raise ValueError("Fleet database and owner-only token file are required")
        path = Path(filename)
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or path.stat().st_uid != os.getuid()
                or stat.S_IMODE(path.stat().st_mode) & 0o077
                or path.stat().st_size > 4096):
            raise ValueError("invalid Fleet lab token file")
        token = path.read_text(encoding="utf-8").rstrip("\n")
        if not 32 <= len(token) <= 200 or "\n" in token or "\r" in token:
            raise ValueError("invalid Fleet lab token")
        import_path = os.environ.get("SOVEREIGN_FLEET_IMPORT_KEY_FILE")
        import_key = load_import_key(Path(import_path)) if import_path else None
        return cls(Path(database), token, import_key)


def create_app(settings: FleetSettings | None = None) -> FastAPI:
    settings = settings or FleetSettings.from_env()
    if not 32 <= len(settings.admin_token) <= 200:
        raise ValueError("invalid Fleet lab token")
    catalog = FleetCatalog(settings.db_path)
    app = FastAPI(title="Sovereign Fleet synthetic lab", docs_url=None,
                  redoc_url=None, openapi_url=None)

    def authorise(x_fleet_lab_token: str | None = Header(default=None)) -> None:
        if (x_fleet_lab_token is None or
                not secrets.compare_digest(x_fleet_lab_token, settings.admin_token)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Fleet authentication required")

    router = APIRouter(prefix="/api/fleet", dependencies=[Depends(authorise)])

    def add(kind: str, record):
        try:
            return catalog.add(kind, record)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    def list_records(kind: str):
        try:
            return catalog.list(kind)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc

    def transition(kind: str, code: str, new_status: str):
        try:
            return catalog.transition(kind, code, new_status)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @router.post("/customers", status_code=201)
    def create_customer(record: Customer):
        return add("customer", record)

    @router.get("/customers")
    def customers():
        return list_records("customer")

    @router.post("/releases", status_code=201)
    def create_release(record: Release):
        return add("release", record)

    @router.get("/releases")
    def releases():
        return list_records("release")

    @router.post("/deployments", status_code=201)
    def create_deployment(record: Deployment):
        return add("deployment", record)

    @router.get("/deployments")
    def deployments():
        return list_records("deployment")

    @router.post("/licences", status_code=201)
    def create_licence(record: Licence):
        return add("licence", record)

    @router.get("/licences")
    def licences():
        return list_records("licence")

    @router.patch("/licences/{code}/status")
    def update_licence(code: str, change: LicenceStatus):
        return transition("licence", code, change.status)

    @router.post("/tickets", status_code=201)
    def create_ticket(record: Ticket):
        return add("ticket", record)

    @router.get("/tickets")
    def tickets():
        return list_records("ticket")

    @router.patch("/tickets/{code}/status")
    def update_ticket(code: str, change: TicketStatus):
        return transition("ticket", code, change.status)

    @router.post("/maintenance", status_code=201)
    def create_maintenance(record: Maintenance):
        return add("maintenance", record)

    @router.get("/maintenance")
    def maintenance():
        return list_records("maintenance")

    @router.patch("/maintenance/{code}/status")
    def update_maintenance(code: str, change: MaintenanceStatus):
        return transition("maintenance", code, change.status)

    @router.post("/import/deployment-receipts", status_code=201)
    def import_receipt(envelope: SignedDeploymentReceipt):
        if settings.import_public_key is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "offline receipt import is not configured")
        try:
            record = verify_signed_receipt(envelope, settings.import_public_key)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        try:
            return catalog.add_signed_receipt(record, envelope.key_id)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @router.get("/import/deployment-receipts")
    def receipts():
        return list_records("receipt")

    @router.get("/audit")
    def audit():
        try:
            return catalog.audit()
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc

    app.include_router(router)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
