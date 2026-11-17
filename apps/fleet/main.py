"""Local synthetic Fleet API with explicit metadata-only request bodies."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat
import re
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, status

from apps.api.oidc import OidcVerifier
from apps.fleet.body_limit import FleetBodyLimit
from services.fleet.catalog import (
    Customer, Deployment, FleetCatalog, FleetError,
    FleetIntegrityError, Licence, LicenceStatus, Maintenance, MaintenanceStatus,
    ReleaseStatus, Ticket, TicketStatus,
)
from services.fleet.offline_import import (
    SignedDeploymentReceipt, load_import_key, verify_signed_receipt,
)


PageAfter = Annotated[str, Query(max_length=32)]
PageLimit = Annotated[int, Query(ge=1, le=100)]
AuditAfter = Annotated[int, Query(ge=0)]
FLEET_ROLES = {"fleet_admin", "fleet_release_manager", "fleet_support", "fleet_viewer"}
CUSTOMER_CODE = re.compile(r"CUST-[A-Z0-9]{4,12}\Z")


def _owner_file(path: Path, maximum: int) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or path.stat().st_size > maximum):
        raise ValueError("Fleet identity file must be owner-only")


@dataclass(frozen=True)
class FleetSettings:
    db_path: Path
    admin_token: str | None
    import_public_key: Ed25519PublicKey | None = None
    oidc_verifier: OidcVerifier | None = None

    @classmethod
    def from_env(cls) -> "FleetSettings":
        database = os.environ.get("SOVEREIGN_FLEET_DB")
        filename = os.environ.get("SOVEREIGN_FLEET_TOKEN_FILE")
        issuer = os.environ.get("SOVEREIGN_FLEET_OIDC_ISSUER")
        roles_filename = os.environ.get("SOVEREIGN_FLEET_ROLES_FILE")
        if (not database or bool(issuer) != bool(roles_filename)
                or bool(filename) == bool(issuer)):
            raise ValueError("Fleet requires exactly one local identity mode")
        import_path = os.environ.get("SOVEREIGN_FLEET_IMPORT_KEY_FILE")
        import_key = load_import_key(Path(import_path)) if import_path else None
        if issuer and roles_filename:
            roles_path = Path(roles_filename)
            _owner_file(roles_path, 1024 * 1024)
            verifier = OidcVerifier(issuer, roles_path, audience="sovereign-fleet",
                                    authorized_client="sovereign-fleet-portal")
            return cls(Path(database), None, import_key, verifier)
        path = Path(filename or "")
        _owner_file(path, 4096)
        token = path.read_text(encoding="utf-8").rstrip("\n")
        if not 32 <= len(token) <= 200 or "\n" in token or "\r" in token:
            raise ValueError("invalid Fleet lab token")
        return cls(Path(database), token, import_key)


def create_app(settings: FleetSettings | None = None) -> FastAPI:
    settings = settings or FleetSettings.from_env()
    if (settings.oidc_verifier is None) == (settings.admin_token is None):
        raise ValueError("Fleet requires exactly one identity mode")
    if settings.admin_token is not None and not 32 <= len(settings.admin_token) <= 200:
        raise ValueError("invalid Fleet lab token")
    if (settings.oidc_verifier is not None and
            (settings.oidc_verifier.audience != "sovereign-fleet" or
             settings.oidc_verifier.authorized_client != "sovereign-fleet-portal")):
        raise ValueError("Fleet OIDC audience and client must be separate from Core")
    catalog = FleetCatalog(settings.db_path)
    app = FastAPI(title="Sovereign Fleet synthetic lab", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.add_middleware(FleetBodyLimit)

    def authorise(x_fleet_lab_token: str | None = Header(default=None),
                  authorization: str | None = Header(default=None)) -> dict:
        if settings.oidc_verifier is not None:
            if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Fleet authentication required")
            user = settings.oidc_verifier.user_for(authorization.removeprefix("Bearer "))
            if user is None or user.get("role") not in FLEET_ROLES:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Fleet authentication required")
            customers = user.get("customer_codes")
            if (not isinstance(customers, list) or len(customers) > 100 or
                    any(not isinstance(code, str) or
                        (code != "*" and not CUSTOMER_CODE.fullmatch(code))
                        for code in customers) or len(set(customers)) != len(customers) or
                    ("*" in customers and
                     (len(customers) != 1 or user["role"] not in
                      {"fleet_admin", "fleet_release_manager"}))):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Fleet customer scope required")
            return user
        if (x_fleet_lab_token is None or settings.admin_token is None or
                not secrets.compare_digest(x_fleet_lab_token, settings.admin_token)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Fleet authentication required")
        return {"id": "synthetic-admin", "role": "fleet_admin",
                "customer_codes": ["*"]}

    def scope(user: dict) -> frozenset[str] | None:
        customers = user["customer_codes"]
        return None if customers == ["*"] else frozenset(customers)

    def require_customer(user: dict, customer: str) -> None:
        allowed = scope(user)
        if allowed is not None and customer not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Fleet customer is not authorised")

    def require_record(user: dict, kind: str, code: str) -> None:
        try:
            customer = catalog.customer_for(kind, code)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Fleet record not found") from exc
        if customer is None:
            if scope(user) is not None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Fleet record not found")
        else:
            if scope(user) is not None and customer not in scope(user):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Fleet record not found")

    def require_roles(*allowed: str):
        def check(user: dict[str, str] = Depends(authorise)) -> None:
            if user["role"] not in allowed:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Fleet role is not authorised")
        return check

    router = APIRouter(prefix="/api/fleet", dependencies=[Depends(authorise)])
    admin_only = [Depends(require_roles("fleet_admin"))]
    support_write = [Depends(require_roles("fleet_admin", "fleet_support"))]
    release_write = [Depends(require_roles("fleet_admin", "fleet_release_manager"))]
    audit_read = [Depends(require_roles("fleet_admin", "fleet_release_manager"))]

    @router.get("/me")
    def me(user: dict = Depends(authorise)):
        return {"id": user["id"], "role": user["role"],
                "customer_codes": user["customer_codes"]}

    def add(kind: str, record):
        try:
            return catalog.add(kind, record)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    def list_records(kind: str, after: str, limit: int, user: dict):
        try:
            return catalog.list(kind, after=after, limit=limit,
                                allowed_customers=scope(user))
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc

    def transition(kind: str, code: str, new_status: str, user: dict):
        require_record(user, kind, code)
        try:
            return catalog.transition(kind, code, new_status)
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc
        except FleetError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @router.post("/customers", status_code=201, dependencies=admin_only)
    def create_customer(record: Customer, user: dict = Depends(authorise)):
        require_customer(user, record.code)
        return add("customer", record)

    @router.get("/customers")
    def customers(after: PageAfter = "", limit: PageLimit = 100,
                  user: dict = Depends(authorise)):
        return list_records("customer", after, limit, user)

    @router.get("/releases")
    def releases(after: PageAfter = "", limit: PageLimit = 100,
                 user: dict = Depends(authorise)):
        return list_records("release", after, limit, user)

    @router.patch("/releases/{code}/status", dependencies=release_write)
    def update_release(code: str, change: ReleaseStatus, user: dict = Depends(authorise)):
        return transition("release", code, change.status, user)

    @router.post("/deployments", status_code=201, dependencies=admin_only)
    def create_deployment(record: Deployment, user: dict = Depends(authorise)):
        require_customer(user, record.customer_code)
        return add("deployment", record)

    @router.get("/deployments")
    def deployments(after: PageAfter = "", limit: PageLimit = 100,
                    user: dict = Depends(authorise)):
        return list_records("deployment", after, limit, user)

    @router.post("/licences", status_code=201, dependencies=admin_only)
    def create_licence(record: Licence, user: dict = Depends(authorise)):
        require_customer(user, record.customer_code)
        require_record(user, "deployment", record.vessel_code)
        return add("licence", record)

    @router.get("/licences")
    def licences(after: PageAfter = "", limit: PageLimit = 100,
                 user: dict = Depends(authorise)):
        return list_records("licence", after, limit, user)

    @router.patch("/licences/{code}/status", dependencies=admin_only)
    def update_licence(code: str, change: LicenceStatus, user: dict = Depends(authorise)):
        return transition("licence", code, change.status, user)

    @router.post("/tickets", status_code=201, dependencies=support_write)
    def create_ticket(record: Ticket, user: dict = Depends(authorise)):
        require_record(user, "deployment", record.vessel_code)
        return add("ticket", record)

    @router.get("/tickets")
    def tickets(after: PageAfter = "", limit: PageLimit = 100,
                user: dict = Depends(authorise)):
        return list_records("ticket", after, limit, user)

    @router.patch("/tickets/{code}/status", dependencies=support_write)
    def update_ticket(code: str, change: TicketStatus, user: dict = Depends(authorise)):
        return transition("ticket", code, change.status, user)

    @router.post("/maintenance", status_code=201, dependencies=support_write)
    def create_maintenance(record: Maintenance, user: dict = Depends(authorise)):
        require_record(user, "deployment", record.vessel_code)
        return add("maintenance", record)

    @router.get("/maintenance")
    def maintenance(after: PageAfter = "", limit: PageLimit = 100,
                    user: dict = Depends(authorise)):
        return list_records("maintenance", after, limit, user)

    @router.patch("/maintenance/{code}/status", dependencies=support_write)
    def update_maintenance(code: str, change: MaintenanceStatus,
                           user: dict = Depends(authorise)):
        return transition("maintenance", code, change.status, user)

    @router.post("/import/deployment-receipts", status_code=201,
                 dependencies=admin_only)
    def import_receipt(envelope: SignedDeploymentReceipt,
                       user: dict = Depends(authorise)):
        require_record(user, "deployment", envelope.receipt.vessel_code)
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
    def receipts(after: PageAfter = "", limit: PageLimit = 100,
                 user: dict = Depends(authorise)):
        return list_records("receipt", after, limit, user)

    @router.get("/audit", dependencies=audit_read)
    def audit(after: AuditAfter = 0, limit: PageLimit = 100,
              user: dict = Depends(authorise)):
        try:
            return catalog.audit(after=after, limit=limit,
                                 allowed_customers=scope(user))
        except FleetIntegrityError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "Fleet store integrity check failed") from exc

    app.include_router(router)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
