"""Synthetic Phase 2 Core API. Launch on loopback only; never use vessel data."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from apps.api.auth import LabRateLimiter, LabSessions
from apps.api.model import LocalModel, ModelTimeout, ModelUnavailable
from services.knowledge.acl import source_access
from services.knowledge.retrieval import search_fixture_documents

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    fixture_root: Path = ROOT / "fixtures"
    lab_password: str | None = None
    inference_endpoint: str = "http://127.0.0.1:11434/v1"
    model_name: str = "qwen3.5:2b"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            lab_password=os.environ.get("SOVEREIGN_LAB_PASSWORD"),
            inference_endpoint=os.environ.get("SOVEREIGN_MODEL_ENDPOINT", cls.inference_endpoint),
            model_name=os.environ.get("SOVEREIGN_MODEL_NAME", cls.model_name),
        )


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=2000)
    mode: Literal["documents", "general"] = "documents"
    model: str | None = Field(default=None, max_length=100)
    conversation_id: str | None = Field(default=None, max_length=80)
    selected_documents: list[str] = Field(default_factory=list, max_length=5)
    workspace: Literal["management", "engineering", "interior", "deck"] | None = None


def create_app(settings: Settings | None = None, model: LocalModel | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    model = model or LocalModel(settings.inference_endpoint, settings.model_name)
    sessions = LabSessions(settings.fixture_root / "roles.json", settings.lab_password)
    limiter = LabRateLimiter()
    app = FastAPI(title="Sovereign Core synthetic lab", docs_url=None, redoc_url=None)
    app.state.sessions = sessions

    @app.middleware("http")
    async def limit_request_body(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                declared_length = int(request.headers.get("content-length", "0"))
            except ValueError:
                return JSONResponse({"detail": "invalid content length"}, status_code=400)
            if declared_length > 16 * 1024:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
            chunks: list[bytes] = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 16 * 1024:
                    return JSONResponse({"detail": "request body too large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        return await call_next(request)

    def current_identity(authorization: str | None = Header(default=None)) -> tuple[str, dict[str, str]]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        token = authorization[7:]
        user = sessions.user_for(token)
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        return token, user

    def permitted_sources(user_id: str) -> list[dict[str, str]]:
        policy = json.loads((settings.fixture_root / "roles.json").read_text(encoding="utf-8"))
        base = settings.fixture_root.resolve()
        permitted: list[dict[str, str]] = []
        with (settings.fixture_root / "manifest.csv").open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if not source_access(user_id, row, policy):
                    continue
                path = (base / row.get("relative_path", "")).resolve()
                if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > 64 * 1024:
                    continue
                if hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]:
                    permitted.append(row)
        return permitted

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"service": "core", "status": "ok", "mode": "synthetic-only"}

    @app.post("/api/login")
    def login(request: LoginRequest, http_request: Request) -> dict[str, object]:
        if not settings.lab_password or len(settings.lab_password) < 12:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "lab authentication is not configured")
        origin = http_request.client.host if http_request.client else "unknown"
        if not limiter.allow(f"login:{origin}", maximum=15):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many sign-in attempts")
        token = sessions.login(request.user_id, request.password)
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid lab credentials")
        return {"access_token": token, "token_type": "bearer", "expires_in": 1800}

    @app.post("/api/logout")
    def logout(identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, bool]:
        sessions.logout(identity[0])
        return {"ok": True}

    @app.get("/api/me")
    def me(identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, str]:
        user = identity[1]
        return {"id": user["id"], "role": user["role"]}

    @app.get("/api/models")
    def models(_: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, list[str]]:
        return {"models": [settings.model_name]}

    @app.get("/api/tools")
    def tools(_: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, object]:
        return {"read_only": ["synthetic_document_search"], "write": []}

    @app.get("/api/admin/status")
    def admin_status(identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, object]:
        if identity[1]["role"] != "avit_admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin scope required")
        return {"mode": "synthetic-only", "identity": "ephemeral-lab", "model": settings.model_name,
                "read_only_tools": ["synthetic_document_search"], "write_tools": []}

    @app.get("/api/sources")
    def sources(identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, object]:
        permitted = permitted_sources(identity[1]["id"])
        return {"sources": [{"document_id": row["document_id"], "collection": row["collection"],
                             "version": row["version"]} for row in permitted]}

    @app.get("/api/conversations")
    def conversations(identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, list[str]]:
        return {"conversation_ids": sessions.list_conversations(identity[1]["id"])}

    @app.get("/api/conversations/{conversation_id}")
    def conversation(conversation_id: str, identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, object]:
        user_id = identity[1]["id"]
        stored = sessions.conversation(conversation_id, user_id)
        if not stored:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
        allowed_ids = {row["document_id"] for row in permitted_sources(user_id)}
        turns = []
        for turn in stored.turns:
            citations = turn.get("citations", [])
            if any(item["document_id"] not in allowed_ids for item in citations):
                turns.append({"message": "[Source access changed]", "answer": "Answer hidden after source access changed.",
                              "citations": [], "mode": "redacted"})
            else:
                turns.append(turn)
        return {"conversation_id": conversation_id, "turns": turns}

    @app.post("/api/chat")
    async def chat(request: ChatRequest, identity: tuple[str, dict[str, str]] = Depends(current_identity)) -> dict[str, object]:
        user_id = identity[1]["id"]
        if not limiter.allow(f"chat:{identity[0]}", maximum=30):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "chat rate limit reached")
        if request.model and request.model != settings.model_name:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "model is not available")
        if not request.message.strip():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "message is empty")
        if request.conversation_id:
            conversation_id = request.conversation_id
            stored = sessions.conversation(conversation_id, user_id)
            if not stored:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
        else:
            try:
                conversation_id, stored = sessions.create_conversation(user_id)
            except OverflowError as exc:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
        if len(stored.turns) >= 20:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "conversation limit reached")

        context: list[dict[str, object]] = []
        if request.mode == "documents":
            try:
                context = search_fixture_documents(
                    settings.fixture_root, user_id, request.message, limit=5,
                    document_ids=set(request.selected_documents) if request.selected_documents else None,
                    collections={request.workspace} if request.workspace else None,
                )
            except ValueError as exc:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        if request.mode == "documents" and not context:
            answer = "No matching permitted source was found. I cannot answer from vessel documents."
        else:
            try:
                answer = await model.complete(request.message, context, general=request.mode == "general")
            except ModelTimeout as exc:
                raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, str(exc)) from exc
            except ModelUnavailable as exc:
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        citations = [{"document_id": item["document_id"], "version": item["version"],
                      "collection": item["collection"], "sha256": item["sha256"]} for item in context]
        turn = {"message": request.message, "answer": answer, "citations": citations,
                "mode": request.mode, "workspace": request.workspace}
        sessions.add_turn(conversation_id, user_id, turn)
        return {"conversation_id": conversation_id, **turn, "model": settings.model_name,
                "tool_route": "synthetic_document_search" if request.mode == "documents" else "none"}

    return app


app = create_app()
