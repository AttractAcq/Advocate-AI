"""Bound Fleet request bodies before JSON parsing or model validation."""

from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse


MAX_BODY_BYTES = 16 * 1024


class FleetBodyLimit:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        async def reject() -> None:
            response = JSONResponse({"detail": "Fleet request body exceeds 16 KiB"},
                                    status_code=413)
            await response(scope, receive, send)

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    if int(value) > MAX_BODY_BYTES:
                        await reject()
                        return
                except ValueError:
                    pass

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                await reject()
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
