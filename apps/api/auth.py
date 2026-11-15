"""Ephemeral credentials for the synthetic Phase 2 lab only.

The vessel product will use the approved local identity provider. No lab token
or conversation survives a Core restart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
import json
from pathlib import Path
import secrets
from threading import RLock
import time


@dataclass
class Conversation:
    owner: str
    turns: list[dict[str, object]] = field(default_factory=list)


@dataclass
class LoginSession:
    user_id: str
    expires_at: float


class LabSessions:
    def __init__(self, roles_path: Path, password: str | None) -> None:
        self.roles_path = roles_path
        self.password = password
        self._tokens: dict[str, LoginSession] = {}
        self._conversations: dict[str, Conversation] = {}
        self._lock = RLock()

    def _active_user(self, user_id: str) -> dict[str, str] | None:
        policy = json.loads(self.roles_path.read_text(encoding="utf-8"))
        return next((user for user in policy.get("users", [])
                     if user.get("id") == user_id and user.get("status") == "active"), None)

    def login(self, user_id: str, password: str) -> str | None:
        if not self.password or len(self.password) < 12:
            return None
        if not secrets.compare_digest(password, self.password) or not self._active_user(user_id):
            return None
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = LoginSession(user_id, time.time() + 1800)
        return token

    def user_for(self, token: str) -> dict[str, str] | None:
        with self._lock:
            session = self._tokens.get(token)
            if not session or session.expires_at <= time.time():
                self._tokens.pop(token, None)
                return None
        user = self._active_user(session.user_id)
        if not user:
            self.logout(token)
        return user

    def logout(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)

    def conversation(self, conversation_id: str, owner: str) -> Conversation | None:
        with self._lock:
            conversation = self._conversations.get(conversation_id)
            return conversation if conversation and conversation.owner == owner else None

    def create_conversation(self, owner: str) -> tuple[str, Conversation]:
        with self._lock:
            if sum(item.owner == owner for item in self._conversations.values()) >= 50:
                raise OverflowError("conversation limit reached")
            conversation_id = secrets.token_urlsafe(18)
            conversation = Conversation(owner)
            self._conversations[conversation_id] = conversation
        return conversation_id, conversation

    def add_turn(self, conversation_id: str, owner: str, turn: dict[str, object]) -> None:
        with self._lock:
            conversation = self._conversations.get(conversation_id)
            if not conversation or conversation.owner != owner:
                raise KeyError("conversation not found")
            if len(conversation.turns) >= 20:
                raise OverflowError("conversation limit reached")
            conversation.turns.append(turn)

    def list_conversations(self, owner: str) -> list[str]:
        with self._lock:
            return [key for key, item in self._conversations.items() if item.owner == owner]


class LabRateLimiter:
    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = {}
        self._lock = RLock()

    def allow(self, key: str, *, maximum: int, window_seconds: float = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            calls = self._calls.setdefault(key, deque())
            while calls and calls[0] <= now - window_seconds:
                calls.popleft()
            if len(calls) >= maximum:
                return False
            calls.append(now)
            return True
