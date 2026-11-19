"""Ephemeral credentials for the synthetic Phase 2 lab only.

The vessel product will use the approved local identity provider. Lab tokens
do not survive a Core restart; optional SQLite conversation history can.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
import json
import os
from pathlib import Path
import secrets
import sqlite3
from threading import RLock
import time

from services.policy.policy_file import PolicyUnavailable, load_policy


@dataclass
class Conversation:
    owner: str
    turns: list[dict[str, object]] = field(default_factory=list)


@dataclass
class LoginSession:
    user_id: str
    expires_at: float


class LabSessions:
    def __init__(self, roles_path: Path, password: str | None,
                 history_db: Path | None = None) -> None:
        self.roles_path = roles_path
        self.password = password
        self.history_db = history_db
        self._tokens: dict[str, LoginSession] = {}
        self._conversations: dict[str, Conversation] = {}
        self._lock = RLock()
        if history_db is not None:
            history_db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(history_db, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
            with self._history() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL
                )""")
                db.execute("CREATE INDEX IF NOT EXISTS conversations_owner ON conversations(owner)")

    def _history(self) -> sqlite3.Connection:
        if self.history_db is None:
            raise RuntimeError("persistent history unavailable")
        return sqlite3.connect(self.history_db.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)

    def _active_user(self, user_id: str) -> dict[str, str] | None:
        try:
            policy = load_policy(self.roles_path)
        except PolicyUnavailable:
            return None
        if not isinstance(policy, dict) or not isinstance(policy.get("users"), list):
            return None
        return next((user for user in policy["users"] if isinstance(user, dict)
                     and user.get("id") == user_id and user.get("status") == "active"), None)

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
            if self.history_db is not None:
                with self._history() as db:
                    row = db.execute("SELECT turns_json FROM conversations WHERE id=? AND owner=?",
                                     (conversation_id, owner)).fetchone()
                return Conversation(owner, json.loads(row[0])) if row else None
            conversation = self._conversations.get(conversation_id)
            return conversation if conversation and conversation.owner == owner else None

    def create_conversation(self, owner: str) -> tuple[str, Conversation]:
        with self._lock:
            if self.history_db is not None:
                with self._history() as db:
                    db.execute("BEGIN IMMEDIATE")
                    count = db.execute("SELECT COUNT(*) FROM conversations WHERE owner=?", (owner,)).fetchone()[0]
                    if count >= 50:
                        raise OverflowError("conversation limit reached")
                    conversation_id = secrets.token_urlsafe(18)
                    db.execute("INSERT INTO conversations VALUES (?,?,?)", (conversation_id, owner, "[]"))
                return conversation_id, Conversation(owner)
            if sum(item.owner == owner for item in self._conversations.values()) >= 50:
                raise OverflowError("conversation limit reached")
            conversation_id = secrets.token_urlsafe(18)
            conversation = Conversation(owner)
            self._conversations[conversation_id] = conversation
        return conversation_id, conversation

    def add_turn(self, conversation_id: str, owner: str, turn: dict[str, object]) -> None:
        with self._lock:
            if self.history_db is not None:
                with self._history() as db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute("SELECT turns_json FROM conversations WHERE id=? AND owner=?",
                                     (conversation_id, owner)).fetchone()
                    if row is None:
                        raise KeyError("conversation not found")
                    turns = json.loads(row[0])
                    if len(turns) >= 20:
                        raise OverflowError("conversation limit reached")
                    turns.append(turn)
                    db.execute("UPDATE conversations SET turns_json=? WHERE id=? AND owner=?",
                               (json.dumps(turns), conversation_id, owner))
                return
            conversation = self._conversations.get(conversation_id)
            if not conversation or conversation.owner != owner:
                raise KeyError("conversation not found")
            if len(conversation.turns) >= 20:
                raise OverflowError("conversation limit reached")
            conversation.turns.append(turn)

    def list_conversations(self, owner: str) -> list[str]:
        with self._lock:
            if self.history_db is not None:
                with self._history() as db:
                    return [row[0] for row in db.execute(
                        "SELECT id FROM conversations WHERE owner=? ORDER BY rowid", (owner,))]
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
