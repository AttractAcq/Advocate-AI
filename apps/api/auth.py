"""Ephemeral credentials for the synthetic Phase 2 lab only.

The vessel product will use the approved local identity provider. Lab tokens
do not survive a Core restart; optional SQLite conversation history can.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from threading import RLock
import time

from services.policy.policy_file import PolicyUnavailable, active_user, load_policy


CORE_STATE_SCHEMA_VERSION = 1


def _history_shape(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
        raise ValueError("conversation database integrity failed")
    columns = [(row[1], row[2].upper(), row[3], row[5])
               for row in db.execute("PRAGMA table_info(conversations)")]
    if columns != [("id", "TEXT", 0, 1), ("owner", "TEXT", 1, 0),
                   ("turns_json", "TEXT", 1, 0)]:
        raise ValueError("unsupported conversation database shape")
    index = db.execute("PRAGMA index_info(conversations_owner)").fetchall()
    if [(row[1], row[2]) for row in index] != [(1, "owner")]:
        raise ValueError("conversation owner index unavailable")


def verify_history_format(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone() != (CORE_STATE_SCHEMA_VERSION,):
        raise ValueError("unsupported Core history schema version")
    _history_shape(db)


def migrate_legacy_history(path: Path) -> int:
    """Explicitly ledger the old history shape after an offline backup."""
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("invalid legacy conversation database")
    details = path.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise ValueError("unsafe legacy conversation database")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)) as db:
        with db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("PRAGMA user_version").fetchone() != (0,):
                raise ValueError("legacy conversation database is already versioned")
            _history_shape(db)
            count = 0
            for identifier, owner, raw in db.execute("SELECT id,owner,turns_json FROM conversations"):
                if (not isinstance(identifier, str) or not 1 <= len(identifier) <= 80
                        or not isinstance(owner, str) or not 1 <= len(owner) <= 200):
                    raise ValueError("invalid legacy conversation identity")
                turns = json.loads(raw)
                if not isinstance(turns, list) or len(turns) > 20 or any(
                        not isinstance(turn, dict) for turn in turns):
                    raise ValueError("invalid legacy conversation turns")
                count += 1
            db.execute(f"PRAGMA user_version={CORE_STATE_SCHEMA_VERSION}")
            return count


@dataclass
class Conversation:
    owner: str
    turns: list[dict[str, object]] = field(default_factory=list)


@dataclass
class LoginSession:
    user_id: str
    role: str
    expires_at: float
    credential_hash: str | None = None


class LabSessions:
    def __init__(self, roles_path: Path, password: str | None,
                 history_db: Path | None = None,
                 emergency_password_file: Path | None = None) -> None:
        self.roles_path = roles_path
        self.password = password
        self.history_db = history_db
        self.emergency_password_file = emergency_password_file
        self._tokens: dict[str, LoginSession] = {}
        self._conversations: dict[str, Conversation] = {}
        self._lock = RLock()
        if history_db is not None:
            history_db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                descriptor = os.open(history_db, flags | os.O_CREAT | os.O_EXCL, 0o600)
                fresh = True
            except FileExistsError:
                descriptor = os.open(history_db, flags)
                fresh = False
            try:
                details = os.fstat(descriptor)
                if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
                        or stat.S_IMODE(details.st_mode) & 0o077):
                    raise ValueError("unsafe conversation database")
            finally:
                os.close(descriptor)
            with closing(self._history()) as db, db:
                if fresh:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("""CREATE TABLE conversations (
                        id TEXT PRIMARY KEY, owner TEXT NOT NULL, turns_json TEXT NOT NULL
                    )""")
                    db.execute("CREATE INDEX conversations_owner ON conversations(owner)")
                    db.execute(f"PRAGMA user_version={CORE_STATE_SCHEMA_VERSION}")
                verify_history_format(db)

    def _history(self) -> sqlite3.Connection:
        if self.history_db is None:
            raise RuntimeError("persistent history unavailable")
        return sqlite3.connect(self.history_db.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)

    def _active_user(self, user_id: str) -> dict[str, object] | None:
        try:
            policy = load_policy(self.roles_path)
        except PolicyUnavailable:
            return None
        return active_user(policy, user_id)

    def _emergency_secret(self) -> tuple[str, str] | None:
        if self.emergency_password_file is None:
            return None
        try:
            descriptor = os.open(self.emergency_password_file,
                                 os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as stream:
                details = os.fstat(stream.fileno())
                if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                        stat.S_IMODE(details.st_mode) & 0o077 or details.st_size > 4096):
                    return None
                raw = stream.read(4097)
            if len(raw) > 4096:
                return None
            value = raw.decode("utf-8").rstrip("\n")
            if not 16 <= len(value) <= 200 or "\n" in value or "\r" in value:
                return None
            return value, hashlib.sha256(raw).hexdigest()
        except (OSError, UnicodeError, ValueError):
            return None

    def login(self, user_id: str, password: str) -> str | None:
        user = self._active_user(user_id)
        if user is None:
            return None
        credential_hash: str | None = None
        if user["role"] == "emergency_recovery":
            emergency = self._emergency_secret()
            if emergency is None or (self.password and secrets.compare_digest(emergency[0], self.password)):
                return None
            if not secrets.compare_digest(password, emergency[0]):
                return None
            credential_hash = emergency[1]
        elif (not self.password or len(self.password) < 12 or
              not secrets.compare_digest(password, self.password)):
            return None
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = LoginSession(user_id, str(user["role"]), time.time() + 1800,
                                               credential_hash)
        return token

    def user_for(self, token: str) -> dict[str, str] | None:
        with self._lock:
            session = self._tokens.get(token)
            if not session or session.expires_at <= time.time():
                self._tokens.pop(token, None)
                return None
        user = self._active_user(session.user_id)
        if not user or user["role"] != session.role:
            self.logout(token)
            return None
        if session.role == "emergency_recovery":
            emergency = self._emergency_secret()
            if emergency is None or emergency[1] != session.credential_hash:
                self.logout(token)
                return None
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
