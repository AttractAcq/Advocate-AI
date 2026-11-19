"""Local Keycloak access-token validation for the Phase 3 lab."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
import time
from urllib.parse import urlsplit

import httpx
import jwt

from services.policy.policy_file import active_user, load_policy


class OidcVerifier:
    def __init__(self, issuer: str, roles_path: Path, audience: str = "sovereign-core",
                 *, transport: httpx.BaseTransport | None = None,
                 revocations_path: Path | None = None,
                 authorized_client: str = "sovereign-console",
                 allow_https_issuer: bool = False,
                 ca_file: Path | None = None) -> None:
        parsed = urlsplit(issuer)
        realm = re.fullmatch(r"/realms/[A-Za-z0-9_-]{1,80}", parsed.path)
        if (not realm or parsed.query or parsed.fragment or parsed.username or
                parsed.password or issuer.endswith("/")):
            raise ValueError("OIDC issuer must identify one Keycloak realm")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid OIDC issuer port") from exc
        if ca_file is not None and parsed.scheme != "https":
            raise ValueError("custom OIDC CA requires an HTTPS issuer")
        if parsed.scheme == "https" and allow_https_issuer:
            hostname = parsed.hostname or ""
            labels = hostname.split(".")
            if (port is not None or len(labels) < 2 or len(hostname) > 253 or
                    hostname.replace(".", "").isdigit() or
                    any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in labels) or
                    parsed.netloc != hostname):
                raise ValueError("Fleet HTTPS issuer must use a DNS host on port 443")
        else:
            try:
                address = ipaddress.ip_address(parsed.hostname or "")
            except ValueError as exc:
                raise ValueError("OIDC issuer must use numeric loopback in lab") from exc
            host = f"[{address}]" if address.version == 6 else str(address)
            if (parsed.scheme != "http" or not address.is_loopback or not port or
                    parsed.netloc != f"{host}:{port}"):
                raise ValueError("OIDC issuer must be local Keycloak realm")
        self.issuer = issuer.rstrip("/")
        self.roles_path = roles_path
        self.audience = audience
        self.authorized_client = authorized_client
        self.transport = transport
        self.ca_file = ca_file
        self._keys: dict[str, object] = {}
        self._expires = 0.0
        self._last_refresh_attempt = float("-inf")
        self._last_unknown_refresh = float("-inf")
        self.revocations_path = revocations_path
        self._revoked_in_memory: set[str] = set()
        self._lock = RLock()
        self._key_lock = RLock()

    def revoke(self, token: str) -> None:
        """Reject a logged-out access token immediately, including after restart."""
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            if self.revocations_path is None:
                self._revoked_in_memory.add(digest)
                return
            self.revocations_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self.revocations_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, (json.dumps({"sha256": digest}) + "\n").encode())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _is_revoked(self, token: str) -> bool:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            if digest in self._revoked_in_memory:
                return True
            if self.revocations_path is None or not self.revocations_path.exists():
                return False
            try:
                with self.revocations_path.open(encoding="utf-8") as stream:
                    for line in stream:
                        item = json.loads(line)
                        if not isinstance(item, dict) or not isinstance(item.get("sha256"), str):
                            return True
                        if item["sha256"] == digest:
                            return True
            except (OSError, ValueError, json.JSONDecodeError):
                return True
        return False

    def _key(self, kid: str):
        if not 0 < len(kid) <= 256:
            return None
        with self._key_lock:
            now = time.monotonic()
            cached = self._keys.get(kid)
            if cached is not None and now < self._expires:
                return cached
            if now < self._expires:
                # The first new signing key is fetched immediately during a
                # rollover. Repeated unknown key IDs cannot force a JWKS
                # request on every unauthenticated API call.
                if now - self._last_unknown_refresh < 2:
                    return None
                self._last_unknown_refresh = now
            elif now - self._last_refresh_attempt < 2:
                return None
            self._last_refresh_attempt = now
            with httpx.Client(timeout=5, trust_env=False, transport=self.transport,
                              verify=str(self.ca_file) if self.ca_file else True) as client:
                with client.stream("GET", f"{self.issuer}/protocol/openid-connect/certs") as response:
                    response.raise_for_status()
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > 256 * 1024:
                            raise ValueError("OIDC key set is too large")
                        body.extend(chunk)
            keys = json.loads(body)["keys"]
            if not isinstance(keys, list) or len(keys) > 64 or any(
                    not isinstance(item, dict) for item in keys):
                raise ValueError("invalid OIDC key set")
            self._keys = {item["kid"]: jwt.PyJWK.from_dict(item).key for item in keys
                          if item.get("kty") == "RSA" and item.get("alg") == "RS256"
                          and isinstance(item.get("kid"), str)}
            self._expires = time.monotonic() + 300
            return self._keys.get(kid)

    def user_for(self, token: str) -> dict[str, str] | None:
        if self._is_revoked(token):
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                return None
            key = self._key(header["kid"])
            if key is None:
                return None
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.audience, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            if claims.get("azp") != self.authorized_client or claims.get("typ") != "Bearer":
                return None
            username = claims.get("preferred_username")
            if not isinstance(username, str):
                return None
            policy = load_policy(self.roles_path)
            user = active_user(policy, username)
            roles = claims.get("realm_access", {}).get("roles", [])
            if user is None or not isinstance(roles, list) or user.get("role") not in roles:
                return None
            return user
        except (jwt.PyJWTError, ValueError, KeyError, TypeError, httpx.HTTPError, OSError):
            return None
