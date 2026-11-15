"""Local Keycloak access-token validation for the Phase 3 lab."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

import httpx
import jwt


class OidcVerifier:
    def __init__(self, issuer: str, roles_path: Path, audience: str = "sovereign-core",
                 *, transport: httpx.BaseTransport | None = None) -> None:
        parsed = urlsplit(issuer)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("OIDC issuer must use numeric loopback in lab") from exc
        if (parsed.scheme != "http" or not address.is_loopback or not parsed.port or
                not parsed.path.startswith("/realms/") or parsed.query or parsed.fragment or
                parsed.username or parsed.password):
            raise ValueError("OIDC issuer must be local Keycloak realm")
        self.issuer = issuer.rstrip("/")
        self.roles_path = roles_path
        self.audience = audience
        self.transport = transport
        self._keys: dict[str, object] = {}
        self._expires = 0.0

    def _key(self, kid: str):
        if time.monotonic() > self._expires or kid not in self._keys:
            with httpx.Client(timeout=5, trust_env=False, transport=self.transport) as client:
                response = client.get(f"{self.issuer}/protocol/openid-connect/certs")
                response.raise_for_status()
                keys = response.json()["keys"]
            self._keys = {item["kid"]: jwt.PyJWK.from_dict(item).key for item in keys
                          if item.get("kty") == "RSA" and item.get("alg") == "RS256"}
            self._expires = time.monotonic() + 300
        return self._keys.get(kid)

    def user_for(self, token: str) -> dict[str, str] | None:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                return None
            key = self._key(header["kid"])
            if key is None:
                return None
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.audience, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            if claims.get("azp") != "sovereign-console" or claims.get("typ") != "Bearer":
                return None
            username = claims.get("preferred_username")
            if not isinstance(username, str):
                return None
            policy = json.loads(self.roles_path.read_text(encoding="utf-8"))
            user = next((item for item in policy.get("users", []) if isinstance(item, dict)
                         and item.get("id") == username and item.get("status") == "active"), None)
            roles = claims.get("realm_access", {}).get("roles", [])
            if user is None or not isinstance(roles, list) or user.get("role") not in roles:
                return None
            return user
        except (jwt.PyJWTError, ValueError, KeyError, TypeError, httpx.HTTPError, OSError):
            return None
