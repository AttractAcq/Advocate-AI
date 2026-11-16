"""Synthetic asset registry with explicit ambiguity instead of guessed joins."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
EQUIPMENT_CLASSES = {"firewall", "network switch", "workstation", "server", "nas",
                     "access point", "camera", "printer", "controller", "other"}


class AssetRegistry:
    def __init__(self, source: Path) -> None:
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != 1 or not isinstance(payload.get("assets"), list):
            raise ValueError("invalid asset registry")
        self.assets: dict[str, dict[str, object]] = {}
        for item in payload["assets"]:
            if not isinstance(item, dict) or not all(isinstance(item.get(key), str) and item[key] for key in
                    ("asset_id", "hostname", "owner", "equipment_class")):
                raise ValueError("invalid asset")
            if (not _IDENTIFIER.fullmatch(item["asset_id"])
                    or not _IDENTIFIER.fullmatch(item["hostname"])
                    or item["equipment_class"] not in EQUIPMENT_CLASSES
                    or len(item["owner"]) > 80
                    or any(ord(char) < 32 for char in item["owner"])):
                raise ValueError("unsafe asset metadata")
            if item["asset_id"] in self.assets:
                raise ValueError("duplicate asset id")
            addresses = item.get("addresses", [])
            if not isinstance(addresses, list):
                raise ValueError("invalid asset addresses")
            for address in addresses:
                if (not isinstance(address, dict) or not isinstance(address.get("ip"), str)
                        or not isinstance(address.get("vlan"), int) or not 1 <= address["vlan"] <= 4094):
                    raise ValueError("invalid asset address")
                ipaddress.ip_address(address["ip"])
            self.assets[item["asset_id"]] = item

    def resolve(self, *, asset_id: str | None = None, hostname: str | None = None,
                ip: str | None = None, vlan: int | None = None) -> dict[str, object]:
        if asset_id:
            asset = self.assets.get(asset_id)
            return {"status": "known", "asset": asset} if asset else {"status": "unknown", "asset": None}
        candidates = list(self.assets.values())
        if hostname:
            candidates = [asset for asset in candidates if asset["hostname"].casefold() == hostname.casefold()]
        if ip:
            try:
                needle = str(ipaddress.ip_address(ip))
            except ValueError:
                return {"status": "unknown", "asset": None}
            candidates = [asset for asset in candidates if any(address["ip"] == needle and
                          (vlan is None or address["vlan"] == vlan) for address in asset["addresses"])]
        if not hostname and not ip:
            return {"status": "unknown", "asset": None}
        if len(candidates) != 1:
            return {"status": "ambiguous" if candidates else "unknown", "asset": None}
        return {"status": "known", "asset": candidates[0]}
