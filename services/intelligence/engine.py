"""Read-only incident views built from allowlisted Wazuh alert fields."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Mapping

from services.intelligence.assets import AssetRegistry


SOURCES = {"fortigate": "FortiGate", "switch-syslog": "Switch", "host-agent": "Host"}
ACTIONS = {"deny", "login-failed", "detected", "allow", "logout", "login"}


def _text(value: object, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError("invalid alert field")
    if any(ord(char) < 32 for char in value):
        raise ValueError("invalid alert field")
    return value


def _nested(source: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = source.get(key)
    if not isinstance(value, dict):
        raise ValueError("invalid alert field")
    return value


def normalize_alert(hit: Mapping[str, object], registry: AssetRegistry) -> dict[str, object]:
    source = _nested(hit, "source")
    index_id = _text(hit.get("index_id"), limit=80)
    event_id = _text(source.get("id"), limit=80)
    if index_id != event_id:
        raise ValueError("alert id mismatch")
    timestamp = _text(source.get("timestamp"), limit=40)
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid alert timestamp") from exc
    if moment.utcoffset() is None:
        raise ValueError("alert timestamp needs timezone")
    rule = _nested(source, "rule")
    decoder = _text(_nested(source, "decoder").get("name"), limit=40)
    if decoder not in SOURCES:
        raise ValueError("unsupported alert source")
    agent = _nested(source, "agent")
    data = _nested(source, "data")
    level = rule.get("level")
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 15:
        raise ValueError("invalid alert level")
    action = _text(data.get("action"), limit=40)
    if action not in ACTIONS:
        raise ValueError("unsupported action")
    hostname = _text(agent.get("name"), limit=80)
    ip = data.get("srcip")
    vlan = data.get("vlan")
    if ip is not None:
        ip = _text(ip, limit=45)
    if vlan is not None and (isinstance(vlan, bool) or not isinstance(vlan, int)):
        raise ValueError("invalid vlan")
    asset_match = registry.resolve(hostname=hostname)
    # The source device is identified by agent hostname. Event source IP may be a different device.
    asset = asset_match["asset"] if asset_match["status"] == "known" else None
    related_match = registry.resolve(ip=ip, vlan=vlan) if ip else {"status": "unknown", "asset": None}
    related = related_match["asset"] if related_match["status"] == "known" else None
    return {
        "event_id": event_id, "timestamp": moment.isoformat(), "source": SOURCES[decoder],
        "rule_id": _text(rule.get("id"), limit=80),
        "description": _text(rule.get("description"), limit=160),
        "severity": "critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 5 else "low",
        "action": action, "location": _text(source.get("location"), limit=80),
        "asset": {key: asset[key] for key in ("asset_id", "hostname", "owner", "equipment_class")} if asset else None,
        "asset_status": asset_match["status"],
        "related_asset": {key: related[key] for key in ("asset_id", "hostname", "owner", "equipment_class")} if related else None,
        "related_asset_status": related_match["status"],
        "read_only": True,
    }


def incident_view(event: Mapping[str, object]) -> dict[str, object]:
    asset = event["asset"]
    asset_label = asset["hostname"] if isinstance(asset, dict) else "unmapped source"
    summary = f"{event['source']} reported {event['description']} on {asset_label} at {event['timestamp']}."
    checks = ["Verify the cited event in the independent alert store.",
              "Compare the timestamp and asset mapping with approved records.",
              "Escalate to the AV/IT officer if the finding remains unexplained."]
    return {"incident_id": event["event_id"], "summary": summary, "event": dict(event),
            "suggested_checks": checks, "confidence": "Limited to one synthetic alert; no independent correlation performed.",
            "evidence": [{"event_id": event["event_id"], "timestamp": event["timestamp"],
                          "rule_id": event["rule_id"], "location": event["location"]}]}


def load_fixture_incidents(path: Path, registry: AssetRegistry) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    hits = payload["hits"]["hits"]
    if not isinstance(hits, list) or len(hits) > 100:
        raise ValueError("invalid alert fixture")
    return [incident_view(normalize_alert({"index_id": hit["_id"], "source": hit["_source"]}, registry))
            for hit in hits]
