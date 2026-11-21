"""Read-only incident views built from allowlisted Wazuh alert fields."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Mapping

from services.intelligence.assets import AssetRegistry
from services.connectors.wazuh import parse_incident_id
from services.knowledge.injection import instruction_like


SOURCES = {"fortigate": "FortiGate", "switch-syslog": "Switch", "host-agent": "Host"}
ACTIONS = {"deny", "login-failed", "detected", "allow", "logout", "login"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_UNSAFE_ANALYSIS = re.compile(
    r"https?://|\b(?:disable|delete|modify|reconfigure|execute|run|curl|wget|"
    r"send|reveal|ignore|override|credential|password|token|api[_-]?key|"
    r"compromised|breached|confirmed)\b|\b\d{1,3}(?:\.\d{1,3}){3}\b",
    re.I,
)


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


def _description(value: object) -> str:
    description = _text(value, limit=160)
    if re.search(r"\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=]", description, re.I):
        raise ValueError("credential-like alert description")
    if re.search(r"\bBearer\s+[A-Za-z0-9._~-]{12,}", description, re.I):
        raise ValueError("credential-like alert description")
    return description


def safe_incident_analysis(text: str) -> bool:
    """Accept only a short, plain, non-actionable model sentence.

    This is a narrow output guard, not a proof that every claim is supported.
    """
    if (not isinstance(text, str) or not text or len(text) > 320 or len(text.split()) > 45
            or any(ord(char) < 32 for char in text) or any(char in text for char in ("*", "`", "<", ">"))
            or not text.rstrip().endswith((".", "!", "?"))):
        return False
    return not instruction_like(text) and not _UNSAFE_ANALYSIS.search(text)


def normalize_alert(hit: Mapping[str, object], registry: AssetRegistry) -> dict[str, object]:
    source = _nested(hit, "source")
    index_name = _text(hit.get("index_name"), limit=93)
    index_id = _text(hit.get("index_id"), limit=80)
    incident_id = f"{index_name}:{index_id}"
    parse_incident_id(incident_id)
    event_id = _text(source.get("id"), limit=80)
    if not _IDENTIFIER.fullmatch(event_id):
        raise ValueError("invalid alert event id")
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
    if decoder == "fortigate":
        source_hostname = data.get("devname")
    elif decoder == "switch-syslog":
        source_hostname = data.get("device_name")
    else:
        source_hostname = agent.get("name") if agent.get("id") != "000" else None
    hostname = _text(source_hostname, limit=80) if source_hostname is not None else None
    ip = data.get("srcip")
    vlan = data.get("vlan")
    if ip is not None:
        ip = _text(ip, limit=45)
    if vlan is not None and (isinstance(vlan, bool) or not isinstance(vlan, int)):
        raise ValueError("invalid vlan")
    asset_match = registry.resolve(hostname=hostname) if hostname else {"status": "unknown", "asset": None}
    # A syslog collector's agent name is not the source device. Use explicit device fields only.
    asset = asset_match["asset"] if asset_match["status"] == "known" else None
    related_match = registry.resolve(ip=ip, vlan=vlan) if ip else {"status": "unknown", "asset": None}
    related = related_match["asset"] if related_match["status"] == "known" else None
    return {
        "incident_id": incident_id, "index_name": index_name, "index_id": index_id,
        "event_id": event_id, "timestamp": moment.isoformat(), "source": SOURCES[decoder],
        "rule_id": _text(rule.get("id"), limit=80),
        "description": _description(rule.get("description")),
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
    limits = ["Limited to one alert; no independent correlation performed."]
    if event["asset_status"] != "known":
        limits.append("Source asset mapping is unresolved; no device identity was inferred.")
    if event["related_asset_status"] == "ambiguous":
        limits.append("Related asset mapping is ambiguous; no related device identity was inferred.")
    return {"incident_id": event["incident_id"], "summary": summary, "event": dict(event),
            "suggested_checks": checks, "confidence": " ".join(limits),
            "evidence": [{"event_id": event["event_id"], "index_name": event["index_name"],
                          "index_id": event["index_id"], "timestamp": event["timestamp"],
                          "rule_id": event["rule_id"], "location": event["location"]}]}


def related_alert_evidence(primary: Mapping[str, object],
                           candidates: list[dict[str, object]]) -> dict[str, object]:
    """Correlate only alerts with the same explicitly resolved source asset."""
    event = primary["event"]
    asset = event["asset"]
    if event["asset_status"] != "known" or not isinstance(asset, dict):
        return {"incident_id": primary["incident_id"], "status": "unresolved-source",
                "related": [], "examined": len(candidates), "limit": 100}
    matches = []
    for item in candidates:
        other = item["event"]
        other_asset = other["asset"]
        if (item["incident_id"] != primary["incident_id"] and
                other["asset_status"] == "known" and isinstance(other_asset, dict) and
                other_asset["asset_id"] == asset["asset_id"]):
            matches.append({"incident_id": item["incident_id"],
                            "summary": item["summary"], "timestamp": other["timestamp"],
                            "severity": other["severity"], "evidence": item["evidence"]})
    matches.sort(key=lambda row: (row["timestamp"], row["incident_id"]), reverse=True)
    return {"incident_id": primary["incident_id"], "status": "observed-same-source",
            "related": matches[:20], "examined": len(candidates), "limit": 100}


def supported_incidents(hits: list[dict[str, object]], registry: AssetRegistry) -> list[dict[str, object]]:
    incidents: list[dict[str, object]] = []
    for hit in hits:
        source = hit.get("source", {})
        decoder = source.get("decoder", {}) if isinstance(source, dict) else {}
        name = decoder.get("name") if isinstance(decoder, dict) else None
        if name not in SOURCES:
            continue
        incidents.append(incident_view(normalize_alert(hit, registry)))
    return incidents


def load_fixture_incidents(path: Path, registry: AssetRegistry) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    hits = payload["hits"]["hits"]
    if not isinstance(hits, list) or len(hits) > 100:
        raise ValueError("invalid alert fixture")
    return [incident_view(normalize_alert({"index_name": hit["_index"],
                                          "index_id": hit["_id"], "source": hit["_source"]}, registry))
            for hit in hits]
