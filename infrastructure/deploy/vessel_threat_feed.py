"""Pin separately controlled offline threat-feed inputs in vessel records."""

from __future__ import annotations

import hashlib
from pathlib import Path

from infrastructure.deploy.vessel_runtime import ThreatFeedMount, VesselRuntimeError, _feed_options


_FIELDS = {"store", "trusted_key", "store_device", "store_inode",
           "key_device", "key_inode", "key_sha256"}


def feed_record(feed: ThreatFeedMount, state: Path, root: Path) -> dict[str, object]:
    """Validate a site-owned feed and bind its stable host paths and key."""
    _feed_options(feed, state, root)
    store = feed.store.stat()
    key = feed.trusted_key.stat()
    return {"store": str(feed.store.resolve()),
            "trusted_key": str(feed.trusted_key.resolve()),
            "store_device": store.st_dev, "store_inode": store.st_ino,
            "key_device": key.st_dev, "key_inode": key.st_ino,
            "key_sha256": hashlib.sha256(feed.trusted_key.read_bytes()).hexdigest()}


def feed_from_record(value: object, state: Path, root: Path) -> ThreatFeedMount:
    if (not isinstance(value, dict) or set(value) != _FIELDS or
            any(type(value[name]) is not int or value[name] < 0
                for name in ("store_device", "store_inode", "key_device", "key_inode")) or
            any(not isinstance(value[name], str) for name in
                ("store", "trusted_key", "key_sha256")) or
            len(value["key_sha256"]) != 64 or
            any(character not in "0123456789abcdef" for character in value["key_sha256"])):
        raise VesselRuntimeError("invalid vessel threat feed record")
    feed = ThreatFeedMount(Path(value["store"]), Path(value["trusted_key"]))
    if (str(feed.store.resolve()) != value["store"] or
            str(feed.trusted_key.resolve()) != value["trusted_key"]):
        raise VesselRuntimeError("vessel threat feed path changed")
    current = feed_record(feed, state, root)
    if current != value:
        raise VesselRuntimeError("vessel threat feed identity changed")
    return feed
