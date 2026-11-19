"""Bounded, regular-file intake for the approved source manifest."""

from __future__ import annotations

import os
from pathlib import Path
import stat

MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def read_manifest_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK |
                         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("approved manifest must be a regular file")
        payload = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ValueError("approved manifest exceeds size limit")
    return payload
