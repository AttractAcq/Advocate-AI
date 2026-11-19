"""Read a bounded regular file without following a final symlink."""

from __future__ import annotations

import os
from pathlib import Path
import stat


def read_regular_file(path: Path, max_bytes: int) -> bytes:
    if max_bytes < 1:
        raise ValueError("file size limit must be positive")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK |
                         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("configuration must be a regular file")
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("configuration exceeds size limit")
    return payload
