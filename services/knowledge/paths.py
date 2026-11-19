"""Read allowlisted local documents without following source symlinks."""

from __future__ import annotations

import os
from pathlib import Path
import stat


def _source_parts(relative: str) -> tuple[str, ...]:
    if (not isinstance(relative, str) or not relative or "\\" in relative
            or Path(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("invalid source path")
    return tuple(relative.split("/"))


def read_source_bytes(root: Path, relative: str, max_bytes: int) -> bytes:
    """Read one bounded source through directory descriptors without following links."""
    if max_bytes < 1:
        raise ValueError("source size limit must be positive")
    parts = _source_parts(relative)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                                  os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
        with os.fdopen(file_descriptor, "rb") as stream:
            details = os.fstat(stream.fileno())
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("source must be a regular file")
            if details.st_size > max_bytes:
                raise ValueError("source exceeds size limit")
            payload = stream.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("source exceeds size limit")
        return payload
    finally:
        os.close(descriptor)
