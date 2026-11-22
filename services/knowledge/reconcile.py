"""Schedule manifest-triggered and periodic local index reconciliation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import time
from typing import Callable

from services.knowledge.ingestion import sync_manifest
from services.knowledge.manifest_io import read_manifest_bytes


class ManifestReconciler:
    def __init__(self, root: Path, manifest: Path, database: Path | str, *,
                 full_scan_seconds: int = 600,
                 sync: Callable[[Path, Path, Path | str], dict[str, object]] = sync_manifest) -> None:
        if not 60 <= full_scan_seconds <= 3600:
            raise ValueError("full scan interval must be 60–3600 seconds")
        self.root = root
        self.manifest = manifest
        self.database = database
        self.full_scan_seconds = full_scan_seconds
        self.sync = sync
        self._last_digest: str | None = None
        self._last_scan: float | None = None

    def poll(self, *, now: float | None = None) -> dict[str, object] | None:
        """Reconcile after a manifest change or a bounded full-scan interval."""
        when = time.monotonic() if now is None else now
        try:
            digest = hashlib.sha256(read_manifest_bytes(self.manifest)).hexdigest()
            if (self._last_scan is not None and digest == self._last_digest and
                    when - self._last_scan < self.full_scan_seconds):
                return None
            result = self.sync(self.root, self.manifest, self.database)
        except Exception:
            self._last_digest = None
            self._last_scan = None
            raise
        self._last_digest = digest
        self._last_scan = when
        return result
