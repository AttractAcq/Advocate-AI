from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.deploy.container_runtime import (
    RuntimeError, _archive_image_ids, _validate_console_config, start_verified_bundle,
)
from infrastructure.release.bundle import BundleError


class ContainerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / "console-config.json"
        self.config.write_text('{"schema":1,"oidc_issuer":null}')

    def test_only_synthetic_config_is_accepted(self) -> None:
        _validate_console_config(self.config)
        for raw in ('{"schema":1,"schema":1,"oidc_issuer":null}',
                    '{"schema":1,"oidc_issuer":"https://id.example/realm"}',
                    '[]', '{"schema":true,"oidc_issuer":null}'):
            with self.subTest(raw=raw):
                self.config.write_text(raw)
                with self.assertRaises(RuntimeError):
                    _validate_console_config(self.config)

    def test_legacy_docker_archive_is_bound_to_config_hash(self) -> None:
        config = b'{"architecture":"amd64","os":"linux"}'
        digest = hashlib.sha256(config).hexdigest()
        archive = self.root / "core.tar"

        def make_archive(data: bytes) -> None:
            with tarfile.open(archive, "w") as stream:
                manifest = json.dumps([{"Config": digest + ".json",
                                        "RepoTags": ["sovereign-core:synthetic"],
                                        "Layers": []}]).encode()
                for name, body in (("manifest.json", manifest), (digest + ".json", data)):
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    stream.addfile(info, io.BytesIO(body))

        make_archive(config)
        self.assertEqual(_archive_image_ids(archive, "core"), {"sha256:" + digest})
        make_archive(b"tampered")
        with self.assertRaises(RuntimeError):
            _archive_image_ids(archive, "core")

    def test_non_product_bundle_never_reaches_docker(self) -> None:
        with patch("infrastructure.deploy.container_runtime.verify_bundle",
                   return_value={"schema": 3}), \
             patch("infrastructure.deploy.container_runtime._docker") as docker:
            with self.assertRaises(BundleError):
                start_verified_bundle(self.root / "bundle", self.root / "trusted.pem",
                                      self.root / "crane", self.config)
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
