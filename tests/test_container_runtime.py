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
    RuntimeError, RuntimeHandle, _archive_image_ids, _validate_console_config,
    probe_runtime, start_verified_bundle, switch_verified_bundle,
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

    def test_nested_oci_index_selects_matching_docker_configuration(self) -> None:
        config = b'{"architecture":"amd64","os":"linux"}'
        config_hash = hashlib.sha256(config).hexdigest()

        def encoded(value: object) -> bytes:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

        image_manifest = encoded({"schemaVersion": 2,
                                  "config": {"digest": "sha256:" + config_hash}})
        image_hash = hashlib.sha256(image_manifest).hexdigest()
        nested = encoded({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + image_hash}]})
        nested_hash = hashlib.sha256(nested).hexdigest()
        index = encoded({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + nested_hash}]})
        docker_manifest = encoded([{"Config": "blobs/sha256/" + config_hash,
                                    "RepoTags": ["sovereign-console:synthetic"], "Layers": []}])
        archive = self.root / "console.tar"
        with tarfile.open(archive, "w") as stream:
            for name, body in (("manifest.json", docker_manifest), ("index.json", index),
                               ("blobs/sha256/" + config_hash, config),
                               ("blobs/sha256/" + image_hash, image_manifest),
                               ("blobs/sha256/" + nested_hash, nested)):
                info = tarfile.TarInfo(name)
                info.size = len(body)
                stream.addfile(info, io.BytesIO(body))
        self.assertIn("sha256:" + image_hash, _archive_image_ids(archive, "console"))

    def test_non_product_bundle_never_reaches_docker(self) -> None:
        with patch("infrastructure.deploy.container_runtime.verify_bundle",
                   return_value={"schema": 3}), \
             patch("infrastructure.deploy.container_runtime._docker") as docker:
            with self.assertRaises(BundleError):
                start_verified_bundle(self.root / "bundle", self.root / "trusted.pem",
                                      self.root / "crane", self.config)
            docker.assert_not_called()

    def test_failed_candidate_preserves_previous_runtime(self) -> None:
        previous = RuntimeHandle("network-old", "core-old", "console-old")
        with patch("infrastructure.deploy.container_runtime.probe_runtime") as probe, \
             patch("infrastructure.deploy.container_runtime.start_verified_bundle",
                   side_effect=BundleError("bad signature")), \
             patch("infrastructure.deploy.container_runtime.stop_runtime") as stop:
            with self.assertRaises(BundleError):
                switch_verified_bundle(previous, self.root, self.root / "key",
                                       self.root / "crane", self.config)
            probe.assert_called_once_with(previous)
            stop.assert_not_called()

    def test_healthy_candidate_retires_previous_runtime(self) -> None:
        previous = RuntimeHandle("network-old", "core-old", "console-old")
        candidate = RuntimeHandle("network-new", "core-new", "console-new")
        with patch("infrastructure.deploy.container_runtime.probe_runtime") as probe, \
             patch("infrastructure.deploy.container_runtime.start_verified_bundle",
                   return_value=candidate), \
             patch("infrastructure.deploy.container_runtime.stop_runtime") as stop:
            result = switch_verified_bundle(previous, self.root,
                                            self.root / "key", self.root / "crane", self.config)
            self.assertEqual(result, candidate)
            probe.assert_called_once_with(previous)
            stop.assert_called_once_with(previous)

    def test_persisted_runtime_must_match_labelled_internal_network(self) -> None:
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        name = "sovereign-synthetic-123456abcdef"

        def docker(*args: str, timeout: int = 120) -> str:
            if args[0] == "network" and "sovereign.synthetic.run" in args[-1]:
                return name
            if args[0] == "network":
                return "true"
            if args[-1] == "{{.State.Running}}":
                return "true"
            if "sovereign.synthetic.run" in args[-1]:
                return name
            return json.dumps({name: {"NetworkID": handle.network_id}})

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker), \
             patch("infrastructure.deploy.container_runtime._health") as health:
            probe_runtime(handle)
            health.assert_called_once_with(handle.core_id)

        def wrong_network(*args: str, timeout: int = 120) -> str:
            if args[-1] == "{{json .NetworkSettings.Networks}}":
                return json.dumps({name: {"NetworkID": "d" * 64}})
            return docker(*args, timeout=timeout)

        with patch("infrastructure.deploy.container_runtime._docker",
                   side_effect=wrong_network), \
             patch("infrastructure.deploy.container_runtime._health") as health:
            with self.assertRaises(RuntimeError):
                probe_runtime(handle)
            health.assert_not_called()


if __name__ == "__main__":
    unittest.main()
