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
    cleanup_orphan_runtimes, verify_runtime_identity,
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
        self.assertIsNone(_validate_console_config(self.config))
        for raw in ('{"schema":1,"schema":1,"oidc_issuer":null}',
                    '{"schema":1,"oidc_issuer":"https://id.example/realm"}',
                    '[]', '{"schema":true,"oidc_issuer":null}'):
            with self.subTest(raw=raw):
                self.config.write_text(raw)
                with self.assertRaises(RuntimeError):
                    _validate_console_config(self.config)

    def test_vessel_oidc_config_requires_exact_https_realm(self) -> None:
        issuer = "https://identity.vessel.example/realms/sovereign"
        self.config.write_text(json.dumps({"schema": 1, "oidc_issuer": issuer}))
        self.assertEqual(_validate_console_config(self.config, allow_oidc=True), issuer)
        with self.assertRaises(RuntimeError):
            _validate_console_config(self.config)
        for candidate in ("http://127.0.0.1:18086/realms/lab",
                          "https://identity.vessel.example/realms/sovereign/",
                          "https://identity.vessel.example:8443/realms/sovereign",
                          "https://other.example/realms/a?redirect=https://example.com"):
            with self.subTest(candidate=candidate):
                self.config.write_text(json.dumps({"schema": 1, "oidc_issuer": candidate}))
                with self.assertRaises(RuntimeError):
                    _validate_console_config(self.config, allow_oidc=True)

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
            if args[-1] in ("{{json .Mounts}}", "{{json .Config.Env}}"):
                return "[]"
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

    def test_vessel_identity_network_attaches_only_core(self) -> None:
        name = "sovereign-synthetic-123456abcdef"
        identity = "vessel-identity"
        handle = RuntimeHandle("a" * 64, "b" * 64, "c" * 64,
                               "d" * 64, identity)

        def docker(*args: str) -> str:
            if args[:2] == ("network", "inspect"):
                if args[2] == identity:
                    return {"{{.Id}}": handle.identity_network_id,
                            "{{.Internal}}": "true",
                            '{{index .Labels "sovereign.vessel.identity"}}': "true"}[args[-1]]
                return name if "sovereign.synthetic.run" in args[-1] else "true"
            if args[-1] == '{{index .Config.Labels "sovereign.synthetic.run"}}':
                return name
            if args[-1] == "{{json .NetworkSettings.Networks}}":
                networks = {name: {"NetworkID": handle.network_id}}
                if args[1] == handle.core_id:
                    networks[identity] = {"NetworkID": handle.identity_network_id}
                return json.dumps(networks)
            raise AssertionError(args)

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            verify_runtime_identity(handle)
        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            with self.assertRaises(RuntimeError):
                verify_runtime_identity(RuntimeHandle(handle.network_id, handle.core_id,
                                                      handle.console_id, None, identity))

        def leaked(*args: str) -> str:
            if args[-1] == "{{json .NetworkSettings.Networks}}" and args[1] == handle.console_id:
                return json.dumps({name: {"NetworkID": handle.network_id},
                                   identity: {"NetworkID": handle.identity_network_id}})
            return docker(*args)

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=leaked):
            with self.assertRaises(RuntimeError):
                verify_runtime_identity(handle)

    def test_scoped_orphan_cleanup_preserves_active_runtime(self) -> None:
        installation = "1" * 32
        active = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)
        orphan = RuntimeHandle("d" * 64, "e" * 64, "f" * 64)
        runs = {active.network_id: "sovereign-synthetic-aaaaaaaaaaaa",
                orphan.network_id: "sovereign-synthetic-dddddddddddd"}
        containers = {active.core_id: (active.network_id, "core"),
                      active.console_id: (active.network_id, "console"),
                      orphan.core_id: (orphan.network_id, "core"),
                      orphan.console_id: (orphan.network_id, "console")}
        removed: list[tuple[str, ...]] = []

        def docker(*args: str, timeout: int = 120) -> str:
            if args[:2] == ("network", "ls"):
                return "\n".join(runs)
            if args[0] == "ps":
                return "\n".join(containers)
            if args[:2] == ("network", "inspect"):
                network_id = args[2]
                if args[-1] == "{{.Name}}":
                    return runs[network_id]
                if args[-1] == "{{.Internal}}":
                    return "true"
                return json.dumps({"sovereign.synthetic.run": runs[network_id],
                                   "sovereign.synthetic.install": installation})
            if args[0] == "inspect":
                network_id, role = containers[args[1]]
                run = runs[network_id]
                if args[-1] == "{{.Name}}":
                    return f"/{run}-{role}"
                if args[-1] == "{{json .Config.Labels}}":
                    return json.dumps({"sovereign.synthetic.run": run,
                                       "sovereign.synthetic.install": installation})
                return json.dumps({run: {"NetworkID": network_id}})
            removed.append(args)
            return args[-1]

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            self.assertEqual(cleanup_orphan_runtimes(installation, active),
                             {"containers": 2, "networks": 1})
        self.assertEqual(removed, [("rm", "-f", orphan.core_id),
                                   ("rm", "-f", orphan.console_id),
                                   ("network", "rm", orphan.network_id)])

    def test_orphan_cleanup_fails_before_deletion_on_wrong_network_label(self) -> None:
        active = RuntimeHandle("a" * 64, "b" * 64, "c" * 64)

        def docker(*args: str, timeout: int = 120) -> str:
            if args[:2] == ("network", "ls"):
                return "d" * 64
            if args[0] == "ps":
                return ""
            if args[-1] == "{{.Name}}":
                return "sovereign-synthetic-dddddddddddd"
            if args[-1] == "{{.Internal}}":
                return "true"
            if args[-1] == "{{json .Labels}}":
                return json.dumps({"sovereign.synthetic.install": "other"})
            raise AssertionError("cleanup reached deletion")

        with patch("infrastructure.deploy.container_runtime._docker", side_effect=docker):
            with self.assertRaises(RuntimeError):
                cleanup_orphan_runtimes("1" * 32, active)


if __name__ == "__main__":
    unittest.main()
