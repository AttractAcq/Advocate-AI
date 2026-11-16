import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import BundleError, create_bundle, verify_bundle


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        (self.payload / "images").mkdir(parents=True)
        (self.payload / "images" / "core.tar").write_bytes(b"fictional-image")
        self.private = self.root / "signing-key.pem"
        self.public = self.root / "trusted-key.pem"
        key = Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        self.bundle = self.root / "release"

    def pack(self) -> None:
        create_bundle(self.payload, self.bundle, self.private, "0.1.0")

    def test_valid_then_tampered_payload_and_manifest_fail(self) -> None:
        self.pack()
        self.assertEqual(verify_bundle(self.bundle, self.public)["version"], "0.1.0")
        (self.bundle / "images" / "core.tar").write_bytes(b"altered-image")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)
        (self.bundle / "images" / "core.tar").write_bytes(b"fictional-image")
        manifest = self.bundle / "release-manifest.json"
        manifest.write_bytes(manifest.read_bytes().replace(b"0.1.0", b"0.2.0"))
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)

    def test_wrong_trust_key_and_unlisted_file_fail(self) -> None:
        self.pack()
        other = Ed25519PrivateKey.generate().public_key()
        self.public.write_bytes(other.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)
        self.public.write_bytes(serialization.load_pem_private_key(
            self.private.read_bytes(), password=None).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        (self.bundle / "extra.txt").write_text("unlisted")
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)

    def test_symlink_and_signing_key_in_payload_rejected(self) -> None:
        (self.payload / "escape").symlink_to(self.private)
        with self.assertRaises(BundleError):
            self.pack()
        (self.payload / "escape").unlink()
        with self.assertRaises(BundleError):
            create_bundle(self.payload, self.bundle, self.payload / "images" / "core.tar", "0.1.0")
        self.pack()
        (self.bundle / "images" / "core.tar").unlink()
        (self.bundle / "images" / "core.tar").symlink_to(self.private)
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)

    def test_duplicate_manifest_record_rejected_even_if_signed(self) -> None:
        self.pack()
        manifest_file = self.bundle / "release-manifest.json"
        manifest = json.loads(manifest_file.read_text())
        manifest["files"].append(manifest["files"][0])
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_file.write_bytes(raw)
        key = serialization.load_pem_private_key(self.private.read_bytes(), password=None)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)

    def test_signed_path_traversal_record_is_rejected(self) -> None:
        self.pack()
        manifest_file = self.bundle / "release-manifest.json"
        manifest = json.loads(manifest_file.read_text())
        manifest["files"][0]["path"] = "../signing-key.pem"
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_file.write_bytes(raw)
        key = serialization.load_pem_private_key(self.private.read_bytes(), password=None)
        (self.bundle / "release-manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))
        with self.assertRaises(BundleError):
            verify_bundle(self.bundle, self.public)


if __name__ == "__main__":
    unittest.main()
