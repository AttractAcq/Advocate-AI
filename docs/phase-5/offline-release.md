# Signed offline release: local software slice

The release builder copies an already approved artifact directory into a new
bundle directory, hashes each file and signs the exact JSON manifest with an
Ed25519 private key. The verifier checks the signature against a separately
provided trusted public key, then checks the complete file inventory, lengths
and SHA-256 hashes. It rejects duplicate paths, symlinks, traversal, unlisted
files and changed bytes. Neither command installs or executes a payload.

For a synthetic exercise, generate an ephemeral Ed25519 key outside the
repository and prepare a directory of fictional artifacts. The signing key
must never be included in the payload or carried onboard. Release-key
generation, storage, rotation and revocation need the approved custodian design
before a real release.

```sh
.venv/bin/python -m infrastructure.release.bundle pack /path/to/approved-payload /path/to/new-bundle --signing-key /secure/offline/signing-key.pem --version 0.1.0
.venv/bin/python -m infrastructure.release.bundle verify /path/to/new-bundle --trusted-key /path/to/pinned-release-public-key.pem
```

The public key must arrive through an authenticated trust-establishment
procedure separate from the bundle. A valid signature proves control of the
corresponding private key, not that the included software was approved or
scanned. The synthetic [installer](installer.md) now stages a verified bundle
and rehearses pointer rollback. The target workflow must still verify
dependency/model/container provenance, generate a resolved SBOM, scan transfer
media, install the full stack offline, exercise functioning-service rollback
and record AT-15. Those remain open in
the [blocker and build tracker](../blockers-and-build-queue.md).
