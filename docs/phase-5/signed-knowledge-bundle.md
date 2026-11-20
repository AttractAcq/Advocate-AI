# Three-image vessel release format

The release signer can now create schema 6 vessel bundles containing exactly
three evidenced image roles: `core`, `console` and `knowledge`. Each role needs
its own OCI archive, generated SBOM, vulnerability scan, archive digest and
crane verification result. The signer refuses missing or extra archives and
refuses any image whose intake has unresolved HIGH, CRITICAL or UNKNOWN
findings. The detached Ed25519 signature binds the complete file inventory,
three image descriptors and `target=vessel`. The verifier repeats the evidence
and payload checks after copying; a valid signature with the wrong target is
still rejected. The earlier two-image vessel and separate Fleet formats
remain valid.

The CLI accepts a strict descriptor file:

```sh
.venv/bin/python -m infrastructure.release.bundle pack-knowledge \
  /path/to/payload /path/to/new-bundle \
  --signing-key /path/to/custodian-key.pem --version <version> \
  --images-json /path/to/three-image-descriptors.json \
  --crane /path/to/verified/crane
```

The original digest-pinned pgvector image and the official Trixie comparison
remain [denied by archive intake](pgvector-image-intake.md). The locally built
[Alpine Knowledge candidate](alpine-knowledge-image.md) has a resolved SBOM
and a zero-finding synthetic scan, but distribution provenance, licence review
and release-signing custody remain open. The current signed installer only
accepts the schema 4 Core and Console bundle. The next implementation must
stage and activate the schema 6 database image, carry separate database roles
and protected credentials, preserve state volumes and coordinate a clean
restore. Target hardware and independent security review remain open.

The [actual-image rehearsal](actual-three-image-release.md) now tests this
contract against the locally built Alpine Knowledge candidate alongside Core
and Console. Its result is a disposable synthetic trial, not a production
release authorization.
