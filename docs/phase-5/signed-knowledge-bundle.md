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

This establishes the release contract; it does not yet create a releasable
Knowledge image. The digest-pinned pgvector image used in the synthetic lab
still needs a resolved SBOM, vulnerability triage, offline archive provenance
and licence review. The current signed installer only accepts the schema 4
Core and Console bundle. The next implementation must stage and activate the
schema 6 database image, separate migration and runtime identities, protected
credentials, state volumes and a coordinated clean restore. Target hardware
and independent security review remain open.
