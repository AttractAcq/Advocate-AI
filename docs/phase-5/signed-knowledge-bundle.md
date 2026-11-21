# Three-image vessel release format

The release signer can create schema-6 or schema-7 vessel bundles containing exactly
three evidenced image roles: `core`, `console` and `knowledge`. Each role needs
its own OCI archive, generated SBOM, vulnerability scan, archive digest and
crane verification result. The signer refuses missing or extra archives and
refuses any image whose intake has unresolved HIGH, CRITICAL or UNKNOWN
findings. The detached Ed25519 signature binds the complete file inventory,
three image descriptors, `target=vessel`, and an explicit compatibility
contract. The contract names the Knowledge schema and external Core state
format required by the release. The current runtime supports exactly
`knowledge_schema=1` and `core_state_schema=1`; a correctly signed release
declaring a different version can be verified for intake but cannot be
installed or switched by this runtime. The verifier repeats the evidence
and payload checks after copying; a valid signature with the wrong target or
malformed contract is rejected. The earlier two-image product and separate
Fleet formats remain valid.

Schema 7 adds a signed model-file descriptor to the same vessel bundle. It
requires every file under `model/` to appear in both the full payload inventory
and the exact model descriptor. The signer rejects model files without a model
ID, and verification rejects altered, missing or extra model files before
installation. Existing schema-6 lab bundles remain verifiable. See the
[model artifact procedure](model-artifact-bundle.md).

For the vessel format, the signer and verifier also read the hash-bound Core
configuration from the exact Docker archive. Its `sovereign.compat.knowledge-schema`
and `sovereign.compat.core-state-schema` labels must equal the signed contract.
This catches a release metadata mismatch before signing and again when a copied
bundle is verified. The image builder declares these labels; independent code
review still needs to confirm the running Core actually implements the declared
formats.

The CLI accepts a strict descriptor file:

```sh
.venv/bin/python -m infrastructure.release.bundle pack-knowledge \
  /path/to/payload /path/to/new-bundle \
  --signing-key /path/to/custodian-key.pem --version <version> \
  --images-json /path/to/three-image-descriptors.json \
  --knowledge-schema 1 --core-state-schema 1 \
  --model-id APPROVED_MODEL_ID \
  --model-provenance-json /path/to/model-provenance.json \
  --crane /path/to/verified/crane
```

The original digest-pinned pgvector image and the official Trixie comparison
remain [denied by archive intake](pgvector-image-intake.md). The locally built
[Alpine Knowledge candidate](alpine-knowledge-image.md) has a resolved SBOM
and a zero-finding synthetic scan, but distribution provenance, licence review
and release-signing custody remain open. The [vessel installer](signed-vessel-first-install.md)
now stages and activates the schema-6, schema-7 or schema-8 database image with separate database
roles and protected credentials. [Stopped release switching](vessel-release-switch.md)
and [coordinated recovery](vessel-recovery-set.md) have synthetic rehearsals.
Actual schema migration and rollback compatibility across versions, target
hardware and independent security review remain open.

The [actual-image rehearsal](actual-three-image-release.md) now tests the schema-8
model-file and declared-provenance binding and this
contract against the locally built Alpine Knowledge candidate alongside Core
and Console. Its result is a disposable synthetic trial, not a production
release authorization.
