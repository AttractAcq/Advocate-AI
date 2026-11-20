# Signed offline model artifact in a vessel bundle

Schema-7 vessel bundles bind a model directory to the same Ed25519 release
signature as the Core, Console and Knowledge images. Put the approved model
files under `payload/model/` and pass `--model-id` to `pack-knowledge`. The
manifest lists every model file with its size and SHA-256 twice: in the full
payload inventory and in a model descriptor bearing that ID. The signer checks
the exact model tree, copies it into the private bundle and signs the copied
bytes. `verify` rejects changed, missing or extra files. The vessel installer
verifies the bundle before staging it, checks that the stage filesystem has
space for one complete bundle copy plus a reserve, and checks the staged copy.
Stopped release switching repeats that process before activation. The free
space check is a local filesystem preflight; target quotas and actual peak
usage still require a hardware rehearsal.

For schema-7 installs, Core receives `SOVEREIGN_MODEL_NAME` from the verified
model descriptor and a fixed HTTP loopback `/v1` endpoint. Vessel status
checks those environment values against the active signed bundle and rejects
an altered request name or endpoint. This binds Core's request configuration
to the staged model ID; it does not start vLLM, verify that weights load, or
make the synthetic vessel rehearsal answer with those weights.

The ID is an operator label, not proof of model publisher, licence, weights
quality or serving compatibility. The connected preparation process must
record source, revision, publisher authentication, redistribution terms and
model safety decision separately before the custodian signs a production
release. The schema-7 synthetic CI fixture uses two small fictional byte sets
to prove signed model changes and tamper refusal; it cannot run inference.

Actual model selection, vLLM start, offline cold start and GPU capacity remain
the target-lab gate B-02. Approved media, key custody, licence review and
production provenance remain B-07 and B-11 in the
[blocker tracker](../blockers-and-build-queue.md). Schema-6 bundles without a
model descriptor remain accepted for prior synthetic lab installations.
