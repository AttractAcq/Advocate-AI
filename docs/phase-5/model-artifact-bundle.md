# Signed offline model artifact in a vessel bundle

Schema-7 and schema-8 vessel bundles bind a model directory to the same Ed25519
release signature as the Core, Console and Knowledge images. Put the approved
model files under `payload/model/` and pass `--model-id` to `pack-knowledge`. The
manifest lists every model file with its size and SHA-256 twice: in the full
payload inventory and in a model descriptor bearing that ID. The signer checks
the exact model tree, copies it into the private bundle and signs the copied
bytes. `verify` rejects changed, missing or extra files. The vessel installer
verifies the bundle before staging it, checks that the stage filesystem has
space for one complete bundle copy plus a reserve, and checks the staged copy.
Stopped release switching repeats that process before activation. The free
space check is a local filesystem preflight; target quotas and actual peak
usage still require a hardware rehearsal.

For schema-7 and schema-8 installs, Core receives `SOVEREIGN_MODEL_NAME` from the verified
model descriptor and a fixed HTTP loopback `/v1` endpoint. Vessel status
checks those environment values against the active signed bundle and rejects
an altered request name or endpoint. This binds Core's request configuration
to the staged model ID; it does not start vLLM, verify that weights load, or
make the synthetic vessel rehearsal answer with those weights.

The actual-image CI rehearsal starts a temporary OpenAI-compatible responder
on the running Core container's loopback interface. It sends one general chat
request through Core and checks that the responder receives the signed model
ID; a request naming another model is rejected by Core before it reaches the
responder. Once the responder stops, another chat request must fail with 503;
Core has no fallback model route. The responder and its canned answer exist only during this
synthetic probe. This confirms local request routing, not inference quality or
the production model service lifecycle.

The retained PR #175–179 actual-image results report `denied-findings` for the
Knowledge image, so those runs stopped before this synthetic probe. The image
must pass the scan and the result must say `signed-and-verified` before treating
the route as observed CI evidence. The CLI now fails if scan intake skips the
rehearsal while retaining its scan artifact. The [PR #180 implementation-head
result](https://github.com/AttractAcq/Advocate-AI/actions/runs/44843503603)
meets that condition and records the signed model route and outage probe.

An authenticated AV/IT administrator can call `GET /api/admin/model-readiness`
to check whether the configured loopback service advertises the signed model
ID at `/v1/models`. The request has a three-second timeout and a 64 KiB response
limit. A missing service, malformed response, unexpected ID or upstream error
returns 503. Other roles receive 403. `/health` remains Core liveness; an
advertised model ID does not prove that its weights can answer a prompt. A
target-lab acceptance run must pair this check with an actual cited answer and
an offline restart. The actual-image synthetic rehearsal checks 403 for a
non-administrator, a matching advertisement while its responder runs and 503
after shutdown.

The ID is an operator label, not proof of model publisher, licence, weights
quality or serving compatibility. The connected preparation process must
record source, revision, publisher authentication, redistribution terms and
model safety decision separately before the custodian signs a production
release. To record the source declaration in a schema-8 bundle, pass
`--model-provenance-json` with a small JSON object containing exactly
`source_url` (HTTPS URL without credentials or query), `revision` (40 or 64
lowercase hex characters), `publisher` and `license_claim`. The signer and
verifier reject malformed declarations and sign the values in the model
descriptor. These are custodian declarations, not proof of publisher identity,
licence terms or redistribution approval. Schema-7 model bundles without this
declaration remain readable for prior synthetic lab work. The schema-8 CI
fixture uses fictional model bytes and an explicitly synthetic declaration;
it cannot run inference.

Actual model selection, vLLM start, offline cold start and GPU capacity remain
the target-lab gate B-02. Approved media, key custody, licence review and
production provenance remain B-07 and B-11 in the
[blocker tracker](../blockers-and-build-queue.md). Schema-6 bundles without a
model descriptor remain accepted for prior synthetic lab installations.
