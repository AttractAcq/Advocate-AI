# AT-18 performance and access review brief

**Status: pending independent review and target GPU test.** The proposed
[AT-18 acceptance row](../05-acceptance-tests.md) calls for five named users,
50 requests per role over 30 minutes on a fixed corpus and context, p95 time
to first token at most 10 seconds, p95 time for a 300-token answer at most
60 seconds, no OOM or process restarts, and recorded throughput and GPU
thermals. Product and QA have not signed these proposed thresholds. A Mac
smoke result is development evidence, not a G2 decision.

## Evidence ready for inspection

| Evidence | What it establishes | What remains unproven |
|---|---|---|
| [Core load harness](../../scripts/phase5_core_load.py) and [runbook](../phase-5/core-load-rehearsal.md) | Fixed five-role schedule, per-request latency and throughput, expected citation identity and exact cross-role denials without retaining question or answer text | Full target run, answer prose support, user-visible first-token latency, 300-token answer time, GPU/process health |
| [Original Core Mac smoke](../phase-5/core-load-smoke-mac.json) | 10/10 local requests passed the original citation-ID and denial checks | Exact source metadata was added later; this is not a capacity result |
| [Citation-integrity Core Mac smoke](../phase-5/core-load-citation-integrity-mac.json) | 10/10 local requests passed with source ID, version, hash, collection and passage ordinal checks; p95 complete-response time 11.543 seconds | Human claim review, target concurrency duration and first-token metric |
| [Direct inference probe](../../scripts/phase5_inference_stream_probe.py), [runbook](../phase-5/inference-stream-probe.md) and [Mac report](../phase-5/inference-stream-mac.json) | Five local model streams stopped normally at 332–393 tokens; p95 first-content time 64.685 seconds and p95 full-answer time 80.620 seconds | Core/Console path, target GPU, a statistically reliable p95 and acceptance of the proposed thresholds |
| [Blocker record](../blockers-and-build-queue.md) | W-207–W-209 and B-01/B-02/B-06/B-08/B-14 identify the software evidence and open gates | Reviewer sign-off, approved target hardware and repository integration |

The Core API returns a complete response and does not stream tokens to the
client. The direct model's first nonempty content delta is only a proxy for
first token. Do not label it an end-to-end Core or Console first-token result.
The 300-token direct probe uses a different prompt from the fixed document
corpus; its timing cannot be substituted for the full Core workload.

## Target lab reproduction and observations

1. Record the exact release, model, runtime and fixture digests; host CPU,
   memory, GPU, driver, network and power profile; and the fixed context size.
   Confirm the approved synthetic corpus and five temporary named roles before
   testing. Keep tokens and any vessel data out of the evidence package.
2. Run the [Core harness command](../phase-5/core-load-rehearsal.md#target-lab-command)
   with 50 requests per role and 1800 scheduled seconds. Preserve its
   metadata-only JSON, script exit code, health-before/after result and a
   monotonic test clock. Check every failed citation, denial, HTTP status and
   latency sample. A successful exit alone is insufficient.
3. Choose and approve a user-visible first-token measurement method before
   applying the proposed 10-second threshold. The current non-streaming Core
   endpoint cannot supply one. If the endpoint or Console changes, repeat the
   security and permission review for any newly exposed partial output.
4. Exercise a representative 300-token answer through the accepted measurement
   path. Record the prompt and output only in protected reviewer material if
   needed for quality assessment; retain timing, token count, finish reason
   and hashes in the shared evidence. Confirm the answer is complete rather
   than stopped by an output cap.
5. Collect time-aligned GPU memory, power and thermal samples, model/Core
   process and container IDs, restart/OOM events, service health, and network
   routes or packet captures. Inspect both WAN-present and WAN-disconnected
   operation under the separate AT-10 and AT-17 procedures.
6. Repeat or extend samples enough to support a p95 decision, compare the
   agreed thresholds, and record quality and access-control regressions.
   Describe any changed model, corpus, context or hardware rather than mixing
   incompatible distributions.

## Independent decision record

The reviewer should provide identity and independence, exact commits and
artifact hashes, environment, commands, sample counts, raw timing distribution,
metric definitions, defects and retests. State separately whether the fixed
five-role workload, citation/denial behavior, first-token measure, 300-token
measure, GPU/process observations and network controls pass, fail or remain
unmeasured. Product and QA must sign any adopted latency thresholds. This brief
does not close AT-18, G2, the product security assessment, or the independent
GitHub PR approval.
