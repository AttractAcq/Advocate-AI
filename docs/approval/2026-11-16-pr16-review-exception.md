# PR #16 requester-directed GitHub review exception

- **Recorded:** 16 November 2026.
- **Requester instruction:** “PR #16 remains open for independent review. - bypass this independant review and merge”.
- **Scope:** [PR #16](https://github.com/AttractAcq/Advocate-AI/pull/16) only. This is a one-time exception to the independent GitHub approval requirement for merging this synthetic security-hardening slice into `main`.
- **Pre-merge evidence:** Verify that `quality`, `secrets` and `dependency-review` pass on the final PR head before merge.
- **Control handling:** Temporarily set required approving reviews to zero and disable last-push approval only for this merge. Keep pull-request, required-status-check, stale-review dismissal and linear-history protections. Restore one required independent review and last-push approval immediately afterward, then verify the settings.

This exception does not substitute for independent product security and QA review, hardware validation or G2/G3 acceptance. Those remain in the [blocker tracker](../blockers-and-build-queue.md).
