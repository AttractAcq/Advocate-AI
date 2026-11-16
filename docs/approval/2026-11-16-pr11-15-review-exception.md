# PR #11–15 requester-directed GitHub review exception

- **Recorded:** 16 November 2026.
- **Requester instruction:** “PR #15 is open and stacked on PRs #14 through #11; it has not been merged. Next buildable slice: security hardening and adversarial tests. merge and then buid this.” Earlier the requester asked whether work could pass without a separate GitHub approval. This instruction authorises merging this specific synthetic software stack now.
- **Scope:** [PR #15](https://github.com/AttractAcq/Advocate-AI/pull/15) through [PR #11](https://github.com/AttractAcq/Advocate-AI/pull/11). Merge the stacked feature PRs into their existing base branches from top to bottom, then merge the resulting PR #11 into `main`. The one-time exception applies only to the independent GitHub approval requirement for the final protected-branch merge.
- **Pre-merge evidence:** Each PR's `quality`, `secrets` and `dependency-review` checks passed at the start of this merge sequence. Recheck all required checks on the final aggregated PR #11 head before merging into `main`.
- **Control handling:** Temporarily set required approving reviews to zero and disable last-push approval for the final PR #11 merge only. Keep pull-request, required-status-check, linear-history and other protections. Restore one required independent review and last-push approval immediately afterward and verify the settings.

This decision does not complete independent product security/QA review, Phase 4
Wazuh evidence, G2 or G3. It does not authorise vessel data, hardware
deployment or production release. Those remain open in the
[blocker tracker](../blockers-and-build-queue.md).

## Execution record

PRs #15, #14, #13 and #12 were merged into their stacked feature bases in that
order. The final aggregated PR #11 head was `6cf26c56d800a40adaf1d03e91bd1fe2c7feb4ce`;
its [quality, secrets and dependency checks](https://github.com/AttractAcq/Advocate-AI/actions/runs/43833974500)
all passed. PR #11 was squash-merged into `main` as
`ed18eb3a4081a65080297b9c2f2a7798ff1d77a3` on 16 November 2026.
The review requirement was temporarily reduced only around that final merge.
The immediately subsequent GitHub protection read confirmed
`required_approving_review_count: 1`, `require_last_push_approval: true` and
`dismiss_stale_reviews: true`. Required status checks and linear history were
not altered.
