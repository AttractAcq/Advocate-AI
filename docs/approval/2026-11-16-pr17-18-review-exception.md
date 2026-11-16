# PR #17–18 requester-directed GitHub review exception

- **Recorded:** 16 November 2026.
- **Requester instruction:** “close all of these. bypass ithe independant review rule. merge all.” The immediate context identifies open PRs #17 and #18.
- **Scope:** Merge [PR #18](https://github.com/AttractAcq/Advocate-AI/pull/18) into its existing feature-branch base, then merge the resulting [PR #17](https://github.com/AttractAcq/Advocate-AI/pull/17) into `main`. The one-time exception applies only to the independent GitHub approval requirement for that final protected-branch merge.
- **Pre-merge evidence:** Recheck `quality`, `secrets` and `dependency-review` on each PR's final head, including PR #17 after the stack is combined.
- **Control handling:** Temporarily set required approving reviews to zero and disable last-push approval for the final PR #17 merge only. Keep pull-request, required-status-check, stale-review dismissal and linear-history protections. Restore one required independent review and last-push approval immediately afterward and verify the settings.

This exception does not close independent **product** security and QA review, target hardware/NAS/Wazuh and network tests, vessel approvals, T-031 or G2/G3. The [blocker tracker](../blockers-and-build-queue.md) keeps those gates open until their specified evidence exists. It does not authorise vessel data or deployment.
