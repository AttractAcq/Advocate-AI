# PR #10 requester-directed GitHub review exception

- **Recorded:** 15 November 2026.
- **Requester instruction:** “can you pass this wihtout the independant different ghithub approval?” This follows their direction to continue Phase 4 software development while physical hardware procurement is paused.
- **Scope:** [PR #10](https://github.com/AttractAcq/Advocate-AI/pull/10) only, containing synthetic Phase 4 software and an explicit open gate. This waives the separate GitHub PR approval for this merge; it does not complete an independent security review or Phase 4 exit gate.
- **Pre-merge evidence:** The 39-test local suite and Console build passed. GitHub `quality`, `secrets` and `dependency-review` checks passed on commit `c201f92`; the final PR head must also pass all three checks.
- **Control handling:** Temporarily set required approving reviews to zero and disable last-push approval for this merge only. Keep pull-request, status-check and other protections. Restore one required independent review and last-push approval immediately after merge and verify the settings.

The independent Wazuh host, collector and offline operation, AI outage event reconciliation, network/write-boundary tests and external security/QA sign-off remain open in the [Phase 4 gate](../phase-4/gate.md). This exception does not authorise vessel data or production deployment.
