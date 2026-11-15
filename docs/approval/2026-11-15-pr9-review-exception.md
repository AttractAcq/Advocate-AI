# PR #9 requester-directed review exception

- **Recorded:** 15 November 2026, 17:59 UTC.
- **Requester instruction:** After being told that GitHub required approval
  from someone other than the last pusher, the requester asked, “can you pass
  this wihtout the independant different ghithub approval?” Earlier in the
  same exchange they instructed, “approved. now merge”.
- **Scope:** [PR #9](https://github.com/AttractAcq/Advocate-AI/pull/9) only,
  containing synthetic Phase 0–3 development work. This is a requester
  exception to the repository's independent PR approval requirement for this
  merge, not an independent review or security sign-off.
- **Evidence before merge:** `quality`, `secrets` and `dependency-review` CI
  checks passed on the prior PR head. The final head must pass the same checks
  before merge. A normal merge and GitHub's administrator merge override were
  rejected by the existing review rule.
- **Control handling:** Temporarily set required approving reviews to zero
  and disable last-push approval for this merge only; keep pull-request,
  status-check and other branch protections. Restore one required independent
  review and last-push approval immediately afterward, then verify the saved
  protection settings through GitHub's API.

The external Phase 0–3 security/QA review remains open in the
[closure audit](../review/phase-0-3-closure-audit.md). This exception does not
authorise vessel data, access, procurement, deployment or a claim that the
security gate passed.
