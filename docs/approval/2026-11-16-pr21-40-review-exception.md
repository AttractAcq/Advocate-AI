# One-time GitHub PR review exception for #21–40

On 16 November 2026, the requester explicitly authorized a one-time
exception to the repository's independent GitHub PR approval requirement for
PRs #21 through #40, provided their CI checks pass. This authorization is
limited to those numbered PRs. It does not waive CI, the independent product
security assessment, hardware validation, vessel/site approvals, release
signing-key custody, licence review or production acceptance gates.

Merge the stacked PRs while preserving the passing code and required status
checks. Temporarily remove the `main` PR approval requirement only for the
final protected-branch merge, then restore one required independent approval,
stale-review dismissal and last-push approval immediately afterward. Verify
the resulting main commit, check run and restored protection state. Future
PRs follow the normal review rule unless the requester approves a separate
exception.
