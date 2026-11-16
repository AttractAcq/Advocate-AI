# Identity and document permission SOP — proposed target workflow

**Owners:** vessel data owner for permission decisions; named identity administrator for execution; separate checker for effective access. This is a workflow template, not a vessel-approved role map or an implemented two-person change API. The current [identity operations design](../phase-3/identity-operations.md) and [Phase 3 lab runbook](../phase-3/runbook.md) describe what is implemented.

## Request and approve

1. Record the named user or service identity, source folder/document class, allowed actions, reason, expiry, approving vessel authority and current policy version. A department title or AV/IT status alone grants no source access.
2. The vessel data owner approves the exact source/role matrix. A separate checker compares the proposed change to source NAS ACLs and verifies that any unknown ACL fails closed. Do not use the fictional lab matrix as a vessel policy.
3. The identity administrator applies the approved change through the deployed identity/source process only after the second check. Store credentials outside the repository, logs and prompts. Production Keycloak, MFA, service identities and approval workflow have not yet been qualified.

## Verify and revoke

4. Test sign-in and each relevant action: search, answer context, citation, preview, download/export if implemented, history and approved tool use. Test a permitted user and at least one denied user. A UI-hidden control does not prove server denial; test direct Core API access as well.
5. For offboarding or source revocation, disable the user or remove the source grant, reconcile index/deletion state, then repeat prior queries and history access. The proposed 60-second propagation target requires timestamped lab measurement; do not claim it from this SOP.
6. Verify audit metadata: actor, action, resource, decision, policy version, timestamp and correlation ID, without prompt or document body. Review and roll back any unintended grant. Keep the request, approval, effective-access result, denial regression and audit reference in the controlled evidence store.

## Emergency and failure cases

Emergency access requires a pre-registered restricted identity, separate custody, two-person release, a recorded reason, short expiry, local notification, action review and secret rotation afterward. This workflow is **unimplemented and untested** in the synthetic realm. Never reuse the lab Keycloak `start-dev` realm or direct password grant for vessel access.

If an ACL cannot be mapped, a source changes without reliable reconciliation, or a removed user still retrieves content, stop ingestion/retrieval for the affected scope, preserve audit evidence and escalate to the data owner and security lead. Do not compensate by widening permissions. [B-03, B-08 and B-10](../blockers-and-build-queue.md) track the target topology, independent bypass review and owner approvals.
