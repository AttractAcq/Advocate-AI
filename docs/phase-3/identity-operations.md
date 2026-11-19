# Phase 3 identity and policy operations design

**Status:** proposed for external security review; synthetic lab only. The
Keycloak `start-dev` realm exercises local OIDC, Console PKCE, short-lived
signed access tokens and server-side source policy. It is not the production
identity configuration. This design records the remaining decisions so they
can be tested on the target deployment without inventing vessel approvals.

## Accounts and factors

| Identity | Intended use | Required control |
|---|---|---|
| Named crew member | Console sign-in with local authorization-code + PKCE flow | Unique account, vessel-approved role, short access-token life, disabled on offboarding; second factor according to vessel access policy |
| AV/IT administrator | Identity, source mapping and maintenance actions | Separate named admin account, phishing-resistant MFA where available, no inherited owner/private-document access, explicit audited elevation |
| Knowledge importer | Read only approved document folders and update the local index | Dedicated service identity, read-only NAS/export permission, no interactive Console login, scoped local API or filesystem access |
| Security event reader | Read approved Wazuh findings in Phase 4 | Dedicated read-only service identity; no rule, agent or network-device administration |
| Emergency access | Restore local service when normal administration is unavailable | Separately held credential, two-person release, short expiry, restricted actions and retrospective review |

Use local Keycloak for named users. Require MFA enrollment before granting an
administrative role; evaluate WebAuthn or local TOTP against the vessel's
offline device and recovery constraints. Disable password grant, self-service
registration and unreviewed role assignment in the deployed realm. Keep
Keycloak storage, signing keys and local TLS under the deployment's protected
backup and recovery process. The synthetic realm intentionally keeps direct
password grant for scripted tests; it must not be copied into production.

## Policy change workflow

1. The owner or delegated management authority approves a vessel-specific
   user, role, collection and document-classification matrix. Default policy
   examples in the build plan grant no vessel rights by themselves.
2. A named administrator records the request, reason, approver, affected
   sources, expiry where relevant and the previous policy version.
3. A second authorised person checks role and source mapping before activation.
   Emergency access is the only separately controlled exception.
4. Core rechecks current user status and source policy before retrieval,
   preview, citation and history output. Ingestion reconciles changes and
   deletions; cached model context and embeddings may never authorize access.
5. The audit record stores actor, action, resource, decision, policy version,
   timestamp and correlation ID. It excludes prompt and document bodies.
6. A reviewer checks the resulting effective permissions and the denial
   regression. Roll back an unintended grant and record the corrective action.

The current lab policy file supports immediate source denial and revocation.
The [synthetic offline policy-change tool](policy-change-rehearsal.md) checks
two distinct signatures and records an interrupted-change recovery packet,
but it is not an owner-approved administrative process or deployed API. The
local ACL test proves denial through API paths within 60 seconds after a policy
file update; target NAS and identity propagation remain unmeasured.
Core now reads that lab file through a 4 MiB regular-file-only boundary for
authentication, retrieval and audit policy hashes. Symlinks, duplicate JSON
keys and oversized content fail closed. A lab session invalidated during a
policy-file fault needs a new sign-in after repair. These software checks do
not approve the file's production ownership, change process or role map.
The shared active-user check also rejects duplicate identities and expired or
malformed `expires_at` values. A lab token is bound to the role at sign-in, so
a later role change requires a new login; OIDC still checks the current local
role against the signed token role on each request. These are prerequisites for
the proposed emergency workflow, not emergency activation.

## Emergency access drill to implement before pilot

Pre-register a disabled emergency identity with a restricted role. Hold its
secret separately from routine administrator credentials. On activation,
record the incident, authorizers, start and automatic expiry; notify the
security owner locally. Restrict the account to recovery actions, not private
document browsing. Verify every action in the audit chain, rotate the secret
after use and obtain retrospective review. Test activation, expiry, misuse
denial and audit evidence in the target lab before calling the control complete.

## Decisions needed for site configuration

- Named vessel approver and two administrators for routine and emergency work.
- MFA method, offline enrollment and lost-factor recovery process.
- NAS, Keycloak and Wazuh service-account permissions and credential custody.
- Role/document classification matrix, emergency expiry and retention periods.
- Keycloak persistent store, backup key custody and local TLS/PKI design.

No actual vessel identities, service accounts or emergency credentials have
been provisioned by this document.
