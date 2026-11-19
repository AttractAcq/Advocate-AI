# Synthetic emergency access drill

The fixture policy contains `lab-emergency-recovery-1` as a revoked identity
with role `emergency_recovery` and no document collections. A candidate policy
may activate it only with an `emergency_incident` such as `INC-SYNTH-001` and
an aware `expires_at` no more than 60 minutes ahead. The
[two-person policy-change tool](policy-change-rehearsal.md) requires separate
signed approvals for that candidate. Core rechecks incident, expiry and role
on each request, including when the policy is edited outside the tool.

The synthetic Core receives a separate `SOVEREIGN_EMERGENCY_PASSWORD_FILE` or
`Settings.emergency_password_file`. Its file must be regular, owner-only and
at most 4 KiB. It must differ from the ordinary lab password. An emergency
token is tied to that secret's hash; changing the secret revokes the token.
The emergency role may call only `/api/me`, `/api/logout` and
`/api/emergency/status`. The latter reports a verified audit-record count,
its expiry and `document_access: denied`. Source, chat, model, incident and
normal administration routes return 403.

The local rehearsal activates the identity with two generated test signers,
rejects ordinary credentials, checks the permitted status route and denied
routes, rotates the separate secret, and advances the test clock beyond
expiry. It also rejects a symlinked or exposed secret and candidate policies
with an excessive expiry, missing incident or document access. No model call
is made by the emergency identity. The local `make check` run passes 205 tests
with five skips.

The synthetic product installer can now pin a separate owner-only emergency
credential on first install or clean restore with `--emergency-password-file`.
It mounts that file read-only into Core, retains the path across updates and
recovery, and checks the running container's mount and environment identity.
It rejects a symlinked, exposed, same-inode or state-internal credential and
rejects later mount changes. The secret itself stays outside the signed bundle
and the encrypted Core-state snapshot. An atomic replacement of the host file
does not update an existing Docker file bind mount; rotate the credential by
restarting the synthetic Core and rechecking its mount before issuing a new
token. The target-host rotation procedure remains untested.

This is a restricted diagnostic account, not a completed break-glass recovery
process. Core does not expose restore actions. Owner-approved authorization, separate custody,
MFA/Keycloak enrollment, local notification, post-use rotation and
retrospective review, target-host testing and independent security assessment
remain open. No real vessel identity or secret is stored in this repository.
