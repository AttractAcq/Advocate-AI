# Synthetic vessel Keycloak clean recovery

**Status: lab rehearsal, not a production identity backup plan.**

After building the Core image and pulling the pinned Keycloak lab image, run
`python -m scripts.phase3_vessel_keycloak_rehearsal --recovery`. The
`fleet-keycloak-interoperability` CI job runs the same command. It uses only
fictional crew accounts, a temporary private CA and an internal Docker
identity network.

The rehearsal obtains real PKCE tokens for an engineer and deckhand, checks
their Core roles and source scope, logs them out and records the engineer's
revoked token. It then stops Keycloak and exports the `sovereign` realm with
users from its disposable data volume. The export is encrypted with the
existing authenticated backup format. A separately retained SHA-256 value
identifies the current archive. A valid but older archive fails that checkpoint;
an altered archive fails authentication even when its altered digest is used.

A fresh Keycloak instance imports only the checked export, without mounting
the old data volume. Core restarts against the same local policy, CA and
revocation log. The old token must remain denied and a fresh engineer login
must succeed. The result reports statuses only; it does not print credentials,
tokens or realm contents.

This test does **not** restore the vessel's signed Core/Knowledge recovery set
alongside Keycloak. Realm export omits some persistent Keycloak state, including
sessions and events. A production identity database topology, consistent
capture point across Core/Knowledge/Keycloak, signing-key custody, separate
checkpoint storage, backup media, RTO/RPO and target-host rehearsal remain
open under B-03/B-07/B-10 in the [blocker tracker](../blockers-and-build-queue.md).
The [synthetic identity recovery pair](../phase-5/vessel-identity-recovery-pair.md)
can bind this export's bytes to one signed Core/Knowledge receipt for later
verification; it does not establish that missing common capture point.
