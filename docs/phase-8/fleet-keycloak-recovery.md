# Synthetic Fleet Keycloak recovery rehearsal

Run `python -m scripts.phase8_fleet_keycloak_rehearsal --recovery` after building
the two Fleet images and pulling the digest-pinned Keycloak lab image. CI runs
the same command in `fleet-keycloak-interoperability`.

The rehearsal creates only fictional users and credentials. It first saves an
encrypted archive of the initial realm. After the existing signing-key rollover,
it stops Keycloak before exporting the current realm and its users with
`export --realm fleet --users realm_file`. The stopped export follows
[Keycloak's import and export guidance](https://www.keycloak.org/server/importExport).
The existing `infrastructure.backup` AES-256-GCM format encrypts that export
with a separate, temporary key. A trusted SHA-256 checkpoint is kept outside
the archive. Recovery rejects the earlier valid archive against that checkpoint
and rejects an altered archive even when its digest is supplied as the expected
value. A clean destination receives the authenticated export, and a fresh
Keycloak container imports it without mounting the old database. A new PKCE
token must still resolve to the `fleet_admin` role in the running Fleet API;
the lab token remains denied. The result contains statuses only, not credentials
or tokens.

The checkpoint is a test of freshness only if an operator retains its expected
value in a trusted system separate from the backup. An attacker who can replace
both the archive and checkpoint can defeat that check. Keycloak also states that
realm export is not a complete database backup: it excludes events, persisted
sessions, workflow state and revoked tokens. This lab exercise does not establish
the production identity database topology, credential escrow, backup media,
key custody, RTO/RPO, or a target-host recovery procedure. Those remain B-07
and B-12 in the [blocker tracker](../blockers-and-build-queue.md).
