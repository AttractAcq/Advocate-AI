# Synthetic product recovery set

`python -m infrastructure.deploy.product_recovery_set create` takes a Core
state snapshot and an upload quarantine snapshot from a stopped installed
product. It requires a reachable Docker daemon, verifies that the recorded
Core and Console containers are absent or stopped, and holds the installer,
policy and upload directory locks throughout capture. The snapshots use
separate encrypted restic repositories. The command writes a private Ed25519
signed receipt containing both exact snapshot IDs, repositories, installation
and release IDs, runtime IDs, the UTC capture window, and the audit sequence
and tail hash. The version 2 receipt records the verified audit checkpoint
before and after capture and refuses a changed trail. `verify` checks the
signature and payload. `restore` checks the signed receipt and the product
bundle's release identity, then passes exactly those snapshot IDs and
repositories to the clean installer. The Core snapshot includes the installed
hash-chained audit trail. Capture refuses a missing, exposed, or invalid trail;
receipt-bound restore requires its sequence and tail hash to match the signed
checkpoint before activation.
When an installed Core also has a Phase 3 `knowledge-manifest.json` and
`knowledge.db`, capture requires both and includes both in the Core snapshot.
The index is taken as a SQLite snapshot; the signed runtime pins both paths in
its environment after restore.
The Core source inventory comes from its synthetic `manifest.csv`. Capture
requires every listed source to be a regular flat file with the listed SHA-256,
rejects missing or extra files, and includes each listed source in the encrypted
snapshot. Receipt-bound restore repeats that check and requires the snapshot
file count to match the restored source inventory before runtime activation.
Capture copies the manifest and its sources into a private owner-only staging
directory, rechecks their digests there, and gives that frozen copy to restic.
Before staging, it estimates the manifest and source file bytes and requires
that space plus a 128 MiB reserve on the staging volume. This is a source-copy
preflight; restic's later staging and repository peaks still need a separate
capacity check.
It checks the live source inventory and manifest again before signing the
receipt; a change during capture leaves no receipt. This guards the synthetic
source pair against an external writer while restic copies it. The knowledge
index, other services and vessel NAS still need a coordinated production
snapshot procedure.
This path is bounded to 122 sources of at most 8 MiB each (the current fixture
has 100); larger vessel datasets require a separate production design.

The actual-image CI rehearsal verifies the receipt and restores that pair into
a clean second signed product installation. It checks that the restored trail
starts with every pre-capture audit byte and continues recording API requests.
A failed second snapshot leaves no
receipt; the first encrypted snapshot may remain in its repository and needs
ordinary retention handling. The receipt does not contain backup passwords.

This is a synthetic local recovery point for the current Core state and upload
quarantine. It does not freeze external PostgreSQL, Keycloak, model services,
Wazuh or NAS data, and cannot prevent an operator outside this installer from
starting containers during capture. Protected media, key custody, target host
timing and full vessel consistency remain open in the
[blocker tracker](../blockers-and-build-queue.md).
The signed receipt can act as an audit checkpoint only if its signing key and
receipt are held outside Core's control. Approved off-host custody, retention,
periodic checkpoints and target-host testing remain required before a vessel
pilot.
