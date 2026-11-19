# Synthetic product recovery set

`python -m infrastructure.deploy.product_recovery_set create` takes a Core
state snapshot and an upload quarantine snapshot from a stopped installed
product. It requires a reachable Docker daemon, verifies that the recorded
Core and Console containers are absent or stopped, and holds the installer,
policy and upload directory locks throughout capture. The snapshots use
separate encrypted restic repositories. The command writes a private Ed25519
signed receipt containing both exact snapshot IDs, repositories, installation
and release IDs, runtime IDs, and the UTC capture window. `verify` checks the
signature and payload before an operator selects the pair for restore.

The actual-image CI rehearsal verifies the receipt and restores that pair into
a clean second signed product installation. A failed second snapshot leaves no
receipt; the first encrypted snapshot may remain in its repository and needs
ordinary retention handling. The receipt does not contain backup passwords.

This is a synthetic local recovery point for the current Core state and upload
quarantine. It does not freeze external PostgreSQL, Keycloak, model services,
Wazuh or NAS data, and cannot prevent an operator outside this installer from
starting containers during capture. Protected media, key custody, target host
timing and full vessel consistency remain open in the
[blocker tracker](../blockers-and-build-queue.md).
