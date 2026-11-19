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
