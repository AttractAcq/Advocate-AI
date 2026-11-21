# Signed three-image runtime with persistent Knowledge

This page records the earlier schema-6 runtime candidate. The later
[first-install path](signed-vessel-first-install.md) and
[signed model artifact](model-artifact-bundle.md) extend it; use those records
for the current synthetic installation contract.

The vessel runtime candidate starts Core and Console only from their archives
in a verified schema-6 vessel bundle. It requires a running Knowledge handle
created from the same signed bundle. Knowledge keeps its database on a labelled
persistent volume, has no network attachment, and exposes only a private Unix
socket volume to Core. Core and Console use an internal Docker network without
published host ports.

Core mounts an owner-only synthetic source tree, a separate lab credential,
and the reader passfile. The runtime verifies the approved manifest and policy,
the Knowledge container, data and socket volume identities, the Core mount
sources and read/write flags, the configured PostgreSQL URI, and the read-only
database role. It checks Core and Console health, Console proxy authentication,
and that Core can read the indexed knowledge table as `sovereign_read`.

The actual-image CI rehearsal indexes two fictional sources with the separate
ingestion passfile, stops and restarts the signed Knowledge container, then
starts Core and Console against the restarted database. It records the live
result in the metadata-only three-image evidence artifact.

The product installer now records all three containers and the labelled
Knowledge and socket volumes in its active state. It uses separate migration
and ingestion authority; [stopped release switching](vessel-release-switch.md)
and a [coordinated encrypted recovery set](vessel-recovery-set.md) have synthetic
actual-image rehearsals. Target-host boot, storage encryption, approved model
and identity provisioning, licensing and independent review remain open.
