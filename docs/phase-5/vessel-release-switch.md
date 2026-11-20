# Synthetic vessel release switch and rollback

The `vesselctl` commands below switch a stopped synthetic three-image vessel
installation to a second signed bundle and roll back to the prior signed
bundle. They reuse the checked persistent Knowledge volume and Core state.

1. Capture a coordinated encrypted recovery set using the existing
   [recovery procedure](vessel-recovery-set.md) and retain its signed receipt.
2. Run `vesselctl stop --root ROOT --trusted-key KEY --crane CRANE` and confirm
   the stopped result. If stop was interrupted, use `finish-stop` or `reconcile`
   as appropriate before proceeding.
3. Run `vesselctl switch-stopped --root ROOT --trusted-key KEY --crane CRANE
   --bundle NEW_BUNDLE --console-config CONFIG`.
4. Run `vesselctl status --root ROOT --trusted-key KEY --crane CRANE` and
   check the returned active release ID.
5. For rollback, stop the new runtime and run
   `vesselctl rollback-stopped --root ROOT --trusted-key KEY --crane CRANE`.
   Check status again.

The switch requires a clean stopped runtime with exactly the recorded,
labelled Knowledge data volume. It verifies both the existing signed stage and
new signed bundle, checks the Knowledge schema and full approved source index
before starting Core and Console, and writes the active release record only
after service health checks. A failed candidate retains the old active record
and data volume. If cleanup is interrupted, reconcile the labelled candidate
and recover the old signed release. After complete cleanup, the same signed
candidate can be retried; an existing stage is reused only if its signature
and release identity still verify. A partial or altered stage is rejected and
requires operator investigation. The state records one previous release, so
rollback is one step; after rollback, the newer release becomes the previous
release and can be selected again with the same procedure.

The Linux actual-image rehearsal uses two distinct signed manifests over the
same three image archives to exercise identity, state continuity, signed
activation, and rollback. It does not prove compatibility across different
image versions or database migrations. Production rollback timing, protected
media, key custody, independent assessment, and target hardware remain open.
