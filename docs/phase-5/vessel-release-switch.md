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
requires operator investigation. For a known interrupted staging attempt,
first confirm a clean stop and inspect the candidate directory. Then run
`vesselctl discard-staged-candidate --root ROOT --trusted-key KEY --bundle
NEW_BUNDLE --console-config CONFIG --discard-stage`. This accepts only the
signed input bundle and exact console configuration that identify the staged
candidate. It refuses the active and rollback releases, running resources,
unsafe entries and linked paths. Repeat the switch command after a successful
discard. The state records one previous release, so
rollback is one step; after rollback, the newer release becomes the previous
release and can be selected again with the same procedure.

The Linux actual-image rehearsal builds a second Core image with a different
synthetic release label. It scans and inventories that exact second archive,
signs it into the update bundle, then checks the running Core image changes
on switch and returns to the original image on rollback. Console and Knowledge
images stay the same. This proves image identity and state continuity across
the release switch; the Core application code and database schema are the same
in both images. Compatibility across actual application versions and database
migrations, production rollback timing, protected media, key custody,
independent assessment, and target hardware remain open.
