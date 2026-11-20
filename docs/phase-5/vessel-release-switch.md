# Synthetic vessel release switch and rollback

The `vesselctl` commands below switch a stopped synthetic three-image vessel
installation to a second signed bundle and roll back to the prior signed
bundle. They reuse the checked persistent Knowledge volume and Core state.

1. Run `vesselctl stop --root ROOT --trusted-key KEY --crane CRANE` and confirm
   the stopped result. If stop was interrupted, use `finish-stop` or `reconcile`
   as appropriate before proceeding.
2. Capture a coordinated encrypted recovery set using the existing
   [recovery procedure](vessel-recovery-set.md). Retain its signed receipt,
   verification key, password and repository. The switch requires a schema-2
   receipt with a Knowledge row digest and clean-restores the exact pre-update
   set before staging a release.
3. Run `vesselctl switch-stopped --root ROOT --trusted-key KEY --crane CRANE
   --bundle NEW_BUNDLE --console-config CONFIG --recovery-receipt RECEIPT
   --receipt-key RECEIPT_KEY --password-file BACKUP_PASSWORD --restic RESTIC
   --restic-sha256 RESTIC_SHA256 --staging-parent PRIVATE_STAGING`.
4. Run `vesselctl status --root ROOT --trusted-key KEY --crane CRANE` and
   check the returned active release ID.
   After accepting the updated release, stop it and capture a new encrypted
   recovery set. Its signed receipt must name the updated release. Keep the
   pre-update set until the approved retention policy permits removal.
5. For rollback, stop the current runtime and capture a new encrypted recovery
   set for that active release. Keep its signed receipt, repository, password
   and verification key. Run `vesselctl rollback-stopped --root ROOT
   --trusted-key KEY --crane CRANE --recovery-receipt UPDATED_RECEIPT
   --receipt-key RECEIPT_KEY --password-file BACKUP_PASSWORD --restic RESTIC
   --restic-sha256 RESTIC_SHA256 --staging-parent PRIVATE_STAGING`.
   Check status again.

Both switch and rollback require a clean stopped runtime with exactly the recorded,
labelled Knowledge data volume. It verifies both the existing signed stage and
new signed bundle. Both must declare the supported Knowledge schema and Core
state format in their signed compatibility contract. An unsupported candidate
is rejected before its stage is created. Before staging, the switch verifies
that the signed recovery receipt names the current installation, release and
Knowledge data volume. It checks the encrypted repository, clean-restores the
set into private temporary staging, then compares the restored Core files with
a fresh stopped-state snapshot. A missing, mismatched or unrestorable set stops
the transition before candidate staging or rollback activation. During activation, it checks live
Knowledge source and passage counts and a canonical digest of every schema-1
Knowledge row against the recovery receipt. A same-count change to a source,
passage, vector or schema row is rejected. The switch
also checks the live Knowledge schema and full approved source index
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
images stay the same. Both signed releases declare schema 1 compatibility.
At first install, after the switch, and after rollback,
the rehearsal also asks the running Core API whether the engineer can find the
fictional engineering document and the deckhand cannot list, search or preview
it. The clean restore rehearsal repeats that permission check against the
restored database and policy files. This proves those synthetic role checks
and image identity across the release switch; the Core application code and
database schema are the same in both images. Compatibility across actual
application versions and database migrations, production rollback timing,
protected media, key custody, independent assessment, and target hardware
remain open.
