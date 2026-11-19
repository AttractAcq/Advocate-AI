# Separate signed Fleet release candidate

Fleet is a company-side service and does not ship in the strict vessel image.
Its offline release bundle uses schema 5 with `target: fleet` and exactly two
image descriptors, `fleet-api` and `fleet-portal`. Each descriptor binds an
`images/<role>.tar` archive, digest-pinned image reference, generated Syft
inventory and Trivy scan. The existing release intake rejects missing or stale
evidence and unresolved HIGH, CRITICAL or UNKNOWN findings. The signer checks
both archives with the pinned crane binary before signing. The verifier checks
the detached Ed25519 signature, exact file inventory and signed evidence.

The descriptor JSON has exactly `fleet-api` and `fleet-portal` keys, each
using the same fields as the schema-4 product descriptor. After preparing the
approved archives and evidence:

```sh
.venv/bin/python -m infrastructure.release.bundle pack-fleet \
  /path/to/payload /path/to/new-fleet-bundle \
  --signing-key /protected/fleet-release-key.pem --version VERSION \
  --images-json /path/to/fleet-images.json --crane /path/to/pinned/crane
.venv/bin/python -m infrastructure.release.bundle verify \
  /path/to/new-fleet-bundle --trusted-key /protected/fleet-trust-key.pem
```

This is a local software candidate. The Fleet release signing authority,
production vulnerability policy, company deployment topology and independent
review remain under B-12. A schema-5 Fleet bundle cannot be imported as a
schema-4 vessel release or passed to the vessel product installer.

The CI Fleet image rehearsal builds the actual API and portal images, saves
their archives, obtains manifest digests with crane, generates Syft inventory
and an offline-database Trivy scan, then attempts the schema-5 signature. If
either image has unresolved HIGH, CRITICAL or UNKNOWN findings, the expected
result is `denied-findings` and no signed bundle. Its metadata-only result,
scan and inventory files are retained as CI artifacts; temporary signing keys
and image archives are not published by the rehearsal. This is evidence of
the software path, not approval to distribute an image.

[PR #60's CI evidence](https://github.com/AttractAcq/Advocate-AI/actions/runs/44091882326)
reported `fleet_bundle: verified`: both actual synthetic Fleet images passed
archive identity and intake with zero unresolved HIGH, CRITICAL or UNKNOWN
findings. This result applies only to those CI-built image digests.

The synthetic Fleet installer stages a verified schema-5 bundle under an
owner-only root, preserves the private state directory across versions and launches both
images on a private Docker network. A candidate becomes active only after the
API and same-origin portal pass health and permission probes. The prior
release remains staged for rollback; recovery restarts the signed active
release after a stopped service. On first installation, supply an owner-only
lab token source. Later updates reuse the installed token and database:

```sh
.venv/bin/python -m infrastructure.deploy.fleet_installer install \
  --bundle /path/to/signed-fleet-bundle --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane --config /path/to/fleet-config.json \
  --root /private/fleet-install --token-file /protected/fleet-lab-token \
  --receipt-trust-dir /protected/receipt-issuers
.venv/bin/python -m infrastructure.deploy.fleet_installer status \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem
.venv/bin/python -m infrastructure.deploy.fleet_installer rollback \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane
```

The local runtime publishes no host port. The CI image rehearsal uses the
no-issuer lab configuration and exercises install, rejected candidate, update,
rollback and recovery only when both images pass intake.

To enable signed offline receipt import on an installed Fleet API, prepare an
owner-only `--receipt-trust-dir` before the first install or a clean
`restore-install`. It must contain only `trusted-issuers.json` and one to four
owner-only Ed25519 public PEM files named `issuer-1.pem` through
`issuer-N.pem`. The JSON array must list their container paths in that order,
for example `["/etc/fleet-import/issuer-1.pem", "/etc/fleet-import/issuer-2.pem"]`.
The installer copies and validates this directory under its private root.
The API container sees it at `/etc/fleet-import` through a read-only bind
mount, and runtime identity checks reject mount, environment or public-key
content drift. The private signing keys stay on the offline issuer
workstation. Receipt trust is
outside the encrypted Fleet catalog backup, so supply the approved trust
directory again during a clean restore. Trust changes to a running installation
use `rotate-receipt-trust` with a new approved directory. The command copies
and checks the new trust, starts the active signed release with the candidate
trust, commits only after the candidate passes, and then retires the old
runtime. Its owner-only journal makes interrupted rotation visible; `status`,
`install` and `rollback` fail closed until `recover` reconciles the old or new
runtime. Editing installed trust files in place is rejected by the runtime
identity check.

```sh
.venv/bin/python -m infrastructure.deploy.fleet_installer rotate-receipt-trust \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane \
  --receipt-trust-dir /protected/approved-next-issuers
```

For an overlap window, provide both old and new public keys. After receipts
signed by the new issuer have been proven, use a second rotation containing
only the new public key. Keep each source directory owner-only and separate
from the installed trust directory. This local operation does not establish
company issuer approval, revocation timing, protected media or target-host
reboot recovery; those remain B-12.

The signed-image CI rehearsal now attempts both rotations against actual
Fleet containers. It imports receipts from both issuers during overlap,
rejects an old-issuer receipt after retirement, then checks update, rollback,
boot recovery and encrypted catalog restore under the retired trust set.
The signed Fleet image CI rehearsal now provisions a fictional issuer,
submits its CLI-signed coded receipt through the running API container, and
checks that the receipt survives encrypted catalog restore with separately
reprovisioned trust. This remains a synthetic offline handoff rehearsal.

The OIDC signed-image rehearsal also installs the same receipt trust in the
company identity mode. It submits a CLI-signed receipt to the running Fleet
API with a signed company administrator token, rejects a wrong-audience token,
and checks that the receipt is stored. A local scoped-role test additionally
denies support users, foreign-customer imports, unknown issuers and replay.
These tests use fictional company identities and do not close B-12 identity
or offline handoff governance.

The OIDC runtime candidate accepts a company HTTPS issuer in
`fleet-config.json`. Before installation, a company administrator provisions a
separate Docker network that is internal and labelled
`sovereign.fleet.identity=true`, attaches the company Keycloak endpoint to it
under the issuer's DNS name, and supplies an owner-only Fleet roles file. Only
the API container joins this identity network. The portal stays on the
private Fleet network; both containers have no host port. The installer copies
the roles file outside the writable catalog volume, mounts it read-only in
the API, and never copies a lab token into OIDC mode. Candidate health checks
verify the portal config, reject unauthenticated and lab-token requests, and
retrieve the issuer's JWKS over certificate-validated HTTPS. The network
name is retained through update, rollback and boot recovery.

```sh
docker network create --internal --label sovereign.fleet.identity=true fleet-identity
.venv/bin/python -m infrastructure.deploy.fleet_installer install \
  --bundle /path/to/signed-fleet-bundle --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane --config /path/to/fleet-https-config.json \
  --root /private/fleet-install --roles-file /protected/fleet-roles.json \
  --identity-network fleet-identity --ca-file /protected/company-idp-ca.pem
```

`--ca-file` is optional when the IdP certificate chains to the image's system
trust store. When supplied, the installer copies the owner-only CA certificate
into the private identity directory, mounts it read-only into the API, and
uses it for JWKS verification and the activation health probe. The catalog
backup excludes this CA and the roles file; recovery requires separate
trusted copies. CA rotation and final company trust policy remain B-12 gates.

The external identity endpoint and browser TLS ingress must exist before this
command can pass health checks. The command does not create them. Production
IdP configuration, certificate trust, MFA, operator ingress and network
policy still require company approval and target validation under B-12.

The actual-image CI release rehearsal also creates a temporary private CA and
HTTPS JWKS service on a labelled internal identity network. It installs the
same signed Fleet images in OIDC mode, checks a signed Fleet-audience token,
rejects a Core-audience token, and confirms status fails when the IdP stops.
The synthetic rotation rehearsal first proves that replacing the installed CA
before the IdP changes fails closed and keeps the old runtime. It then overlaps
old and new CA certificates and JWKS signing keys, verifies both tokens,
switches the IdP certificate, removes the old trust, and verifies that the old
token and old CA are rejected. Each CA change uses the installer's `rotate-ca`
operation to start a candidate from the active signed bundle. The operation
checks that the replacement is an owner-only file containing current CA
certificates, probes the existing runtime, stages the new trust, and writes the
active state only after the candidate passes the signed runtime checks. A
failed candidate restores the old CA file and leaves the old runtime active.
The new API instance clears the five-minute JWKS cache at signing-key cutover.

```sh
.venv/bin/python -m infrastructure.deploy.fleet_installer rotate-ca \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane --ca-file /protected/next-company-idp-ca.pem
```

Stage an overlapping CA bundle before changing the IdP certificate. After
the IdP serves the new certificate and signing key, rotate to the new-only CA
bundle. The local rehearsal checks rejected candidate rollback, overlapping
trust, cutover and stale-trust denial. An owner-only journal records the old
CA and runtime before staging. `status`, `install` and `rollback` stop if a
rotation is interrupted. `recover` restores the old CA when the old runtime
is still active, or verifies the committed candidate before retiring the old
runtime. If the committed candidate is unhealthy after a process crash,
recovery fails closed and leaves the journal for operator investigation.
Company CA custody, approved rollover timing, target ingress and interrupted
host-reboot rehearsal remain B-12.
The signed-image CI rehearsal also injects a synthetic process interruption
on each side of active-state replacement. It requires status to stop on the
journal, restores the previous CA and API before commit, and after commit
verifies the candidate before removing the old API and portal containers. It
then checks authorised access again. This covers process interruption on a
running Docker host; a physical reboot and protected-media restore still need
target hardware.
The synthetic runner maps that temporary IdP hostname to its private network
address because the hosted Linux Docker runner does not resolve its network
alias from the two-network API container. This mapping is confined to the
rehearsal; target DNS and network routing remain pilot acceptance checks.
Ephemeral CA, keys and tokens are deleted; retained evidence contains only
result codes. This synthetic service is not a Keycloak interoperability or
browser TLS acceptance test.

[PR #67's signed-image CI run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44150682876/job/134277834972)
reports `oidc_runtime: synthetic-https-token-authorized`,
`wrong_audience: denied` and `idp_outage: status-failed-closed`.

[PR #61's retained CI result](https://github.com/AttractAcq/Advocate-AI/actions/runs/44093561479)
reports `fleet_bundle: verified`, `failed_candidate: previous-runtime-preserved`,
`update: healthy-candidate-activated`, `rollback: previous-release-restored`
and `recovery: signed-release-restarted` for the actual CI-built images. The
synthetic images had zero unresolved HIGH, CRITICAL or UNKNOWN findings in
that run. This does not establish production readiness for company identity,
TLS, backup or operator access.

The local Fleet backup command verifies the catalog audit chain, snapshots
only `fleet.db` through the existing SQLite-safe backup code and encrypts it
with AES-256-GCM. It excludes the lab token, signing keys and portal config.
An OIDC roles file and the identity network are also outside the encrypted
catalog archive and must be reprovisioned separately during recovery.
Restore authenticates into a new private directory and verifies the catalog
again before the signed installer starts. The token is provisioned separately:

```sh
.venv/bin/python -m infrastructure.deploy.fleet_backup backup \
  --db /private/fleet-install/state/fleet.db \
  --output /private/backups/fleet.svb --key /protected/fleet-backup.key
.venv/bin/python -m infrastructure.deploy.fleet_installer restore-install \
  --archive /private/backups/fleet.svb --backup-key /protected/fleet-backup.key \
  --bundle /path/to/signed-fleet-bundle --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane --config /path/to/fleet-config.json \
  --root /private/new-fleet-install --token-file /protected/fleet-lab-token
```

The synthetic daily backup candidate creates a new timestamped encrypted
archive and immediately performs an authenticated clean restore of the newest
archive, including the Fleet audit-chain check. It fails if no archive exists,
the newest one is stale or damaged, or the archive count reaches the configured
limit. The timer never deletes an archive. The service creates an owner-only
`.fleet-backup.lock` in the archive directory, shared with the manual retention
command. An owner-approved production retention policy and protected storage
capacity are still required. Render the units into a private
staging directory, review them, and validate with `systemd-analyze verify`
on a compatible host before installation. The `sovereign-fleet` service user
must own the catalog, archive directory and key source. The timer and service
names are fixed so the timer cannot point at a different unit.

```sh
.venv/bin/python -m infrastructure.deploy.fleet_backup_service render \
  --service-output /private/unit-staging/sovereign-fleet-backup.service \
  --timer-output /private/unit-staging/sovereign-fleet-backup.timer \
  --db /private/fleet-install/state/fleet.db --directory /private/backups \
  --key /protected/fleet-backup.key --python /opt/sovereign/.venv/bin/python \
  --workdir /opt/sovereign --hour-utc 3 --max-age-hours 26 \
  --max-archives 30
```

The manual synthetic retention command takes an owner-only JSON policy such as
`{"schema":1,"keep_last":2,"max_age_hours":26}`. `plan` records the exact
archive names, sizes and SHA-256 digests in a new owner-only file outside the
archive directory; it deletes nothing. Review its `retain` and `remove` lists,
then supply the printed plan digest to `apply` within 24 hours. `apply` rejects
changed policy bytes, archive inventory or directory identity and clean-restores
every retained encrypted archive before deleting the listed older archives.
The latest retained archive must meet the policy freshness limit. A failed
restore leaves every archive in place. If deletion is interrupted, inspect the
remaining set and make a new plan; there is no automatic retry or rollback.

```sh
.venv/bin/python -m infrastructure.deploy.fleet_backup_retention plan \
  --directory /private/backups --policy /protected/fleet-retention.json \
  --output /protected/fleet-retention-plan.json
.venv/bin/python -m infrastructure.deploy.fleet_backup_retention apply \
  --directory /private/backups --policy /protected/fleet-retention.json \
  --plan /protected/fleet-retention-plan.json --plan-sha256 REVIEWED_DIGEST \
  --key /protected/fleet-backup.key
```

The minimum keep count of two is a software guard, not an approved retention
period. The company must approve policy, archive media, legal holds and key
custody before this process can govern production backups. Target systemd and
protected-media behavior remain unverified.

The actual-image Fleet release rehearsal now creates three encrypted catalog
archives against a three-archive limit, confirms that a fourth is refused,
reviews and applies an exact plan retaining the newest two, creates another
archive, verifies its clean restore and uses it for the second signed Fleet
installation. The retained result field is
`archive_retention: reviewed-plan-applied-and-backup-resumed`. This exercises
the host-side retention command with a catalog produced by the signed Fleet
runtime; it does not establish an approved production retention policy.

For boot recovery, render the Fleet one-shot unit into the same private staging
area and validate it before installation. It waits for Docker, requires an
installed Fleet state file, restarts the signed active release if unhealthy,
then runs the full status probe. The service account must own the installation
root and have access to the local Docker socket; that privilege and the host
unit placement need target review. CI validates the unit syntax and calls the
same recover/status CLI against actual synthetic Fleet images after stopping
the portal. This is not a physical reboot test.

```sh
.venv/bin/python -m infrastructure.deploy.fleet_boot_service \
  --output /private/unit-staging/sovereign-fleet-recover.service \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane --python /opt/sovereign/.venv/bin/python \
  --workdir /opt/sovereign
```

This synthetic software path uses owner-only staging but has no approved
production backup media, retention, key custody or timed recovery runbook.
Those remain B-12 gates. CI checks that a fictional customer survives a clean
restore and that the restored signed runtime is healthy.

[PR #62's retained CI result](https://github.com/AttractAcq/Advocate-AI/actions/runs/44095382392)
reports `encrypted_recovery: fictional-customer-restored` after a clean
database restore and signed runtime activation. The same run retained the
verified bundle, failed-candidate, update, rollback and recovery results.
