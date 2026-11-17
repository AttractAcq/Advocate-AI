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
  --root /private/fleet-install --token-file /protected/fleet-lab-token
.venv/bin/python -m infrastructure.deploy.fleet_installer status \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem
.venv/bin/python -m infrastructure.deploy.fleet_installer rollback \
  --root /private/fleet-install --trusted-key /protected/fleet-trust-key.pem \
  --crane /path/to/pinned/crane
```

The local runtime publishes no host port. The CI image rehearsal uses the
no-issuer lab configuration and exercises install, rejected candidate, update,
rollback and recovery only when both images pass intake.

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
  --identity-network fleet-identity
```

The external identity endpoint and browser TLS ingress must exist before this
command can pass health checks. The command does not create them. Production
IdP configuration, certificate trust, MFA, operator ingress and network
policy still require company approval and target validation under B-12.

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
limit. It never deletes an archive: an owner-approved retention policy and
protected storage capacity are still required. Render the units into a private
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
