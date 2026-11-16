# Installation and handover SOP — synthetic lab

**Owner:** installation engineer. **Witness:** separate QA or security reviewer for a gate run. The commands below stage a signed fictional bundle in a local directory. They do not install or start the full service stack. The engineer must use an approved site method statement, qualified equipment and signed release before a real deployment.

## Before work

1. Record change ID, authorised window, rollback owner and build ID. Check the [handover fields](operator-engineer-pack.md#handover-record-to-fill-for-each-installation). If any required approval or artifact is absent, stop and record **not run**.
2. Confirm that payload and public verification key arrived through separately approved channels. Check approved provenance, resolved SBOM, media scan and manifest hash outside this synthetic procedure. Do not carry a release private signing key to the installation host.
3. Confirm the lab is isolated and contains only fictional data. For a vessel, obtain approved site topology, source/ACL matrix, route rules, certificates, backup design and owner permission first; [B-06, B-09 and B-10](../blockers-and-build-queue.md) remain open.

## Local staging sequence

Run from the repository root with paths replaced by disposable lab paths. The bundle must already have been packed and signed according to the [offline release procedure](../phase-5/offline-release.md).

```sh
.venv/bin/python -m infrastructure.deploy.installer validate-config infrastructure/deploy/lab-config.json
.venv/bin/python -m infrastructure.release.bundle verify /path/to/signed-bundle --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.deploy.installer install --bundle /path/to/signed-bundle --trusted-key /path/to/pinned-public-key.pem --config infrastructure/deploy/lab-config.json --root /path/to/new-synthetic-install
.venv/bin/python -m infrastructure.deploy.installer status --root /path/to/new-synthetic-install --trusted-key /path/to/pinned-public-key.pem
```

Record the command exit codes, bundle and trust-key fingerprints, active version and installation root in the controlled lab evidence store. `status` verifies staged files; it does not prove that application services run. Repeating an identical install is a no-op.

## Post-install and failure decision

Only after the six synthetic loopback services are started, run the postcheck with a separately prepared local health configuration:

```sh
.venv/bin/python -m infrastructure.deploy.installer postcheck --root /path/to/new-synthetic-install --trusted-key /path/to/pinned-public-key.pem --health-config /path/to/local-health.json
```

A failed signature, unexpected file, invalid configuration, failed status or missing health check stops handover. Preserve metadata-only diagnostic output and defect ID; do not treat a partial result as a pass. For a previously installed synthetic release, use the checked pointer rollback in [maintenance and recovery](maintenance-and-recovery.md); that rollback does not restart services or restore their data.

## Acceptance and handover

Attach the build/manifest identifiers, test record, health output, defects and witness decision to the [pack record](operator-engineer-pack.md#handover-record-to-fill-for-each-installation). Demonstrate the [training exercise](operator-engineer-pack.md#training-exercise). Mark the synthetic stage **locally checked** only. G3 requires a clean-room offline install on qualified equipment, functioning service rollback, full recovery, site configuration and independent security review. See [B-07 to B-09](../blockers-and-build-queue.md).
