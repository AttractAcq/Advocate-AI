# Synthetic product installer activation

The two-image product installer stages a signed schema-4 Core and Console
bundle in an owner-only directory. It checks the bundle and a strict synthetic
Console configuration, then launches the exact verified archives on an
internal Docker network. The active release record changes only after both
services pass their health checks. A failed candidate or failed state write
leaves the previous runtime active. Repeating an install checks the running
release and returns `unchanged`. Rollback restarts the staged previous bundle,
checks it, changes the active record, and retires the replaced runtime.

```sh
.venv/bin/python -m infrastructure.deploy.product_installer install \
  --bundle /path/to/signed-product-bundle \
  --trusted-key /path/to/pinned-public-key.pem \
  --crane /path/to/pinned-crane \
  --console-config /path/to/synthetic-console-config.json \
  --root /path/to/new-synthetic-product-install
.venv/bin/python -m infrastructure.deploy.product_installer status \
  --trusted-key /path/to/pinned-public-key.pem \
  --root /path/to/new-synthetic-product-install
.venv/bin/python -m infrastructure.deploy.product_installer rollback \
  --trusted-key /path/to/pinned-public-key.pem \
  --crane /path/to/pinned-crane \
  --root /path/to/new-synthetic-product-install
.venv/bin/python -m infrastructure.deploy.product_installer recover \
  --trusted-key /path/to/pinned-public-key.pem \
  --crane /path/to/pinned-crane \
  --root /path/to/new-synthetic-product-install
.venv/bin/python -m infrastructure.deploy.product_installer cleanup-orphans \
  --trusted-key /path/to/pinned-public-key.pem \
  --root /path/to/new-synthetic-product-install
```

For a synthetic Core state restored from restic, the first `install` can also
specify `--core-state /path/to/restored` and
`--lab-password-file /path/to/owner-only-lab-password`. The installer validates
both paths and writes only their canonical paths to an owner-only mount record.
It does not copy the credential into the signed release or backup. Later
installs, rollback and `recover` reuse those paths automatically. `status`
checks the running Core's bind sources, read/write flags, user and environment;
a missing or changed mount fails the check. This mount record is fixed for the
synthetic installation, so changing state locations requires a separate
reviewed migration instead of an implicit install option.

The [CI product image rehearsal](product-image-release-rehearsal.md) creates
two distinct ephemeral signed product versions, installs the first, rejects a
missing candidate while preserving the first, installs the second, and rolls
back to the first. It then stops the Console, restarts the signed active
release through `recover`, checks health, and verifies that the previous
labelled runtime was retired. It also starts the first release with cleanly
restored fictional Core state and verifies that its permissions and history
persist through update, rollback and recovery. The rehearsal removes the disposable containers
when finished.

Each new install root gets an owner-only random installation identifier. New
Core, Console and internal network resources carry that identifier and a
separate per-run label. `cleanup-orphans` verifies the signed active stage and
healthy active runtime, checks all scoped Docker identities before deletion,
then removes only resources outside the active pair. The CI rehearsal starts
a second signed runtime without recording it, removes it through this command,
and checks that the active pair remains healthy. Docker's documented
[network](https://docs.docker.com/reference/cli/docker/network/ls/) and
[container](https://docs.docker.com/reference/cli/docker/container/ls/) label
filters provide the initial scope; the installer rechecks each result.

This is still a synthetic lab path. Its state survives the launcher process,
and an operator can explicitly restart a stopped runtime from the signed
staged release. Recovery retires the previous containers only when their
labels and network attachment still match the saved record. It does not
enable boot-time restart or automatically remove unlabelled resources created
before this change, provision TLS or a real identity issuer, load a model, configure
the vessel network, or prove clean-host disaster recovery. The
[synthetic boot unit renderer](boot-recovery-service.md) prepares a systemd
recovery unit for later target-host validation. The older
[six-service staging installer](installer.md) remains a separate loopback
configuration exercise. Target installation and recovery gates remain in the
[blocker tracker](../blockers-and-build-queue.md).
