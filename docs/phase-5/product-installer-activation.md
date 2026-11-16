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
```

The [CI product image rehearsal](product-image-release-rehearsal.md) creates
two distinct ephemeral signed product versions, installs the first, rejects a
missing candidate while preserving the first, installs the second, and rolls
back to the first. It then stops the Console, restarts the signed active
release through `recover`, and checks health. The rehearsal removes the
disposable containers when finished.

This is still a synthetic lab path. Its state survives the launcher process,
and an operator can explicitly restart a stopped runtime from the signed
staged release. It does not enable boot-time restart or automatically remove
orphaned containers after a host crash, provision TLS or a real identity issuer, load a model, configure
the vessel network, or prove clean-host disaster recovery. The older
[six-service staging installer](installer.md) remains a separate loopback
configuration exercise. Target installation and recovery gates remain in the
[blocker tracker](../blockers-and-build-queue.md).
