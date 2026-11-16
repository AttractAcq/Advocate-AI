# Synthetic boot recovery unit

The unit renderer takes the installed product root, trusted public key,
pinned crane binary, Python environment and application directory as absolute
paths. It writes a new owner-only `.service` file; it does not install,
enable or start it. The unit is a systemd `oneshot` ordered after and
requiring `docker.service`. It runs the existing `recover` command once when
the host reaches `multi-user.target`, provided a product state record exists.
The [systemd unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit)
and [service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service)
manuals define this ordering and `oneshot` behavior.

```sh
.venv/bin/python -m infrastructure.deploy.boot_service \
  --output /path/to/new/sovereign-synthetic-recover.service \
  --root /path/to/installed-product \
  --trusted-key /path/to/pinned-public-key.pem \
  --crane /path/to/pinned-crane \
  --python /path/to/product-python \
  --workdir /path/to/product-application
systemd-analyze verify /path/to/new/sovereign-synthetic-recover.service
```

The CI product-image rehearsal renders the unit against a real synthetic
installation and runs `systemd-analyze verify` on Ubuntu. The unit is not
enabled in CI, so this proves syntax and dependency declaration only. A
target-host reboot, Docker readiness, service account and Docker socket
privileges, timeout, recovery latency, orphan cleanup, and health monitoring
still need site-specific validation. `oneshot` does not continuously monitor
the running containers.
