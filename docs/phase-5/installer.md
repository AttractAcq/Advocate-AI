# Synthetic installer and configuration validation

The local installer stages a signed release bundle under an owner-only
installation root. It validates a strict, non-secret configuration, verifies
the bundle against a separately pinned Ed25519 public key, copies it to a
private staging directory, verifies the copy again, and switches the active
release through an atomic state-file replacement. Repeating the same install
is a no-op. A second release keeps the previous one available for a checked
software rollback. `status` re-verifies the active files; a changed staged
file blocks status and reinstall.

The [lab configuration template](../../infrastructure/deploy/lab-config.json)
allows only the six synthetic loopback services, a loopback bind address,
distinct local ports and `public_egress: false`. Extra fields, including
credentials, are rejected. This is configuration validation; it does not
configure a firewall or prove no-egress.

```sh
.venv/bin/python -m infrastructure.deploy.installer validate-config infrastructure/deploy/lab-config.json
.venv/bin/python -m infrastructure.deploy.installer install --bundle /path/to/signed-bundle --trusted-key /path/to/pinned-public-key.pem --config infrastructure/deploy/lab-config.json --root /path/to/new-synthetic-install
.venv/bin/python -m infrastructure.deploy.installer status --root /path/to/new-synthetic-install --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.deploy.installer rollback --root /path/to/new-synthetic-install --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.deploy.installer postcheck --root /path/to/new-synthetic-install --trusted-key /path/to/pinned-public-key.pem --health-config /path/to/local-health.json
```

`postcheck` requires a health probe for every configured service on the
configured loopback port. The probe uses the separately supplied local CA and
returns metadata only. Run it only after starting the synthetic lab. The
installer does not start services, provision PKI, configure containers or
networks, handle secrets, reboot, or recover a failed host. Its rollback
changes the synthetic active pointer; it does not restart a production stack.

## Local rehearsal, 16 November 2026

The [recorded rehearsal](install-rehearsal.json) created two ephemeral signed
fictional bundles, installed the first twice, installed the second, rolled
back, then passed six live loopback health checks. The same rehearsal runs
inside `make lab-smoke` in CI. Unit tests cover invalid config, tampered
bundle, changed staged files, idempotence, rollback and missing health checks.

T-028 and G3 remain open. A target installer needs approved images and model
artifacts, local certificate provisioning, service identities, idempotent
playbooks, real health probes, clean-host offline rehearsal and independent
review. Track those dependencies in the [blocker index](../blockers-and-build-queue.md).
