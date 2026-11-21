# Synthetic vessel boot recovery unit

`infrastructure.deploy.vessel_boot_service` renders a site-specific systemd
unit for an already installed, signed synthetic vessel release. Rendering does
not install or enable the service. It requires explicit absolute paths and a
non-root service account, then writes a new owner-only
`sovereign-vessel-recover.service` file. For example:

```sh
.venv/bin/python -m infrastructure.deploy.vessel_boot_service \
  --output /tmp/sovereign-vessel-recover.service \
  --root /var/lib/sovereign-vessel \
  --core-state /var/lib/sovereign-core-state \
  --trusted-key /etc/sovereign/vessel-trusted.pem \
  --crane /opt/sovereign/bin/crane \
  --python /usr/bin/python3 --workdir /opt/sovereign/app \
  --user sovereign-vessel --group sovereign-vessel
```

The unit runs after Docker and only when `vessel-state.json` exists. It calls
the existing `vesselctl finish-stop` operation first. That command verifies the
signed stage and the exact recorded Docker identities before removing a
partially stopped runtime, retaining the Knowledge data volume. The unit then
calls `recover` from the signed stage and finally `status`; any failed command
fails the unit. It cannot bootstrap an empty installation or accept a new
release at boot. The unit grants write access only to the installation and
external Core state paths through its systemd filesystem sandbox.

The chosen service account must own the installation and external Core state,
read the trusted key and pinned crane binary, and have access to the Docker
socket. Docker socket access is highly privileged; the target host must
approve and test this account and its group membership. The lab renderer does
not configure that account, enable the unit, test a physical reboot, or prove
model and identity services are ready after boot. CI checks the rendered unit
syntax on Linux; the signed actual-image rehearsal separately exercises the
vessel stop and recovery commands. Target boot, service privileges, protected
storage and independent review remain under B-07/B-09.
