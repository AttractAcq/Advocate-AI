# Synthetic scheduled backup and verification

The renderer creates a `sovereign-backup.service` and matching timer for a
daily UTC run. The one-shot service creates an allowlisted restic snapshot,
then requires a recent tagged Sovereign snapshot, checks all repository data
and performs a clean restore into private temporary staging. Its dedicated `sovereign-backup` user,
private network namespace, read-only system view and two allowed write paths
are candidate controls for the Ubuntu lab. The password is loaded as a
systemd credential; its bytes are not placed in the unit or command line.
The renderer writes files but does not install, enable or start them.

Example for an isolated synthetic lab, after creating the service account,
protected staging directory, local repository and owner-held password file:

```sh
.venv/bin/python -m infrastructure.deploy.backup_service \
  --service-output /path/to/new/sovereign-backup.service \
  --timer-output /path/to/new/sovereign-backup.timer \
  --spec /srv/sovereign/spec.json --repository /srv/sovereign/repository \
  --password-source /etc/sovereign/backup-password \
  --restic /usr/local/bin/restic --restic-sha256 '<approved-binary-sha256>' \
  --python /opt/sovereign/.venv/bin/python --workdir /opt/sovereign \
  --staging /srv/sovereign/staging --hour-utc 2 --max-age-hours 24
systemd-analyze verify /path/to/new/sovereign-backup.service /path/to/new/sovereign-backup.timer
```

The timer has `Persistent=true`, so systemd schedules one catch-up run after
an outage. [systemd's timer documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html)
describes this behavior, and its [credential documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html)
documents `${CREDENTIALS_DIRECTORY}`. [Restic documents](https://restic.readthedocs.io/en/stable/040_backup.html)
that recurring invocations need an external scheduler. CI checks unit syntax
on Ubuntu and runs a real pinned-restic snapshot, full data check, clean
restore and stale/empty repository cases with fictional files.

Site approval must set the schedule and age limit, provision the account and
encrypted staging capacity and protected media, monitor timer failures, and validate write permissions and
power-off recovery on target hardware. The synthetic unit covers allowlisted
files and SQLite only. PostgreSQL, Keycloak, model, configuration and Wazuh
state need a coordinated full-stack backup and clean-host recovery procedure;
[AT-16](../05-acceptance-tests.md) remains open.
