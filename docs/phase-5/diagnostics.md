# Local health diagnostics

`python -m scripts.diagnose --lab` checks each running Phase 1 synthetic
service over loopback HTTPS using the lab CA. It exits 0 only when every
configured probe returns the expected service name and `status: ok`.
`make lab-diagnose` is the equivalent shortcut when the lab is running.

For another isolated lab, pass `--config /path/to/health.json`. The file has
schema 1, mode `local`, a private numeric CIDR allowlist, and named HTTPS or
SQLite checks. An HTTPS check requires an explicit local numeric address,
`/health`, a CA file, and an expected service name. A SQLite check opens an
existing database read-only and runs `PRAGMA quick_check(1)`.

```json
{
  "schema": 1,
  "mode": "local",
  "allowed_cidrs": ["127.0.0.0/8"],
  "checks": [
    {
      "name": "core",
      "kind": "https",
      "url": "https://127.0.0.1:18081/health",
      "ca_file": "/path/to/trusted-lab-ca.pem",
      "expected_service": "core"
    },
    {"name": "knowledge_store", "kind": "sqlite", "path": "/path/to/knowledge.db"}
  ]
}
```

All configured targets are validated before any probe starts. The HTTP client
does not use environment proxies or follow redirects. It accepts only a small
JSON response, and the output contains check names, types and fixed status
codes; it never prints endpoints, response bodies, credentials or database
contents. Keep check names generic because they appear in the report.

This is a diagnostic building block, not an egress control or a production
readiness gate. The synthetic lab has a Wazuh **simulator** and no qualified
model service. Real Wazuh, model, PostgreSQL, Keycloak, TLS, storage and
network checks must be configured and tested on the target topology. An
absent component cannot be treated as healthy simply because it was omitted
from the configuration. See the [blocker and build queue](../blockers-and-build-queue.md).

## Local verification, 16 November 2026

At the `phase5/health-diagnostics` branch, `make check` passed 56 tests and
the repository checks. With `make lab-up` running, `make lab-diagnose` reported
six of six synthetic services `verified` and exited 0. This result covers only
the loopback simulator and is not AT-10, AT-11, AT-12 or G2 evidence.
