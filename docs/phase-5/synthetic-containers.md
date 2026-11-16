# Synthetic Core and Console containers

The local packaging rehearsal builds separate Core and Console OCI images. Core
serves FastAPI on port 18100. Console serves the compiled React app on port 8080
and proxies `/api/*` unchanged to Core. The smoke test uses an internal Docker
network, no host-published ports, read-only filesystems, a non-root UID and no
Linux capabilities. It checks static serving, runtime configuration, Core health
and unauthenticated API denial. The images contain only fictional generated
documents and alerts; they are not a production release.
CI retains HIGH/CRITICAL Trivy reports for both built image tags for [triage](product-image-scan.md).
Those reports do not supply the exact digest and signed archive evidence required
by release intake.

```sh
docker build -f infrastructure/containers/Core.Dockerfile -t sovereign-core:synthetic .
docker build -f infrastructure/containers/Console.Dockerfile -t sovereign-console:synthetic .
bash infrastructure/containers/smoke.sh
```

The three base image references are pinned to OCI index digests, resolved on 16
November 2026: Python `3.14-alpine` at
`sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67`,
Node `22-alpine` at
`sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a`,
and Caddy `2-alpine` at
`sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0`.
Python dependencies use the hashed `requirements.lock`; Console uses
`npm ci --ignore-scripts` against its lockfile. The runtime Console image has
neither Node nor the source tree. Its `/console-config.json` must be mounted
separately and is served with `Cache-Control: no-store`.
Core removes pip after installing the locked dependencies; pip and its bundled
packages are build inputs, not runtime dependencies.

The local rehearsal does not establish a production TLS endpoint, approve base
image vulnerability findings or licences, attest a resolved release image, or
prove target GPU/Keycloak/NAS/Wazuh integration. Before distribution, run the
[release intake](release-intake.md) on the exact built digest and complete
the [open gates](../blockers-and-build-queue.md). [Docker's image guidance](https://docs.docker.com/build/building/best-practices/)
supports digest pinning; the [Caddy route documentation](https://caddyserver.com/docs/caddyfile/directives/route)
explains why proxy routes must precede SPA rewriting.
