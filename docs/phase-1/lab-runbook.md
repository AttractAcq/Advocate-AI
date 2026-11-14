# Phase 1 synthetic lab runbook

## Local bring-up

Prerequisite: Python 3.11 or newer and `make`. This repository's Phase 1 skeleton has no package downloads.

1. From the repository root, run `make fixtures`.
2. Run `make check` for deterministic source build, unit tests, corpus hashes and link checks.
3. Run `make lab-up` in a terminal. Six probes bind to IPv4 loopback only.
4. In another terminal, run `make lab-check`. The Console placeholder is at `http://127.0.0.1:18080/`; each service responds to `/health` and `/metrics`.
5. Stop the first command with Ctrl-C. `make lab-smoke` starts, checks and stops the services automatically.

The topology and ports live in [topology.json](../../infrastructure/lab/topology.json). `fixtures/sources` simulates an approved NAS export. `fixtures/phase-1/events.jsonl` simulates Wazuh input. The simulator exposes only read-only events. These processes do not read a real NAS, firewall or Wazuh server.

## Observability

Each service writes one JSON line per request to stderr with service, route category, HTTP status, elapsed milliseconds and timestamp. It does not log query strings, headers, request bodies, prompts or document text. `/metrics` reports uptime, counts, latest and maximum request timing, one-minute CPU load, storage capacity and an NVIDIA GPU sample when `nvidia-smi` is available. A missing GPU is explicitly reported. `/health` is a liveness check, not a claim that the final product works.

For a local overview, run `make lab-check` and query each `/metrics` endpoint. Do not expose these endpoints outside the lab. A production dashboard, authenticated metrics access, retention policy and independent security-host forwarding remain later work.

## Lab boundary

This is a loopback simulation on the available Apple M3 Mac. It is useful for a fresh source build and synthetic service checks. It **does not satisfy T-007**: there is no NVIDIA GPU workstation, running container engine, segmented network, test NAS appliance, local DNS/PKI or separate Wazuh host/VM. Install and test those components on an approved Ubuntu lab host before asserting G0A. No production vessel connection is permitted by this runbook.

## Fresh-clone verification

Clone or copy the local repository into a new directory with no shared build output. Run `make fixtures`, `make check`, and `make lab-smoke`. Record the commit, OS/Python version, build SHA-256 and command output. The generated `build/` source archive and fixture payloads are intentionally ignored by Git; the versioned generators and manifests provide those payloads. Compare generated fixture manifests to the committed versions to prove reproducibility.
