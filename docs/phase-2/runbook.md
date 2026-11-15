# Phase 2 synthetic local runbook

This runbook is for the local Mac simulation using fictional fixtures. It does
not establish target-lab, vessel, or G1 acceptance. Keep every service bound to
`127.0.0.1`; do not load real vessel documents.

## Prepare

Use Python 3.14 with uv 0.11.3, Node 22 or newer, and an already-installed
Ollama `qwen3.5:2b` model. The model must be present before the demo; the
scripts never pull weights. From the repository root:

```sh
uv sync --locked
make fixtures
make check
cd apps/console/web
npm ci --ignore-scripts
npm run build
```

`uv.lock`, `requirements.lock` and `apps/console/web/package-lock.json` pin
the resolved development dependencies. The pull-request dependency job checks
lock consistency, audits Python dependencies with pip-audit, and runs npm audit.

## Start Core and Console

Choose a test-only passphrase of at least 12 characters in the shell that
starts Core. Do not commit it. In two terminals:

```sh
export SOVEREIGN_LAB_PASSWORD='<synthetic lab passphrase>'
uv run --locked uvicorn apps.api.main:app --host 127.0.0.1 --port 18100 --no-access-log
```

```sh
cd apps/console/web
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:18101/`. Vite proxies `/api` to Core on localhost. Sign
in as a named fixture user such as `lab-chief_engineer-1` with the test
passphrase. Try “What is the verification marker in the Generator inspection
procedure?” in the engineering workspace. The Console shows the model answer
and its permitted source citation. File selection narrows the search before
ranking. The Administration view is available only to `lab-avit_admin-1`.

The passphrase-based identity service and in-memory history are synthetic lab
devices. A Core restart invalidates sessions and erases history. Browser tokens
remain in memory and disappear on refresh. The Vite/Core HTTP setup has no TLS
and must not be exposed beyond loopback. Local production identity, TLS,
persistent storage and source ACL propagation require later implementation.

## Repeat the recorded checks

In a third terminal, export the same `SOVEREIGN_LAB_PASSWORD` value and run:

```sh
uv run --locked python -m scripts.phase2_demo --output docs/phase-2/demo-result.json
uv run --locked python -m scripts.phase2_benchmark --output docs/phase-2/benchmark-mac.json
```

For a cold benchmark, first run `ollama stop qwen3.5:2b` and verify `ollama ps`
shows no loaded model. The benchmark probes the local model list and refuses
to download a missing model. It records model digest, size, active context,
single-request latency and two-request concurrency. It does not prove WAN
disconnection or target NVIDIA/vLLM capacity.

`make lab-smoke` still tests the separate Phase 1 loopback topology and TLS
probes. Stop Core and Vite with Ctrl-C when finished.
