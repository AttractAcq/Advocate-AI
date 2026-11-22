# Five-user Core load rehearsal

This is a repeatable software harness for the AT-18 workload. It sends a fixed
synthetic document corpus through Core as five named roles, schedules up to 50
requests per role over 30 minutes, checks each citation or cross-role denial,
and records per-request end-to-end latency without prompts, answers or tokens.
It is not an AT-18 pass on the target server.

## Local smoke

With the synthetic Phase 3 index and preinstalled loopback `qwen3.5:2b` model,
run a short in-process Core rehearsal:

```sh
.venv/bin/python -m scripts.phase5_core_load \
  --requests-per-role 2 --duration-seconds 2 \
  --output /private/tmp/sovereign-core-load-smoke.json
```

The [retained Mac sample](core-load-smoke-mac.json) at source commit `f012bf9`
made ten requests across captain, chief engineer, chief stewardess, deckhand
and AV/IT administrator. All ten returned the expected single citation or
no-source denial. The p95 end-to-end response time was 12.760 seconds; the
entire run took about 16 seconds. This is a small concurrent smoke on an Apple
arm64 host, not a capacity measurement or target GPU result.

## Target lab command

On an approved isolated lab host, prepare an owner-only JSON file containing
exactly the five synthetic user IDs in the script's `CASES` mapping and their
temporary Core bearer tokens. Give it mode `0600`; do not commit it or include
tokens in an evidence package. The harness rejects linked, oversized,
non-private and duplicate-key token files. Use a private numeric HTTPS Core
address with normal certificate validation; `--ca-bundle` may point to an
owner-only local CA PEM when the lab does not use the host trust store.

```sh
.venv/bin/python -m scripts.phase5_core_load \
  --core-url https://10.8.0.7:8443 \
  --tokens-file /private/lab/core-load-tokens.json \
  --ca-bundle /private/lab/core-ca.pem \
  --requests-per-role 50 --duration-seconds 1800 \
  --output /private/lab/evidence/core-load.json
```

The token lifetime must cover the scheduled run. A nonzero exit or any failed
citation, denial, HTTP request or final health probe fails this software
rehearsal. Preserve the host configuration, route and WAN state, model and
runtime hashes, process restart/OOM record, GPU power and thermal readings,
and independent tester decision alongside the metadata-only JSON. The script
does not collect those external measurements.

Core currently returns a complete non-streaming answer. The harness therefore
cannot measure end-to-end time to first token, and it does not guarantee a
300-token completion. Both AT-18 thresholds remain untested, as do the target
GPU, 30-minute workload and network conditions. A streaming Core path or an
approved separately labelled inference probe is needed before claiming the
first-token result.
