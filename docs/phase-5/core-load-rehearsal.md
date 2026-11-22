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

A [second Mac run](core-load-citation-integrity-mac.json) at `988df18`
repeated ten requests after tightening the harness. It now requires the
expected document ID, version, SHA-256 and collection from the fixed synthetic
manifest, one nonnegative passage ordinal, and a nonempty allowed answer.
Denials must contain no citations and the exact no-source response. All ten
requests passed; p95 end-to-end response time was 11.543 seconds. This checks
citation identity and denial behavior, not whether the answer prose supports
every claim. Independent claim review and the target workload remain open.

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
  --nvidia-smi /absolute/path/to/approved/nvidia-smi \
  --nvidia-smi-sha256 APPROVED_BINARY_SHA256 \
  --gpu-uuid GPU-00000000-0000-0000-0000-000000000001 \
  --output /private/lab/evidence/core-load.json
```

The token lifetime must cover the scheduled run. Replace the illustrative
GPU UUID with the exact target UUID. The optional NVIDIA sampler requires an
absolute, regular, non-writable executable whose SHA-256 matches the approved
value. It queries only UUID, core temperature, board power, used memory and
utilisation with [NVIDIA's documented selective query interface](https://docs.nvidia.com/deploy/nvidia-smi/).
A five-second interval produces time-aligned metadata-only samples in
`gpu_thermals`; an unavailable metric, query error, wrong UUID or truncated
sampling makes the command exit nonzero after retaining the report. On a host
without NVIDIA hardware, omit all three GPU arguments; the report then leaves
`gpu_thermals` null and cannot satisfy the GPU evidence requirement.

A nonzero exit or any failed citation, denial, HTTP request or final health
probe fails this software rehearsal. Preserve the host configuration, route
and WAN state, model and runtime hashes, process restart/OOM record, GPU
readings and independent tester decision alongside the JSON. The sampler does
not establish absence of OOM or process restarts; collect supervisor and host
logs separately. A clean result on the target hardware remains required.

Core currently returns a complete non-streaming answer. The harness therefore
cannot measure end-to-end time to first token, and it does not guarantee a
300-token completion. Both AT-18 thresholds remain untested, as do the target
GPU, 30-minute workload and network conditions. A [separate direct model
probe](inference-stream-probe.md) is now available, but it does not measure
end-to-end first-token time through Core or Console.
