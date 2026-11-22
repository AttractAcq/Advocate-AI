# Local inference streaming probe

This probe measures the first non-empty content delta and total completion
time from a numeric loopback OpenAI-compatible model service. It confirms the
model is already advertised locally before sending a fixed synthetic prompt.
It bounds SSE bytes and line length, rejects incomplete streams, and retains
only timing, token count, finish reason, output length and hash. The output
does not contain the prompt or generated answer.

```sh
.venv/bin/python -m scripts.phase5_inference_stream_probe \
  --endpoint http://127.0.0.1:11434/v1 \
  --model qwen3.5:2b --samples 5 \
  --output /private/tmp/sovereign-inference-stream.json
```

The [retained Mac result](inference-stream-mac.json) at source commit `086d09a`
ran five concurrent samples with the installed local Qwen 2B model. Its p95
first-content time was 55.428 seconds. Two of five responses reported at
least 300 completion tokens and a normal stop; their p95 total time was
70.933 seconds. The other three stopped normally at 284–295 tokens and are
excluded from that 300-token figure. The staggered first-content times show
contention in this particular local run; they do not establish target GPU
performance.

This is a **direct model-service probe**, separate from the [five-user Core
load rehearsal](core-load-rehearsal.md). First content is only a proxy for
first token, and the two qualifying completions are too few to establish a
reliable p95. Core still returns a non-streaming response, so end-to-end
first-token time remains unobservable. AT-18 needs the full target workload,
model/runtime hashes, GPU thermals and process observations, and an approved
decision on how its first-token metric will be measured. No AT-18 threshold is
marked passed by this Mac result.
