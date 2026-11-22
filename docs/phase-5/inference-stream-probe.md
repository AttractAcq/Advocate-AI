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

The [retained Mac result](inference-stream-mac.json) at source commit `7aae0e2`
ran five concurrent samples with the installed local Qwen 2B model. All five
reported 332–393 completion tokens and a normal stop. P95 first-content time
was 64.685 seconds and p95 full-answer time was 80.620 seconds. The fixed
synthetic prompt was expanded from 25 to 30 observations after the first run
returned fewer than 300 tokens in three of five samples. The staggered
first-content times show contention in this particular local run; they do not
establish target GPU performance.

This is a **direct model-service probe**, separate from the [five-user Core
load rehearsal](core-load-rehearsal.md). First content is only a proxy for
first token, and five samples are too few to establish a reliable p95. Core still returns
a non-streaming response, so end-to-end first-token time remains unobservable. AT-18 needs the full target workload,
model/runtime hashes, GPU thermals and process observations, and an approved
decision on how its first-token metric will be measured. No AT-18 threshold is
marked passed by this Mac result.
