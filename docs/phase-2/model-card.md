# Local fallback model card — synthetic Mac lab

| Item | Observed configuration |
|---|---|
| Runtime | Ollama 0.40.11, OpenAI-compatible localhost endpoint |
| Model | `qwen3.5:2b`, reported 2.2B parameters, `mxfp8` |
| Local digest | `dfaf2605162e689c8cac330dc4a190c4c50ad30aa47814a8fe9b79fa5127e97e` |
| Stored size | 3,117,475,695 bytes from local `/api/tags` |
| Active context | 4,096 tokens from local `/api/ps` during benchmark |
| Host | Apple arm64 Mac, 8 GiB memory, MLX runner; macOS 26.5.2 |
| Local licence display | Apache-2.0 in `ollama show`; publisher revision and redistribution review remain open |
| Core generation setting | `reasoning_effort: none`, maximum 320 output tokens, 90 s timeout |

The model was already installed locally. Core only accepts a numeric loopback
inference endpoint and does not offer an external AI API. [The benchmark](benchmark-mac.json)
records a cold load, source question and two concurrent prompts. These small
samples are development measurements, not a capacity claim. The [demo](demo-result.json)
records one cited answer using the same local model.

This fallback differs from the Phase 0 candidate stack of NVIDIA/vLLM with
Qwen3-8B. Exact upstream weight revision, model file hashes, full licence
notices, model-serving network isolation, target GPU compatibility and target
throughput remain unverified. Do not treat this Mac benchmark as T-010 or G1
sign-off for the target lab.
