<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# LLM workload (Fig. 7b)

- `serve_vllm.py`: the LLM server of the paper. It serves Llama-3.1-8B-Instruct with vLLM (`/generate`, streamed).
- `serve_hf.py`: the same interface on plain Hugging Face Transformers.
- `llm_prompts.json`: the 50 prompts that the Fig. 7(b) bench sends, one time-to-first-token sample each. They are
  user prompts from the ShareGPT V3 unfiltered dataset (`anon8231489123/ShareGPT_Vicuna_unfiltered`, Apache 2.0),
  selected for their length distribution. Five prompts that contained personal data were replaced by prompts of the
  same length.
