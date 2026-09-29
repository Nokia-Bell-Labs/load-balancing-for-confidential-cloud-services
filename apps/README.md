<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Applications

The three evaluated workloads. Each runs unmodified inside the SEV-SNP backend
and is fronted identically (client → `dc_proxy` in redirection, or via the
frontend's `/forward` in proxy mode); only the protocol differs, so latency
deltas are pure protocol overhead.

- `browser_app/app.py` — self-contained Flask site (no external resources) that
  is the page-load-time target. Driven by `eval/benches/browser_plt_bench.py`.
- `llm_app/serve_vllm.py` — Llama-3.1-8B on the confidential H100 via vLLM
  (the paper's TTFT stack). `serve_hf.py` is the CPU dry-run engine with the
  same streaming `/generate` interface (the paravisor masks AVX512, so vLLM-CPU
  can't run there). Driven by `eval/benches/llm_ttft_bench.py`.
- `microservice_app/` — DeathStarBench `hotelReservation`, used stock (external
  clone, not vendored; no Janus code). See `microservice_app/README.md`. Driven
  by `eval/benches/microservice_bench.py`.

Upstream commits for the non-vendored dependencies are pinned in
`docs/DEPENDENCIES.md`.
