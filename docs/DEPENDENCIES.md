<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# External dependencies

This document is the complete index of the external (non-Janus) software that this system and its evaluation build against. No upstream code is committed into this repo. A fetch script next to each source dependency clones it at a **pinned** commit or tag into a gitignored directory. The script applies a patch where the table notes one. You can run each script again safely.

## Source builds (pinned + scripted)

| Dependency | Used by | Pinned version | Patch | Fetch / build |
|---|---|---|---|---|
| DeathStarBench `hotelReservation` | microservice workload | `6ecb09706140f8730b5385c08f1386c654c3c526` | none (stock) | `apps/microservice_app/fetch.sh` |
| `deathstarbench/hotel-reservation` image (pulled by that checkout's compose file as `:latest`) | the hotelReservation services | digest `sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436`, the image on the testbed. `deploy/backend_setup.sh` pins it | none | `deploy/backend_setup.sh` |
| BoringSSL | `dc_proxy` (RFC 9345 DC **server** API) | `d258906c992e30c07328eac375f2c6a4a0f30fd9` | `janus/backend/dc_proxy/boringssl-dc.patch` | `janus/backend/dc_proxy/fetch_boringssl.sh` |
| ratls (`Barkhausen-Institut/ratls`) | RA+TLS baseline | `c05b640c71371893da25cd74deb1f1fa412c161d` | `baselines/ratls/ratls-external-intel-sgx.patch` (+ `baselines/patches/ratls-external-makefile.patch`) | `baselines/ratls/build_python_with_ratls.sh` |
| Pebble (`letsencrypt/pebble`) | the certificate authority of the testbed (frontend ACME) | `v2.9.0` | `ca/pebble-janus.patch` | `ca/fetch_pebble.sh` |
| snpguest (`virtee/snpguest`) | backend SEV-SNP evidence (report/VCEK fetch) | `v0.10.0` | none | `janus/backend/fetch_snp_tools.sh` |
| Gramine (`gramineproject/gramine`) | SGX frontend packaging | `v1.7` tarball. The SGX UAPI header `sgx.h` is pinned to linux `v5.11` and SHA256-verified | none | built in `gramine/Dockerfile.gramine` (`make -C gramine gramine-image`) |

Each script clones next to itself, for example `apps/microservice_app/DeathStarBench/`, `janus/backend/dc_proxy/boringssl/`, `ca/pebble/` and `janus/backend/snpguest/`. All of these directories are gitignored. To see exactly what a patch changes, read the `.patch` file. You can also run `git -C <clone> diff` after you fetch.

## System packages (distro / apt)

These are standard OS packages. The script or Dockerfile in the table installs them. They are not source-built:

| Package | Used by | Installed by |
|---|---|---|
| `tpm2-tools` | backend SNP evidence (`tpm2_nvread` HCL report, `tpm2_quote`) | `janus/backend/fetch_snp_tools.sh` |
| `libnss3-dev` | native client `nss_dc_helper` (NSS is the only client TLS stack that validates DCs), `pkg-config nss` | apt, before `make -C janus/client/native` (see that README) |
| `libsgx-dcap-quote-verify-dev`, `libsgx-dcap-ql`, `az-dcap-client` | SGX quote verification (Intel DCAP + Azure DCAP provider) | `gramine/Dockerfile.gramine` |
| `azguestattestation1` (1.0.5) | optional. Azure `AttestationClient`. The evaluation does not use it | not installed by default |

## LLM serving (not a source clone)

`apps/llm_app/serve_vllm.py` serves Llama-3.1-8B-Instruct (fp16) directly on **vLLM** behind a `/generate` SSE endpoint. vLLM is a pip package, used through `AsyncLLMEngine`. The H100 run used vLLM 0.22. There is **no Triton**. The model weights and the ShareGPT prompts are data, not code. We do not redistribute them here:

- **Model**: `meta-llama/Llama-3.1-8B-Instruct` (fp16) from Hugging Face. The official repository is gated. Accept Meta's licence on Hugging Face first. `eval/staging/env.sh` names the mirror that we pulled from.
  - `eval/staging/01-stage-and-upload.sh` downloads the model with the `hf` CLI. It stages the model, with the dataset, in a blob container.
  - `02-pull-on-cvm.sh` is a template. It prints the manual steps to pull both onto the H100 CVM (blobfuse2/azcopy with the CVM's managed identity). This step is not automated.
- **Prompts**: `ShareGPT_V3_unfiltered_cleaned_split.json`. This is the ShareGPT V3 unfiltered, cleaned, split release on Hugging Face. The benchmark's prompt file (`--prompts`, `~/llm_prompts.json` on the client) holds the 50 prompts used, in order. `eval/benches/llm_ttft_bench.py` documents its format. We copy the file to the client when we set up the GPU window.
