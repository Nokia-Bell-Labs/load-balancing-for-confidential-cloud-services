#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -euo pipefail

# Pull the staged model + dataset from blob onto the H100 CVM and serve with
# vLLM. Runs on the H100 CVM (NOT the SGX host).
#
# TODO: implement after CVM provisioning is decided.
#
# Sketch:
#   1. Verify system-assigned MI is enabled and has "Storage Blob Data Reader"
#      on the eval storage account (see end of 01-stage-and-upload.sh output).
#   2. Install azcopy.
#   3. azcopy sync as://$STORAGE_ACCOUNT/$CONTAINER/models/   /opt/models/
#      azcopy sync as://$STORAGE_ACCOUNT/$CONTAINER/datasets/ /data/
#      (or: blobfuse2 mount the container read-only at a stable path).
#   4. Serve with vLLM (the paper's stack — no Triton):
#        python3 apps/llm_app/serve_vllm.py \
#          --model /opt/models/$MODEL_NAME --bind 127.0.0.1 --port 8000
#      (fp16, gpu_memory_utilization 0.9, enforce_eager; /generate SSE).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=eval/env.sh
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"

echo "TODO: CVM-side pull not implemented yet." >&2
echo "What 01-stage-and-upload.sh produced:" >&2
echo "  https://${STORAGE_ACCOUNT:-<unset>}.blob.core.windows.net/${CONTAINER}/models/${MODEL_NAME}/" >&2
echo "  https://${STORAGE_ACCOUNT:-<unset>}.blob.core.windows.net/${CONTAINER}/datasets/sharegpt/${DATASET_FILENAME}" >&2
exit 1
