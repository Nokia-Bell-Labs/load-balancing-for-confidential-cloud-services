#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# shellcheck shell=bash
# Shared variables for eval/01-stage-and-upload.sh (the SGX host) and
# eval/02-pull-on-cvm.sh (CVM). Source it: `. eval/env.sh`.

# Azure resources
RG="${RG:-<your-resource-group>}"
LOCATION="westeurope"
CONTAINER="artifacts"

# Storage account name is generated on first run of 01-stage-and-upload.sh
# and persisted to eval/.storage_account. Override by exporting STORAGE_ACCOUNT.
if [[ -z "${STORAGE_ACCOUNT:-}" ]]; then
    _eval_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$_eval_dir/.storage_account" ]]; then
        STORAGE_ACCOUNT="$(cat "$_eval_dir/.storage_account")"
    fi
fi

# Model + dataset
# Using the unsloth mirror because the official meta-llama/Llama-3.1-8B-Instruct
# repo is gated:manual (requires human approval from Meta). Weights are
# byte-identical. Swap back to "meta-llama/Llama-3.1-8B-Instruct" once approved.
MODEL_ID="${MODEL_ID:-unsloth/Meta-Llama-3.1-8B-Instruct}"
MODEL_NAME="llama-3.1-8b-instruct"
DATASET_URL="https://huggingface.co/datasets/anon8231489123/ShareGPT_Vicuna_unfiltered/resolve/main/ShareGPT_V3_unfiltered_cleaned_split.json"
DATASET_FILENAME="ShareGPT_V3_unfiltered_cleaned_split.json"

# Local staging on the SGX host (~17 GB needed: 16 GB model + 600 MB dataset)
STAGING_DIR="${STAGING_DIR:-/home/janus/Janus/eval/staging}"
