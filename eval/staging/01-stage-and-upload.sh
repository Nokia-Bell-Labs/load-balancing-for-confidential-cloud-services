#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -euo pipefail

# Provision Azure blob storage, download Llama-3.1-8B-Instruct from HuggingFace
# and the ShareGPT V3 unfiltered dataset, then sync both to the blob container.
# Run on the SGX host (cheap) so we don't pay for HF download time on H100 CVMs.
#
# Idempotent — every step can be re-run safely. Existing artifacts are skipped.
#
# Output blob layout (container: $CONTAINER):
#   models/llama-3.1-8b-instruct/   (full HF snapshot: config.json, tokenizer*, *.safetensors)
#   datasets/sharegpt/ShareGPT_V3_unfiltered_cleaned_split.json
#
# After this: a CVM with system-assigned MI granted "Storage Blob Data Reader"
# on the storage account can read the artifacts via blobfuse2 or azcopy.
# See 02-pull-on-cvm.sh.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVAL_DIR="$REPO_ROOT/eval"
# shellcheck source=eval/env.sh
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"

KEEP_STAGING=false
for arg in "$@"; do
    case "$arg" in
        --keep-staging) KEEP_STAGING=true ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--keep-staging]
  --keep-staging    Don't delete \$STAGING_DIR after successful upload.
EOF
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '\n>>> %s\n' "$*"; }

# ----- 0. Tooling --------------------------------------------------------

install_azcopy() {
    log "Installing azcopy to /usr/local/bin (sudo)..."
    local tmp
    tmp=$(mktemp -d)
    (
        cd "$tmp"
        curl -sSL -o azcopy.tar.gz https://aka.ms/downloadazcopy-v10-linux
        tar -xzf azcopy.tar.gz --strip-components=1
        sudo install -m 0755 azcopy /usr/local/bin/azcopy
    )
    rm -rf "$tmp"
}

install_hf_cli() {
    log "Installing huggingface_hub (provides 'hf' CLI)..."
    if command -v pipx >/dev/null; then
        pipx install -q huggingface_hub
    else
        pip install --user -q huggingface_hub
        export PATH="$HOME/.local/bin:$PATH"
    fi
}

command -v az >/dev/null || {
    echo "!!! az CLI missing. Install: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash" >&2
    exit 1
}
command -v azcopy >/dev/null || install_azcopy
command -v hf >/dev/null || install_hf_cli
# Make sure ~/.local/bin is on PATH even if hf was installed in a previous run
export PATH="$HOME/.local/bin:$PATH"

# ----- 1. HuggingFace token ---------------------------------------------

HF_TOKEN_FILE="$HOME/.cache/huggingface/token"
if [[ -z "${HF_TOKEN:-}" ]]; then
    if [[ -f "$HF_TOKEN_FILE" ]]; then
        HF_TOKEN="$(cat "$HF_TOKEN_FILE")"
    else
        cat <<EOF >&2
!!! HuggingFace token not found.
    Either: export HF_TOKEN=hf_xxxxx
    Or:     hf auth login

    Llama 3.1 is gated — accept the license at
    https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct first.
EOF
        exit 1
    fi
fi
export HF_TOKEN

# ----- 2. Azure auth ----------------------------------------------------

if ! az account show -o none 2>/dev/null; then
    echo "!!! Not logged in to Azure. Run: az login --use-device-code" >&2
    exit 1
fi

# ----- 3. Storage account + container -----------------------------------

if [[ -z "${STORAGE_ACCOUNT:-}" ]]; then
    suffix=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 6)
    STORAGE_ACCOUNT="ctlsmodels${suffix}"
    log "Creating storage account $STORAGE_ACCOUNT in $RG / $LOCATION"
    az storage account create \
        --name "$STORAGE_ACCOUNT" \
        --resource-group "$RG" \
        --location "$LOCATION" \
        --sku Standard_LRS \
        --kind StorageV2 \
        --access-tier Hot \
        --min-tls-version TLS1_2 \
        --allow-blob-public-access false \
        -o none
    echo "$STORAGE_ACCOUNT" > "$EVAL_DIR/.storage_account"
    log "Persisted storage account name to eval/.storage_account"
else
    log "Using storage account: $STORAGE_ACCOUNT"
fi

# We authenticate via the storage account key (Contributor on the RG can read it).
# This avoids needing User Access Administrator to grant Storage Blob Data
# Contributor — which most users in this subscription don't have.
SUB_ID=$(az account show --query id -o tsv)
SCOPE="/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT"

ACCOUNT_KEY=$(az storage account keys list -g "$RG" -n "$STORAGE_ACCOUNT" --query "[0].value" -o tsv)
[[ -n "$ACCOUNT_KEY" ]] || { echo "!!! could not read account key for $STORAGE_ACCOUNT" >&2; exit 1; }

log "Creating container $CONTAINER (idempotent)"
az storage container create \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$ACCOUNT_KEY" \
    --name "$CONTAINER" \
    -o none

# ----- 4. Stage model ---------------------------------------------------

MODEL_STAGE="$STAGING_DIR/models/$MODEL_NAME"
mkdir -p "$MODEL_STAGE"

log "Downloading $MODEL_ID -> $MODEL_STAGE"
hf download "$MODEL_ID" \
    --local-dir "$MODEL_STAGE" \
    --exclude "original/*"

# ----- 5. Stage dataset -------------------------------------------------

DATASET_STAGE="$STAGING_DIR/datasets/sharegpt"
mkdir -p "$DATASET_STAGE"

if [[ ! -s "$DATASET_STAGE/$DATASET_FILENAME" ]]; then
    log "Downloading ShareGPT dataset"
    wget -q --show-progress -O "$DATASET_STAGE/$DATASET_FILENAME" "$DATASET_URL"
else
    log "ShareGPT dataset already present at $DATASET_STAGE/$DATASET_FILENAME"
fi

# ----- 6. Push to blob --------------------------------------------------

# Generate a short-lived write SAS from the account key. Avoids needing
# data-plane RBAC roles that most users in this sub can't grant themselves.
SAS_EXPIRY=$(date -u -d '6 hours' '+%Y-%m-%dT%H:%MZ')
SAS=$(az storage container generate-sas \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$ACCOUNT_KEY" \
    --name "$CONTAINER" \
    --permissions racwdl \
    --expiry "$SAS_EXPIRY" -o tsv)

BLOB_URL_BASE="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}"

log "azcopy sync $STAGING_DIR/ -> $BLOB_URL_BASE/  (SAS expires $SAS_EXPIRY)"
# Skip HF's local cache metadata — it's only useful for re-running hf download
# from the same local-dir, not for serving.
azcopy sync "$STAGING_DIR/" "${BLOB_URL_BASE}?${SAS}" \
    --delete-destination=false \
    --exclude-pattern '.cache;*/.cache/*'

# ----- 7. Cleanup -------------------------------------------------------

if $KEEP_STAGING; then
    log "Done. Staging kept at $STAGING_DIR (--keep-staging)."
else
    log "Removing staging dir $STAGING_DIR"
    rm -rf "$STAGING_DIR"
fi

cat <<EOF

Upload complete.

  Storage account : $STORAGE_ACCOUNT
  Container       : $CONTAINER
  Model           : $BLOB_URL_BASE/models/$MODEL_NAME/
  Dataset         : $BLOB_URL_BASE/datasets/sharegpt/$DATASET_FILENAME

For CVMs to read this, the simplest path is a short-lived read SAS:
  az storage container generate-sas --account-name $STORAGE_ACCOUNT \\
      --account-key "\$(az storage account keys list -g $RG -n $STORAGE_ACCOUNT \\
                       --query '[0].value' -o tsv)" \\
      --name $CONTAINER --permissions rl --expiry <YYYY-MM-DDTHH:MMZ> -o tsv

The MI/RBAC path also works once a User Access Administrator grants
"Storage Blob Data Reader" on $SCOPE to the CVM's system-assigned identity.
See eval/02-pull-on-cvm.sh.

EOF
