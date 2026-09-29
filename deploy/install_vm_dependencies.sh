#!/bin/bash
# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Host/VM dependency installer for Janus (Ubuntu 22.04 "jammy").
# Installs everything needed to BUILD and RUN the system on a build host:
# the Intel SGX host stack (incl. the aesmd service), Docker, Azure DCAP, the
# Go/Node/Python toolchains, and the C/C++ build tools used by the source
# builds (BoringSSL, dc_proxy, Pebble). SEV-SNP backends additionally run
# janus/backend/install_backend.sh on the CVM.

set -e  # Exit on error

echo "=================================="
echo "Janus VM Dependencies Installation"
echo "=================================="

# ============================================================================
# REPOSITORY SETUP
# ============================================================================

echo "[1/7] Setting up repositories..."

# Add SGX repo
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list

# For libssl1.1 (required by some SGX components)
echo "deb http://security.ubuntu.com/ubuntu focal-security main" | sudo tee /etc/apt/sources.list.d/focal-security.list

# Docker repos
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update

# ============================================================================
# SYSTEM PACKAGES
# ============================================================================

echo "[2/7] Installing system packages..."

# Essential build tools
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    build-essential \
    make \
    cmake \
    clang \
    pkg-config \
    uuid-dev \
    gdb \
    git \
    wget \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    libnss3-dev \
    libnss3-tools

# SSL/TLS libraries
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    libssl-dev \
    libssl1.1

# SGX dependencies (host runtime incl. the aesmd architectural-enclave service)
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    libsgx-enclave-common \
    libsgx-quote-ex \
    libprotobuf17 \
    libsgx-dcap-ql \
    libsgx-dcap-ql-dev \
    sgx-aesm-service \
    libsgx-aesm-launch-plugin

# ============================================================================
# DOCKER
# ============================================================================

echo "[3/7] Installing Docker..."

sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker "${USER:-$(id -un)}"

# ============================================================================
# AZURE DCAP CLIENT
# ============================================================================

echo "[4/7] Installing Azure DCAP client..."

wget -q https://packages.microsoft.com/ubuntu/20.04/prod/pool/main/a/az-dcap-client/az-dcap-client_1.12.3_amd64.deb
sudo dpkg -i az-dcap-client_1.12.3_amd64.deb || sudo apt-get install -y -f
rm -f az-dcap-client_1.12.3_amd64.deb

# ============================================================================
# PYTHON ENVIRONMENT
# ============================================================================

echo "[5/7] Installing Python and packages..."

sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv

# Upgrade pip
sudo pip3 install --upgrade pip setuptools wheel

# Install Python dependencies for the frontend/backend servers (Azure SDKs are
# only needed for the optional frontend-driven CVM provisioner).
# Using --ignore-installed to avoid conflicts with system packages
sudo pip3 install --ignore-installed \
    azure-mgmt-resource==23.3.0 \
    azure-mgmt-compute==34.1.0 \
    azure-mgmt-network==28.1.0 \
    azure-identity==1.21.0 \
    azure-security-attestation==1.0.0 \
    cryptography==45.0.7 \
    flask==3.1.2 \
    paramiko==3.5.1 \
    requests==2.32.3 \
    urllib3==1.26.5 \
    acme==2.11.0 \
    josepy==1.14.0 \
    cffi

# Install Graminize dependencies
sudo pip3 install --ignore-installed \
    python-dotenv \
    click \
    jinja2 \
    tomli \
    tomli-w \
    toml \
    voluptuous

# ============================================================================
# NODE.JS & NPM (for browser extension)
# ============================================================================

echo "[6/7] Installing Node.js and npm..."

# Install Node.js LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo DEBIAN_FRONTEND=noninteractive apt install -y nodejs

# Verify installation
node --version
npm --version

# ============================================================================
# GOLANG (for Pebble ACME server)
# ============================================================================

echo "[7/7] Installing Go..."

# Pebble is built from source by ca/fetch_pebble.sh (Go 1.22 here; its go.mod requires 1.24, which the toolchain auto-downloads)
GO_VERSION="1.22.0"
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm -f go${GO_VERSION}.linux-amd64.tar.gz

# Add to PATH for current session and future sessions
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Verify installation
/usr/local/go/bin/go version

# ============================================================================
# COMPLETION
# ============================================================================

echo ""
echo "========================================"
echo "✓ Installation completed successfully!"
echo "========================================"
echo ""
echo "Next steps (see README.md 'Build and run'):"
echo "  1. Log out and log back in (or run: newgrp docker)"
echo "  2. CA:        ca/fetch_pebble.sh && ca/pebble/ca_certs/generate_ca_certificates.sh"
echo "  3. Images:    docker build -f janus/frontend/Dockerfile -t janus/frontend ."
echo "                docker build -f janus/backend/Dockerfile  -t janus/backend  ."
echo "  4. SGX image: make -C gramine gramine-image && make -C gramine signed-image MODULE=frontend"
echo ""
echo "Installed versions:"
echo "  - Docker: $(docker --version)"
echo "  - Python: $(python3 --version)"
echo "  - Node.js: $(node --version)"
echo "  - Go: $(/usr/local/go/bin/go version)"
echo ""
