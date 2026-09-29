#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

#
# Build Python 3.10.12 with RATLS OpenSSL
# This creates a separate Python installation that can use RATLS TLS extensions
#

set -e  # Exit on error

PYTHON_VERSION="3.10.12"
RATLS_REPO="https://github.com/Barkhausen-Institut/ratls.git"
RATLS_COMMIT="c05b640"  # Known working commit
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEBASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RATLS_EXTERNAL_DIR="${CODEBASE_DIR}/ratls-external"
RATLS_OPENSSL_DIR="${RATLS_EXTERNAL_DIR}/install"
INSTALL_DIR="${CODEBASE_DIR}/python-ratls"
BUILD_DIR="/tmp/python-ratls-build"
PATCH_FILE="${SCRIPT_DIR}/ratls-external-intel-sgx.patch"

echo "=========================================="
echo "Building Python ${PYTHON_VERSION} with RATLS OpenSSL"
echo "=========================================="
echo "  Codebase dir: ${CODEBASE_DIR}"
echo "  RATLS OpenSSL: ${RATLS_OPENSSL_DIR}"
echo "  Install dir: ${INSTALL_DIR}"
echo "=========================================="

# Step 0a: Clone ratls-external if needed
if [ ! -d "${RATLS_EXTERNAL_DIR}" ]; then
    echo ""
    echo "[Step 0a/7] Cloning ratls-external repository..."
    cd "${CODEBASE_DIR}"
    git clone "${RATLS_REPO}" ratls-external
    cd ratls-external
    git checkout "${RATLS_COMMIT}"
    echo "✅ Cloned ratls-external at commit ${RATLS_COMMIT}"
else
    echo ""
    echo "[Step 0a/7] ratls-external already exists, skipping clone"
fi

# Step 0b: Apply Intel SGX patch if needed
if [ -f "${PATCH_FILE}" ]; then
    echo ""
    echo "[Step 0b/7] Applying Intel SGX compatibility patch..."
    cd "${RATLS_EXTERNAL_DIR}"
    
    if git apply --check "${PATCH_FILE}" 2>/dev/null; then
        git apply "${PATCH_FILE}"
        echo "✅ Patch applied (disables AMD SEV for Intel SGX)"
    elif git apply --reverse --check "${PATCH_FILE}" 2>/dev/null; then
        echo "ℹ️  Patch already applied"
    else
        echo "⚠️  Cannot apply patch - may need manual intervention"
    fi
else
    echo ""
    echo "[Step 0b/7] No patch file found, skipping"
fi

# Step 0c: Build ratls-external if not already built
if [ ! -d "${RATLS_OPENSSL_DIR}" ]; then
    echo ""
    echo "[Step 0c/7] Building ratls-external (OpenSSL, libsodium, TPM2 TSS)..."
    echo "  This may take 10-15 minutes..."
    cd "${RATLS_EXTERNAL_DIR}"
    make bootstrap
    echo "✅ ratls-external built successfully"
else
    echo ""
    echo "[Step 0c/7] ratls-external already built, skipping"
fi

# 1. Install build dependencies
echo ""
echo "[Step 1/7] Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libffi-dev \
    libgdbm-dev \
    libsqlite3-dev \
    libreadline-dev \
    libbz2-dev \
    liblzma-dev \
    zlib1g-dev \
    tk-dev \
    libncurses5-dev \
    libgdbm-compat-dev \
    libnss3-dev \
    uuid-dev

# 2. Download Python source
echo ""
echo "[Step 2/7] Downloading Python ${PYTHON_VERSION} source..."
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

if [ ! -f "Python-${PYTHON_VERSION}.tgz" ]; then
    wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
fi

tar xzf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}

# 3. Configure Python to use RATLS OpenSSL
echo ""
echo "[Step 3/7] Configuring Python build..."
echo "  OpenSSL path: ${RATLS_OPENSSL_DIR}"
echo "  Install path: ${INSTALL_DIR}"

./configure \
    --prefix=${INSTALL_DIR} \
    --enable-optimizations \
    --with-openssl=${RATLS_OPENSSL_DIR} \
    --with-openssl-rpath=${RATLS_OPENSSL_DIR}/lib \
    --enable-loadable-sqlite-extensions

# Verify configuration detected RATLS OpenSSL
echo ""
echo "Checking configuration..."
grep -A5 "checking for openssl/ssl.h" config.log | tail -6

# 4. Build Python
echo ""
echo "[Step 4/7] Building Python (this takes ~15-30 minutes)..."
make -j$(nproc)

# 5. Run tests7(optional but recommended)
echo ""
echo "[Step 5/7] Running ssl module tests..."
./python -c "import ssl; print('SSL module loaded:', ssl.OPENSSL_VERSION)"

# Expected output: OpenSSL 1.1.1m (should match RATLS version)
DETECTED_OPENSSL=$(./python -c "import ssl; print(ssl.OPENSSL_VERSION)")
echo "Detected: ${DETECTED_OPENSSL}"

if [[ ! "$DETECTED_OPENSSL" =~ "1.1.1" ]]; then
    echo "WARNING: Python is not using RATLS OpenSSL 1.1.1!"
    echo "Expected OpenSSL 1.1.1m, got: ${DETECTED_OPENSSL}"
    exit 1
fi

# 6. Install Python
echo ""
echo "[Step 6/7] Installing Python to ${INSTALL_DIR}..."
make install

# 7. Install required Python packages
echo ""
echo "[Step 7/7] Installing required Python packages..."
${INSTALL_DIR}/bin/pip3 install --upgrade pip
${INSTALL_DIR}/bin/pip3 install azure-identity azure-security-attestation six Flask cryptography
echo "✅ Python packages installed"

# Verify installation
echo ""
echo "=========================================="
echo "✅ Installation Complete!"
echo "=========================================="
echo ""
echo "Python executable: ${INSTALL_DIR}/bin/python3"
echo "OpenSSL version: $(${INSTALL_DIR}/bin/python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)')"
echo ""
echo "To use this Python:"
echo "  export PATH=${INSTALL_DIR}/bin:\$PATH"
echo "  python3 --version"
echo "  python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'"
echo ""
echo "To verify RATLS functions are available:"
echo "  ${INSTALL_DIR}/bin/python3 -c 'import ssl, ctypes; lib = ctypes.CDLL(ssl._ssl.__file__); print(\"SSL_export_handshake_binder_secret\" in dir(lib))'"
echo ""
echo "[Step 7/7] Installing required Python packages..."
${INSTALL_DIR}/bin/pip3 install --upgrade pip
${INSTALL_DIR}/bin/pip3 install azure-identity azure-security-attestation six Flask cryptography
echo "✅ Python packages installed"
echo ""
echo "Cleanup build directory:"
echo "  rm -rf ${BUILD_DIR}"
echo ""
