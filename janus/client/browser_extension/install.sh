#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Build script for SGX Attestation Extension

set -e  # Exit on error

echo "================================================"
echo "SGX Attestation Extension - Build Script"
echo "================================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if manifest.json exists
if [ ! -f "manifest.json" ]; then
    echo "❌ manifest.json not found in current directory"
    exit 1
fi

# Step 1: Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"
echo ""

# Step 2: Build package
echo "🔨 Building extension package..."
npm run package

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Extension built successfully!"
    echo ""
    echo "📦 Package location:"
    ls -lh dist/*.zip
    echo ""
    echo "To install in Firefox:"
    echo "  1. Open about:debugging#/runtime/this-firefox"
    echo "  2. Click 'Load Temporary Add-on'"
    echo "  3. Select manifest.json or install the .zip file"
else
    echo "❌ Build failed"
    exit 1
fi