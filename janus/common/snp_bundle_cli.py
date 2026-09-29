#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""CLI wrapper around common.snp_attestation.build_snp_evidence_bundle.

Used by the RATLS C bridge to produce per-handshake evidence inside the TLS
handshake critical path.  Forking Python is heavier than direct ioctl, but
matches what `snpguest report` already does and keeps the protocol logic in
one Python module.

Usage:
    echo <nonce_hex_or_empty> | snp_bundle_cli.py <output-file>

If the input is non-empty, it must be hex-encoded bytes (any length); the
helper hashes them and binds the hash into the TPM2 quote's qualifyingData.
If empty (just a newline), the bundle has no TPM2 quote — caller can rely on
the static SNP report only (e.g., for Janus provisioning where the nonce is
carried over the TLS-protected request body instead).

Exit codes:
    0 success
    1 usage error
    2 bundling failed
"""
from __future__ import annotations

import os
import sys

# Make the package importable regardless of where the binary that invoked us
# was launched from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))  # parent of janus/
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from janus.common.snp_attestation import build_snp_evidence_bundle, parse_snp_evidence_bundle

# Disk cache for the VCEK+ASK+ARK chain — per-VM stable, so persisting it
# across CLI invocations avoids the ~1s AMD KDS fetch on every TLS handshake.
# Override with SNP_VCEK_CHAIN_CACHE env var.
_DEFAULT_CACHE = "/tmp/snp_vcek_chain.pem"


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(f"usage: {sys.argv[0]} <output-bundle-path>\n")
        return 1

    out_path = sys.argv[1]
    nonce_hex = sys.stdin.read().strip()
    nonce = bytes.fromhex(nonce_hex) if nonce_hex else None

    cache_path = os.environ.get("SNP_VCEK_CHAIN_CACHE", _DEFAULT_CACHE)
    cached = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                cached = f.read() or None
        except OSError:
            cached = None

    try:
        bundle = build_snp_evidence_bundle(nonce=nonce, vcek_chain_cache=cached)
    except Exception as exc:
        sys.stderr.write(f"bundle build failed: {exc}\n")
        return 2

    if cached is None:
        try:
            chain = parse_snp_evidence_bundle(bundle).pem_chain
            with open(cache_path, "wb") as f:
                f.write(chain)
        except Exception:
            pass

    with open(out_path, "wb") as f:
        f.write(bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
