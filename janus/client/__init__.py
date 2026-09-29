# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Janus reference client (Python).

- ``attest`` — client-side attestation validation: extract the AS-JWT from a
  server leaf certificate, verify it against the cached MAA signing key, and
  check the REPORTDATA binding. This is the Python counterpart to the browser
  extension's ``jwt-verifier.js`` / ``sgx-validator.js``.
- ``native/`` (C) — the NSS-based RFC 9345 Delegated-Credential TLS handshake.
- ``browser_extension/`` (JS) — the stock-Firefox client.
"""
