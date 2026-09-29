<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# RA-TLS Implementation

> **In this artifact** the RA+TLS baseline server runs on a SEV-SNP CVM (`ratls_http_server.py --type snp`,
> started by `deploy/backend_setup.sh app`), and the client is the RA+TLS interpreter on the client VM.
> The SGX/Gramine packaging described below is the upstream prototype's original mode; the paper's
> numbers do not use it.


Remote Attestation TLS with per-connection attestation via TLS protocol extensions. Fresh SGX quote generated for each TLS handshake.

## Architecture

```
Every TLS Connection:
  1. TLS handshake begins
  2. Server generates fresh SGX quote
  3. Quote bound to binder_secret
  4. Quote sent via TLS extension 421
  5. Client verifies during handshake
```

## Components

- **[server/](server/)** - RA-TLS server with TLS extension support
- **[client.py](client.py)** - RA-TLS client with verification (requires RATLS Python)
- **[gramine/](gramine/)** - Gramine-SGX containerization
- **[openssl/](../ratls-external/)** - Custom OpenSSL 1.1.1m (external repo)
- **[python/](../python-ratls/)** - Custom Python build with RA-TLS OpenSSL

## Prerequisites

Unlike cTLS, RA-TLS requires:
- Custom OpenSSL 1.1.1m with `SSL_export_handshake_binder_secret()` API
- Custom Python 3.10 linked to RA-TLS OpenSSL
- C compiler for Python bridge

## Build

```bash
# 1. Build RA-TLS OpenSSL
cd ../ratls-external/
make

# 2. Build Python with RA-TLS OpenSSL
cd ..
./ratls/build_python_with_ratls.sh

# 3. Build Python C bridge
cd ratls/server/
../../python-ratls/bin/python3 setup.py build_ext --inplace
```

## Quick Start

```bash
# Run RA-TLS server (non-SGX, from server/ directory)
cd server/
make run-docker

# Test with client (from ratls/ directory)
# Uses RATLS Python via shebang
./client.py

# Or explicitly with RATLS Python
../python-ratls/bin/python3 client.py
```

## Client Usage

```bash
# Default: connects to https://localhost:5001
./client.py

# With custom server
./client.py --server https://your-server:port

# Skip quote verification (for testing)
./client.py --no-verify

# With CA certificate for TLS validation
./client.py --ca-cert /path/to/ca.pem
```

**Note:** The client requires the RATLS Python build (`python-ratls/bin/python3`) because it uses the custom OpenSSL with TLS extension support.

## SGX Mode

```bash
cd server/
make graminize
make run-sgx
```

## Performance

- Every connection: ~250ms (quote generation + verification)
- Quote freshness: Real-time (seconds old)
- Use case: Maximum freshness, server-to-server communication

## Documentation

See [server/README.md](server/README.md) for implementation details.

## Comparison with cTLS

| Aspect | cTLS | RA-TLS |
|--------|------|--------|
| Attestation | Once at startup | Every connection |
| First connection | ~6.6s | ~250ms |
| Subsequent | ~10ms | ~250ms |
| Browser support | ✅ | ❌ |
| Freshness | 0-90 days | Real-time |
