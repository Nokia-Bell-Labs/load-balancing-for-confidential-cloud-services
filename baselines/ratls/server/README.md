<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# RATLS Implementation Guide

> **In this artifact** the RA+TLS baseline server runs on a SEV-SNP CVM (`ratls_http_server.py --type snp`,
> started by `deploy/backend_setup.sh app`), and the client is the RA+TLS interpreter on the client VM.
> The SGX/Gramine packaging described below is the upstream prototype's original mode; the paper's
> numbers do not use it.


## Overview

This directory contains a complete RATLS (Remote Attestation TLS) implementation that provides SGX attestation during the TLS handshake itself, not as a post-handshake operation. The implementation uses custom TLS extensions (420 and 421) to embed SGX quotes bound to the TLS session's binder secret.

## Architecture

### Key Components

1. **Custom Python Build** (`/home/janus/SGX/build/python-ratls/`)
   - Python 3.10.12 compiled with RATLS OpenSSL 1.1.1m
   - Provides `SSL_export_handshake_binder_secret()` API
   - Isolated from system Python to avoid conflicts

2. **RATLS OpenSSL** (`/home/janus/SGX/build/ratls/install/`)
   - Modified OpenSSL 1.1.1m with binder secret export
   - Custom TLS extension support (extensions 420/421)

3. **C Extension Bridge** (`ratls_bridge.so`)
   - Python C extension linking to RATLS OpenSSL
   - Registers TLS extension callbacks
   - Extracts binder secret during handshake

4. **Python Implementation**
   - `ratls_server.py` - Server with quote generation
   - `ratls_client.py` - Client with quote verification
   - `benchmark_ratls.py` - Performance testing

### TLS Extension Flow

```
Client                          Server
------                          ------
ClientHello
  + Extension 420 (RA_REQ)    →
  + Extension 421 (negotiate)

                              ← ServerHello
                                Certificate
                                  + Extension 421 (RA_RES)
                                    [SGX Quote with binder_secret]

Verify Quote
  - Extract REPORTDATA
  - Compute SHA256(binder_secret)
  - Verify binding
  - Validate via Azure MAA

Application Data              ↔ Application Data
```

### Quote Binding

The critical security property is binding the SGX quote to the TLS session:

```
binder_secret = SHA256(handshake_secret || handshake_traffic_hash)  [48 bytes]
REPORTDATA = SHA256(binder_secret)  [32 bytes]

SGX Quote contains:
  - MRENCLAVE (enclave measurement)
  - MRSIGNER (enclave signer)
  - REPORTDATA (bound to TLS session)
```

This prevents replay attacks - each TLS session has a unique binder_secret, making quotes non-transferable.

## Prerequisites

### Generate Pebble CA Certificates (REQUIRED FIRST STEP)

**⚠️ IMPORTANT: Run this BEFORE building Docker images. RATLS uses Pebble ACME CA for obtaining server certificates.**

```bash
cd /home/janus/SGX/build/pebble/ca_certs
./generate_ca_certificates.sh
```

This creates persistent root and intermediate CA certificates (10-year validity) that Pebble will use for signing RATLS server certificates via ACME protocol.

**Note**: This is a one-time setup shared with cTLS. The script is idempotent (safe to run multiple times).

## Usage

### Quick Start (Non-SGX)

The RATLS implementation follows the same unified server pattern as cTLS:

```bash
# Terminal 1: Start RATLS server (via unified server)
cd /home/janus/SGX/build/AdminEnclave
make run-ratls

# Equivalent to:
/home/janus/SGX/build/python-ratls/bin/python3 unified_server.py \
    --mode ratls \
    --port 5001 \
    --environment direct

# Terminal 2: Test with client
make run-ratls-client
```

### Unified Server Architecture

Both cTLS and RATLS use the same entry point (`unified_server.py`):

```bash
# Run cTLS server
python3 unified_server.py --mode ctls --port 5000 --environment direct

# Run RATLS server
python-ratls/bin/python3 unified_server.py --mode ratls --port 5001 --environment sgx
```

**Arguments:**
- `--mode`: Server mode (`ctls` or `ratls`)
- `--port`: Port number (default: 5000 for cTLS, 5001 for RATLS)
- `--environment`: Attestation mode (`direct` for simulation, `sgx` for real SGX)

### Testing Multiple Connections

```bash
/home/janus/SGX/build/python-ratls/bin/python3 ratls_client.py \
    --host localhost \
    --port 5001 \
    --connections 10
```

### Performance Benchmarking

```bash
# Benchmark RATLS only
make benchmark-ratls

# Compare with standard TLS (requires both servers running)
make benchmark-compare
```

### Docker Deployment

The Docker setup uses the unified server with environment variables:

```bash
# Build RATLS Docker image
make image-ratls

# Run in simulation mode
make run-ratls-docker
# Sets: ENVIRONMENT=direct, RATLS_PORT=5001

# Run with SGX support
make run-ratls-docker-sgx
# Sets: ENVIRONMENT=sgx, RATLS_PORT=5001
```

The `start_ratls.sh` script automatically calls `unified_server.py` with the appropriate mode and environment.

### Gramine-SGX

```bash
# Generate manifest
make ratls-manifest

# Sign manifest
make ratls-sign

# Run under Gramine-SGX
make run-sgx-ratls
```

## Implementation Details

### Server Side

1. **Extension Registration**
   - Extension 420: Parse client's RA request
   - Extension 421: Send quote in Certificate message

2. **Quote Generation** (`generate_quote()`)
   ```python
   def generate_quote(binder_secret):
       reportdata = hashlib.sha256(binder_secret).digest()
       
       if SGX_MODE:
           # Write reportdata to SGX device
           with open('/dev/attestation/user_report_data', 'wb') as f:
               f.write(reportdata)
           
           # Read quote from SGX device
           with open('/dev/attestation/quote', 'rb') as f:
               quote = f.read()
       else:
           # Simulation mode
           quote = b"FAKE_SGX_QUOTE_" + reportdata + binder_secret[:16]
       
       return quote
   ```

### Client Side

1. **Extension Registration**
   - Extension 420: Request attestation (empty payload)
   - Extension 421: Receive and parse quote

2. **Quote Verification** (`verify_quote()`)
   ```python
   def verify_quote(quote, binder_secret):
       expected_reportdata = hashlib.sha256(binder_secret).digest()
       
       # Parse quote structure
       quote_body = quote[48:432]  # Standard SGX quote format
       actual_reportdata = quote_body[320:352]
       
       # Verify binding
       if actual_reportdata != expected_reportdata:
           raise ValueError("REPORTDATA mismatch!")
       
       # Verify via Azure MAA
       attestation_result = azure_maa.verify(quote)
       
       return True
   ```

## Performance Characteristics

Based on benchmark results (simulation mode, 20 iterations):

- **Mean Latency**: 2.60 ms per connection
- **Success Rate**: 100%
- **P95 Latency**: 4.75 ms
- **P99 Latency**: 4.75 ms

The overhead compared to standard TLS is primarily from:
1. Quote generation (real SGX: ~10-30ms, simulation: <1ms)
2. Quote verification via Azure MAA (~5-20ms in production)
3. Additional TLS extension processing (~0.5ms)

## File Structure

```
AdminEnclave/
├── ratls_server.py              # RATLS server implementation
├── ratls_client.py              # RATLS client with verification
├── ratls_python_bridge.c        # C extension for TLS callbacks
├── setup.py                     # C extension build configuration
├── benchmark_ratls.py           # Performance benchmarking
├── test_ratls_minimal.py        # Minimal callback test
├── start_ratls.sh               # Docker startup script
├── Dockerfile.ratls             # Docker image with RATLS Python
├── Makefile                     # Build and run targets
└── attestation_verifier.py      # Azure MAA integration

graminize/
└── ratls.manifest.template      # Gramine manifest for SGX

python-ratls/                    # Custom Python installation
└── bin/python3                  # Python 3.10.12 + RATLS OpenSSL

ratls/
└── install/                     # RATLS OpenSSL 1.1.1m
    └── lib/
        ├── libssl.so.1.1
        └── libcrypto.so.1.1
```

## Debugging

### Check Extension Registration

```bash
# Server logs should show:
RATLS Bridge: Registered server extension 420 (parse RA request)
RATLS Bridge: Registered server extension 421 for ALL contexts

# Client logs should show:
RATLS Bridge: Registered client extension 420 (send RA request)
RATLS Bridge: Registered client extension 421 (parse+negotiate)
```

### Verify Callback Invocation

```bash
# During handshake, you should see:
RATLS Bridge: add_ra_request_cb CALLED! ext_type=420 context=0x80
RATLS Bridge: add_ra_request_cb CALLED! ext_type=421 context=0x80
RATLS Bridge: parse_ra_request_cb CALLED! ext_type=420 context=0x80 inlen=0
RATLS Bridge: add_ra_response_cb CALLED! ext_type=421 context=0x1000 chainidx=0
RATLS Bridge: parse_ra_response_cb CALLED! ext_type=421 context=0x1000 inlen=63
```

### Test Minimal Implementation

```bash
/home/janus/SGX/build/python-ratls/bin/python3 test_ratls_minimal.py
```

## Key Differences from cTLS

| Aspect | cTLS (Current) | RATLS (This Implementation) |
|--------|----------------|----------------------------|
| **Attestation Timing** | Post-handshake | During handshake |
| **Method** | Application-layer protocol | TLS extensions 420/421 |
| **Quote Binding** | Session ID | Binder secret (handshake-derived) |
| **Python Version** | System Python 3.10 + OpenSSL 3.0 | Custom Python 3.10 + OpenSSL 1.1.1m |
| **Extension Support** | Standard TLS 1.3 | Custom extensions via C bridge |
| **Overhead** | ~2 RTT (separate attestation) | Same handshake (no extra RTT) |

## Security Considerations

1. **Binder Secret Binding**: The use of `binder_secret` (derived from `handshake_secret`) provides cryptographic binding to the specific TLS session. Unlike session IDs which can be copied, binder secrets cannot be extracted or replayed.

2. **Freshness**: Each TLS handshake generates a new binder secret, ensuring quote freshness. Old quotes cannot be replayed in new sessions.

3. **SGX Protection**: In real SGX mode, the quote generation happens inside the enclave, and REPORTDATA is measured by SGX hardware. The binder secret never leaves the secure environment.

4. **Verification**: Azure MAA verifies:
   - Quote signature (Intel/AMD attestation key)
   - Enclave measurements (MRENCLAVE, MRSIGNER)
   - Platform TCB status
   - REPORTDATA integrity

## Troubleshooting

### "Failed to import ratls_bridge"

```bash
cd /home/janus/SGX/build/AdminEnclave
/home/janus/SGX/build/python-ratls/bin/python3 setup.py build_ext --inplace
```

### "Address already in use"

```bash
killall python3
# Wait 2 seconds for ports to be released
sleep 2
make run-ratls
```

### Callbacks Not Invoked

Ensure the client sends BOTH extensions 420 and 421 in ClientHello. This signals support for both request and response extensions, enabling the server's add callback.

## References

- [RATLS C++ Implementation](../ratls/src/ratls/ratls.cpp)
- [OpenSSL Custom Extensions](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_add_custom_ext.html)
- [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
- [Azure MAA Documentation](https://docs.microsoft.com/en-us/azure/attestation/)
- [Intel SGX Documentation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
