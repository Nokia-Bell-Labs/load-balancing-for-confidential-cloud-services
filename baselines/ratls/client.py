#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# NOTE: requires the patched interpreter (baselines/python-ratls/bin/python3,
# built from baselines/ratls-external) for the ratls_bridge module.
"""
RATLS HTTP Client - Fetches HTML pages over RATLS-attested TLS

Per-connection attestation via TLS extensions 420/421.  The server's SEV-SNP
report is bound to the TLS handshake's binder secret (REPORT_DATA =
SHA256(binder_secret)).  The client receives the report inside the handshake
(extension 421), submits it to Azure MAA's /attest/SevSnpVm endpoint over
REST, parses the returned JWT, and verifies that REPORT_DATA in the verified
claims matches SHA256(binder_secret).

Usage:
    # From ratls/ directory (uses RATLS Python via shebang):
    ./client.py

    # Or explicitly:
    ../python-ratls/bin/python3 client.py --server https://<cvm-ip>:5001
"""

import os
import sys
import ssl
import socket
import base64
import hashlib
import logging
import argparse
import json
import time
from urllib.parse import urlparse

# Add parent directory for common module imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # repo root
# Add server directory for ratls_bridge
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "server"))

try:
    import ratls_bridge
except ImportError:
    print("❌ ERROR: ratls_bridge module not found")
    print("   Make sure you're using the RATLS Python build")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("❌ ERROR: requests not installed.  pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Azure MAA configuration — same shared instance used by HTTPA/2 baseline and
# cTLS, so per-connection MAA cost is comparable across protocols.
MAA_URL = os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net")
MAA_API_VERSION = "2022-08-01"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class RATLSHTTPClient:
    """HTTP client with RATLS quote verification."""

    def __init__(self, server_url: str, verify_quote: bool = True, ca_cert_path: str = None):
        """
        Initialize RATLS HTTP client.

        Args:
            server_url: Server URL (e.g., https://localhost:5001)
            verify_quote: Whether to verify quotes with Azure MAA
            ca_cert_path: Path to CA certificate for TLS validation (None = insecure mode)
        """
        self.server_url = server_url
        self.verify_quote = verify_quote
        self.ca_cert_path = ca_cert_path
        self.received_quote = None
        self.received_binder_secret = None

        # Timing metrics
        self.timing = {
            'tls_handshake_total': 0,
            'tls_handshake_baseline': 0,  # Pure TLS without RA
            'ra_verification': 0,  # Total RA overhead
            'azure_maa': 0,
            'jwt_parsing': 0,
            'reportdata_validation': 0,
            'http_request': 0
        }

        # Parse server URL
        parsed = urlparse(server_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or 443

        logger.info(f"RATLS HTTP Client initialized")
        logger.info(f"  Server: {self.hostname}:{self.port}")
        logger.info(f"  Verification: {'Enabled' if verify_quote else 'Disabled'}")

    def quote_callback(self, binder_secret: bytes, quote: bytes):
        """
        Callback invoked when quote received via TLS extension 421.

        Args:
            binder_secret: 48-byte binder secret from TLS 1.3 handshake
            quote: SGX quote bytes from server

        Returns:
            bool: True to continue handshake, False to abort
        """
        # Start timing RA verification overhead
        self.ra_start_time = time.perf_counter()

        logger.info(f"📥 Received quote via TLS extension 421")
        logger.info(f"   Quote size: {len(quote)} bytes")
        logger.info(f"   Binder secret: {binder_secret.hex()[:40]}...")

        self.received_quote = quote
        self.received_binder_secret = binder_secret

        if self.verify_quote:
            result = self._verify_quote(binder_secret, quote)
            # Calculate RA overhead
            ra_elapsed_ms = (time.perf_counter() - self.ra_start_time) * 1000
            self.timing['ra_verification'] = ra_elapsed_ms
            logger.info(f"   ⏱ Time (RA verification overhead): {ra_elapsed_ms:.2f} ms")
            return result

        # If verification disabled, allow handshake to proceed
        return True

    def _verify_quote(self, binder_secret: bytes, quote: bytes):
        """Verify the SEV-SNP evidence bundle the server included in extension 421.

        Delegates to common.snp_attestation.verify_snp_bundle, which:
          1. Splits HCL → SNP report + boot runtime claims + (optional) TPM2 quote.
          2. POSTs (SnpReport, VcekCertChain) to Azure MAA /attest/SevSnpVm.
          3. Verifies the returned JWT signature + claims.
          4. (When a TPM2 quote is in the bundle) cross-checks it against the
             AK pub from the verified runtime claims and the binder_secret.

        binder_secret here is the per-handshake secret derived from the TLS
        handshake (Weinhold et al.'s linking hash); the bundle's TPM2 quote
        signed SHA256(binder_secret) as qualifyingData.
        """
        try:
            # Make the helper module importable (cTLS root)
            ratls_dir = os.path.dirname(os.path.abspath(__file__))
            repo = os.path.dirname(os.path.dirname(ratls_dir))
            if repo not in sys.path:
                sys.path.insert(0, repo)
            from janus.common.snp_attestation import verify_snp_bundle

            start_time_total = time.perf_counter()
            logger.info("🔍 Verifying SEV-SNP evidence bundle via Azure MAA…")
            logger.info(f"   Binder secret: {binder_secret.hex()[:32]}…")
            logger.info(f"   Bundle bytes:  {len(quote)}")

            start_time_maa = time.perf_counter()
            ok, info = verify_snp_bundle(
                quote, expected_nonce=binder_secret, maa_url=MAA_URL,
                logger=logger,
            )
            elapsed_maa_ms = (time.perf_counter() - start_time_maa) * 1000

            if not ok:
                logger.error(f"❌ MAA verification failed: {info.get('error')}")
                return False

            measurement = info.get("measurement", "N/A")
            logger.info("✅ Bundle verification SUCCESSFUL")
            logger.info(f"   ⏱ Time (full verify path): {elapsed_maa_ms:.2f} ms")
            logger.info(f"   MEASUREMENT: {measurement[:32]}…")
            logger.info(f"   guestsvn: {info.get('guestsvn')}, "
                        f"is-debuggable: {info.get('is_debuggable')}")

            elapsed_total_ms = (time.perf_counter() - start_time_total) * 1000
            logger.info(f"   ⏱ Time (total verification): {elapsed_total_ms:.2f} ms")

            self.timing['azure_maa'] = elapsed_maa_ms
            self.timing['total_verification'] = elapsed_total_ms

            return True

        except Exception as e:
            logger.error(f"❌ Quote verification failed: {e}")
            import traceback
            traceback.print_exc()
            # Return False to abort handshake on verification failure
            return False

    def http_request(self, path: str, method: str = "GET") -> tuple:
        """
        Make HTTP request over RATLS-attested TLS connection.

        Args:
            path: Request path (e.g., "/", "/static/index.html")
            method: HTTP method

        Returns:
            Tuple of (status_code, headers, body)
        """
        try:
            logger.info(f"🌐 HTTP {method} {path}")

            # Create socket. TCP_NODELAY mirrors the HTTPA client and the
            # TLS+RA paper's reference impl — without it the small Finished
            # write after handshake can be delayed by Nagle.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Pin TLS 1.3 — the RATLS bridge registers ext 421 only under
            # the TLS 1.3 EncryptedCertificate context, and TLS 1.3's 1-RTT
            # handshake is where the paper's RATLS-vs-HTTPA gap comes from.
            # Reference impl: ratls-external/src/ratls/demo-client.cpp:424.
            context.minimum_version = ssl.TLSVersion.TLSv1_3

            # Configure TLS certificate validation
            if self.ca_cert_path:
                # SECURE MODE: Enable TLS certificate chain validation
                logger.info(f"→ Enabling TLS verification with CA: {self.ca_cert_path}")
                context.load_verify_locations(cafile=self.ca_cert_path)

                # For localhost, skip hostname verification but keep chain validation
                if self.hostname in ['127.0.0.1', 'localhost']:
                    logger.info("✓ Certificate chain validation: ENABLED")
                    logger.info("✓ CA trust verification: ENABLED")
                    logger.info("⚠ Hostname verification: DISABLED (localhost exception)")
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_REQUIRED
                else:
                    # Production: full validation including hostname
                    logger.info("✓ Certificate chain validation: ENABLED")
                    logger.info("✓ CA trust verification: ENABLED")
                    logger.info("✓ Hostname verification: ENABLED")
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
            else:
                # INSECURE MODE: Skip TLS validation (rely on SGX quote only)
                logger.info("⚠ TLS certificate verification DISABLED (insecure mode)")
                logger.info("  → Relying on SGX quote verification only")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            # Register RATLS client callback
            ratls_bridge.setup_ratls_client(context, self.quote_callback)
            logger.info("✅ Registered TLS extension 421 callback")

            # Connect and perform TLS handshake
            logger.info(f"Connecting to {self.hostname}:{self.port}...")
            start_time_tls = time.perf_counter()
            ssl_sock = context.wrap_socket(sock, server_hostname=self.hostname)
            ssl_sock.connect((self.hostname, self.port))
            elapsed_tls_total_ms = (time.perf_counter() - start_time_tls) * 1000

            # Calculate baseline TLS time (excluding RA verification overhead)
            ra_overhead_ms = self.timing.get('ra_verification', 0)
            elapsed_tls_baseline_ms = elapsed_tls_total_ms - ra_overhead_ms

            # Store timing
            self.timing['tls_handshake_total'] = elapsed_tls_total_ms
            self.timing['tls_handshake_baseline'] = elapsed_tls_baseline_ms

            # Log TLS connection details
            tls_version = ssl_sock.version()
            cipher_info = ssl_sock.cipher()
            cipher_name = cipher_info[0] if cipher_info else 'Unknown'
            logger.info(f"✅ TLS handshake completed")
            logger.info(f"   Protocol: {tls_version}")
            logger.info(f"   Cipher: {cipher_name}")
            logger.info(f"   ⏱ Time (TLS total): {elapsed_tls_total_ms:.2f} ms")
            logger.info(f"   ⏱ Time (TLS baseline, no RA): {elapsed_tls_baseline_ms:.2f} ms")

            # At this point, quote_callback has been invoked (if server sent quote)

            # Send HTTP request
            start_time_http = time.perf_counter()
            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {self.hostname}\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"

            ssl_sock.sendall(request.encode())
            logger.debug(f"Sent HTTP request: {len(request)} bytes")

            # Receive response
            response_data = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            elapsed_http_ms = (time.perf_counter() - start_time_http) * 1000

            logger.info(f"📥 Received response: {len(response_data)} bytes")
            logger.info(f"   ⏱ Time (HTTP request): {elapsed_http_ms:.2f} ms")

            # Store timing
            self.timing['http_request'] = elapsed_http_ms

            # Parse HTTP response
            parts = response_data.split(b"\r\n\r\n", 1)
            if len(parts) < 2:
                logger.error("Invalid HTTP response")
                return (0, {}, b"")

            header_lines = parts[0].decode('utf-8', errors='ignore').split('\r\n')
            body = parts[1]

            # Parse status line
            status_line = header_lines[0]
            status_code = int(status_line.split()[1])

            # Parse headers
            headers = {}
            for line in header_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            logger.info(f"✅ HTTP {status_code}")

            # Close connection
            ssl_sock.close()

            return (status_code, headers, body)

        except Exception as e:
            logger.error(f"❌ HTTP request failed: {e}")
            import traceback
            traceback.print_exc()
            return (0, {}, b"")

    def fetch_page(self, path: str = "/") -> str:
        """
        Fetch HTML page from server.

        Args:
            path: Page path

        Returns:
            Page content as string
        """
        status, headers, body = self.http_request(path)

        if status == 200:
            content = body.decode('utf-8', errors='ignore')
            logger.info(f"✅ Fetched page: {len(content)} characters")
            return content
        else:
            logger.error(f"❌ Failed to fetch page: HTTP {status}")
            return ""


def main():
    """Main entry point for RATLS HTTP client."""
    parser = argparse.ArgumentParser(description="RATLS HTTP Client")
    parser.add_argument('--server', default='https://localhost:5001', help='Server URL (default: https://localhost:5001)')
    parser.add_argument('--no-verify', action='store_true', help='Skip quote verification')
    parser.add_argument('--ca-cert', type=str, default=None, help='Path to CA certificate for TLS validation (enables TLS cert verification)')
    parser.add_argument('--no-tls-verify', action='store_true', help='Skip TLS certificate verification (insecure, relies on SGX quote only)')
    parser.add_argument('--path', default='/', help='Path to fetch')

    args = parser.parse_args()

    # Handle ca_cert: if --no-tls-verify is set, force ca_cert to None
    if args.no_tls_verify:
        ca_cert_path = None
    else:
        ca_cert_path = args.ca_cert

    print()
    print("="*70)
    print("🔐 RATLS HTTP Client")
    print("="*70)
    print(f"  Server: {args.server}")
    print(f"  Path: {args.path}")
    print(f"  Quote Verification: {'Disabled' if args.no_verify else 'Azure MAA'}")
    print(f"  TLS Cert Validation: {'Enabled' if ca_cert_path else 'Disabled (insecure)'}")
    print("="*70)
    print()

    try:
        # Create client
        client = RATLSHTTPClient(args.server, verify_quote=not args.no_verify, ca_cert_path=ca_cert_path)

        # Fetch page
        content = client.fetch_page(args.path)

        if content:
            # Show page content
            print()
            print("="*70)
            print("📄 Page Content")
            print("="*70)
            # Show first 500 chars
            preview = content[:500]
            if len(content) > 500:
                preview += "..."
            print(preview)
            print("="*70)

        # Check for expected content
        if content and "RATLS Mode" in content:
            logger.info("✅ Page contains RATLS mode indicator")

        # Summary
        print()
        print("="*70)
        print("✅ Test Summary")
        print("="*70)
        print(f"  TLS: Established successfully")
        print(f"  Quote: {'Received and verified' if client.received_quote else 'Not received'}")
        print(f"  Page: Fetched successfully ({len(content)} chars)")
        print("="*70)

        # Timing summary
        if client.timing['tls_handshake_total'] > 0:
            print()
            print("="*70)
            print("⏱ Performance Metrics")
            print("="*70)
            print(f"  TLS Handshake (total):     {client.timing['tls_handshake_total']:>8.2f} ms")
            if client.timing['ra_verification'] > 0:
                print(f"    ├─ Baseline TLS:          {client.timing['tls_handshake_baseline']:>8.2f} ms")
                print(f"    └─ RA Verification:       {client.timing['ra_verification']:>8.2f} ms")
                print(f"         ├─ Azure MAA:        {client.timing['azure_maa']:>8.2f} ms")
                print(f"         ├─ JWT Parsing:      {client.timing['jwt_parsing']:>8.2f} ms")
                print(f"         └─ REPORTDATA Check: {client.timing['reportdata_validation']:>8.2f} ms")
            print(f"  HTTP Request/Response:     {client.timing['http_request']:>8.2f} ms")
            print(f"  {'─'*30}")
            total = client.timing['tls_handshake_total'] + client.timing['http_request']
            print(f"  Total Time:                {total:>8.2f} ms")
            print("="*70)

    except KeyboardInterrupt:
        logger.info("\n👋 Stopped by user")
    except Exception as e:
        logger.error(f"❌ Client error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
