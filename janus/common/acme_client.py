# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
ACME Client - Get certificates from Pebble CA

This module implements the ACME protocol to request certificates from Pebble CA.
Supports two modes:
- Plain certificates (for RATLS): Standard CA-signed certificates
- SGX-embedded certificates (for Janus): Certificates with SGX quote in extensions

Usage:
    from janus.common.acme_client import ACMEClient

    # For RATLS (plain certificate)
    client = ACMEClient(pebble_url="https://localhost:14000/dir")
    cert_pem, key_pem = client.get_certificate(
        private_key=my_key,
        common_name="localhost"
    )

    # For Janus (certificate with SGX extensions)
    cert_pem, key_pem = client.get_certificate_with_sgx(
        private_key=my_key,
        common_name="localhost"
    )
"""

import logging
import time
from typing import Tuple, Optional
import http.server
import threading

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from acme import client, messages, challenges
import josepy as jose
import requests


class ACMEClient:
    """
    ACME client for requesting certificates from Pebble CA.

    Supports both plain certificates (for RATLS) and certificates with
    SGX extensions (for Janus).
    """

    def __init__(
        self,
        pebble_url: str = "https://localhost:14000/dir",
        verify_ssl: bool = False,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize ACME client.

        Args:
            pebble_url: Pebble directory URL
            verify_ssl: Whether to verify SSL (False for Pebble)
            logger: Optional logger instance
        """
        self.pebble_url = pebble_url
        self.verify_ssl = verify_ssl
        self.logger = logger or logging.getLogger(__name__)

        # Disable SSL warnings for Pebble
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()

        # ACME account key (generate new for each client)
        self._account_key = self._generate_account_key()
        self._acme_client = None

    def _generate_account_key(self):
        """Generate RSA key for ACME account."""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return jose.JWKRSA(key=key)

    def _get_acme_client(self) -> client.ClientV2:
        """Get or create ACME client."""
        if self._acme_client is None:
            net = client.ClientNetwork(
                self._account_key,
                account=None,
                verify_ssl=self.verify_ssl
            )

            directory = messages.Directory.from_json(
                net.get(self.pebble_url).json()
            )

            self._acme_client = client.ClientV2(directory, net=net)

            # Register account
            self.logger.info("Registering ACME account with Pebble...")
            regr = self._acme_client.new_account(
                messages.NewRegistration.from_data(
                    email='admin@localhost',
                    terms_of_service_agreed=True
                )
            )
            self.logger.info(f"✓ ACME account registered: {regr.uri}")

        return self._acme_client

    def _create_plain_csr(
        self,
        private_key,
        common_name: str,
        dns_names: Optional[list] = None,
        ip_addresses: Optional[list] = None
    ) -> bytes:
        """
        Create a plain CSR without SGX extensions (for RATLS).

        Args:
            private_key: RSA private key
            common_name: Common name (e.g., "localhost")
            dns_names: Optional DNS SANs
            ip_addresses: Optional IP address SANs

        Returns:
            CSR in PEM format
        """
        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])

        # Build CSR
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        # Add SANs if provided
        san_list = []
        if dns_names:
            san_list.extend([x509.DNSName(name) for name in dns_names])
        if ip_addresses:
            from ipaddress import ip_address
            san_list.extend([x509.IPAddress(ip_address(ip)) for ip in ip_addresses])

        if san_list:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )

        # Sign CSR
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        return csr.public_bytes(serialization.Encoding.PEM)

    def get_certificate(
        self,
        private_key,
        common_name: str,
        dns_names: Optional[list] = None,
        ip_addresses: Optional[list] = None,
        challenge_port: int = 5002
    ) -> Tuple[bytes, bytes]:
        """
        Request plain certificate from Pebble CA (for RATLS).

        This is the standard ACME flow without SGX extensions:
        1. Create plain CSR
        2. Create ACME order
        3. Complete HTTP-01 challenges
        4. Finalize order
        5. Download certificate

        Args:
            private_key: RSA private key for the certificate
            common_name: Common name (e.g., "localhost")
            dns_names: Optional DNS SANs (defaults to [common_name])
            ip_addresses: Optional IP address SANs (e.g., ["127.0.0.1"])
            challenge_port: Port for HTTP-01 challenge server

        Returns:
            Tuple of (certificate_pem, private_key_pem)

        Raises:
            RuntimeError: If certificate request fails
        """
        import time as time_module
        start_time_total = time_module.perf_counter()

        self.logger.info("="*60)
        self.logger.info("ACME Certificate Request (Plain)")
        self.logger.info("="*60)

        # 1. Create plain CSR
        self.logger.info("\n[1/5] Creating CSR...")
        try:
            start_time_step = time_module.perf_counter()
            csr_pem = self._create_plain_csr(
                private_key,
                common_name,
                dns_names or [common_name],
                ip_addresses
            )
            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ CSR created ({len(csr_pem)} bytes)")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")
        except Exception as e:
            raise RuntimeError(f"Failed to create CSR: {e}")

        # Steps 2-5 are identical to get_certificate_with_sgx
        return self._complete_acme_flow(
            csr_pem,
            private_key,
            challenge_port,
            start_time_total,
            cert_type="Plain"
        )

    def get_certificate_with_sgx(
        self,
        private_key,
        common_name: str,
        dns_names: Optional[list] = None,
        ip_addresses: Optional[list] = None,
        challenge_port: int = 5002
    ) -> Tuple[bytes, bytes]:
        """
        Request certificate from Pebble CA with SGX quote embedded (for Janus).

        This implements the complete ACME flow:
        1. Create CSR with SGX quote extension
        2. Create ACME order
        3. Complete HTTP-01 challenges
        4. Finalize order
        5. Download certificate

        Args:
            private_key: RSA private key for the certificate
            common_name: Common name (e.g., "localhost")
            dns_names: Optional DNS SANs (defaults to [common_name])
            ip_addresses: Optional IP address SANs (e.g., ["127.0.0.1"])
            challenge_port: Port for HTTP-01 challenge server

        Returns:
            Tuple of (certificate_pem, private_key_pem)

        Raises:
            RuntimeError: If certificate request fails
        """
        import time as time_module
        start_time_total = time_module.perf_counter()

        self.logger.info("="*60)
        self.logger.info("ACME Certificate Request with SGX Quote")
        self.logger.info("="*60)

        # 1. Create CSR with SGX quote (requires janus.common.cert_generator)
        self.logger.info("\n[1/5] Creating CSR with SGX quote...")
        self.logger.info("       (includes server-side attestation verification via Azure MAA)")
        try:
            # Import cert_generator (only available alongside the janus package)
            try:
                from janus.common.cert_generator import get_cert_generator
            except ImportError:
                try:
                    import sys
                    import os
                    sys.path.insert(0, os.path.dirname(__file__))
                    from cert_generator import get_cert_generator
                except ImportError:
                    raise RuntimeError(
                        "cert_generator not available - SGX certificate requires Janus dependencies"
                    )

            start_time_step = time_module.perf_counter()
            cert_gen = get_cert_generator()
            csr_pem, attestation_result = cert_gen.create_csr_with_sgx_quote(
                private_key,
                common_name,
                dns_names,
                ip_addresses=ip_addresses,
                verify_attestation=True,  # Server-side verification enabled
                logger=self.logger
            )
            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ CSR created ({len(csr_pem)} bytes)")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")
            if attestation_result:
                self.logger.info(f"✓ Attestation verified: MRENCLAVE={attestation_result.get('mrenclave', 'N/A')[:16]}...")
        except Exception as e:
            raise RuntimeError(f"Failed to create CSR with SGX quote: {e}")

        # Steps 2-5 are identical to get_certificate
        return self._complete_acme_flow(
            csr_pem,
            private_key,
            challenge_port,
            start_time_total,
            cert_type="SGX"
        )

    def _complete_acme_flow(
        self,
        csr_pem: bytes,
        private_key,
        challenge_port: int,
        start_time_total: float,
        cert_type: str = "Plain"
    ) -> Tuple[bytes, bytes]:
        """
        Complete the ACME flow (steps 2-5).

        Args:
            csr_pem: Certificate Signing Request in PEM format
            private_key: RSA private key
            challenge_port: Port for HTTP-01 challenge server
            start_time_total: Start time for total timing
            cert_type: Type of certificate ("Plain" or "SGX")

        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        import time as time_module

        # 2. Create ACME order
        self.logger.info("\n[2/5] Creating ACME order...")
        acme = self._get_acme_client()

        try:
            start_time_step = time_module.perf_counter()
            order = acme.new_order(csr_pem)
            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ Order created: {order.uri}")
            self.logger.info(f"  Status: {order.body.status}")
            self.logger.info(f"  Authorizations: {len(order.body.authorizations)}")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")
        except Exception as e:
            raise RuntimeError(f"Failed to create ACME order: {e}")

        # 3. Complete HTTP-01 challenges
        self.logger.info("\n[3/5] Completing HTTP-01 challenges...")
        challenge_server = None
        start_time_step = time_module.perf_counter()

        # Collect all tokens first
        tokens = {}  # token -> validation mapping

        try:
            # Note: order.authorizations is a list of authorization objects, not URLs
            for authz in order.authorizations:
                domain = authz.body.identifier.value
                self.logger.info(f"  Processing authorization for: {domain}")

                # Find HTTP-01 challenge
                http01_challenges = [
                    c for c in authz.body.challenges
                    if isinstance(c.chall, challenges.HTTP01)
                ]

                if not http01_challenges:
                    raise RuntimeError(f"No HTTP-01 challenge found for {domain}")

                challb = http01_challenges[0]
                response, validation = challb.response_and_validation(self._account_key)

                # Collect token and validation
                token_str = challb.chall.encode("token")
                tokens[token_str] = validation

                # Start challenge server with all tokens
                if challenge_server is None:
                    challenge_server = self._start_challenge_server(
                        challenge_port,
                        tokens
                    )

                # Answer challenge
                acme.answer_challenge(challb, response)
                self.logger.info(f"  ✓ Challenge answered for {domain}")

            # Wait for validation - keep server running!
            # Give Pebble enough time to complete all 3 validation attempts
            self.logger.info("  Waiting for challenge validation...")
            time.sleep(5)

            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ Challenge answered")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")

        except Exception as e:
            if challenge_server:
                challenge_server.shutdown()
            raise RuntimeError(f"Challenge completion failed: {e}")

        # 4. Poll and finalize order (polls authorizations until valid, then finalizes)
        # NOTE: Challenge server must stay running during polling/finalization!
        self.logger.info("\n[4/5] Polling and finalizing order...")
        try:
            start_time_step = time_module.perf_counter()
            order = acme.poll_and_finalize(order)
            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ Order finalized")
            self.logger.info(f"  Status: {order.body.status}")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")
        except Exception as e:
            self.logger.error(f"Order finalization error details: {str(e)}")
            self.logger.error(f"Error type: {type(e).__name__}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            if challenge_server:
                challenge_server.shutdown()
            raise RuntimeError(f"Order finalization failed: {e}")

        # 5. Download certificate
        self.logger.info("\n[5/5] Downloading certificate...")
        try:
            start_time_step = time_module.perf_counter()
            fullchain_pem = order.fullchain_pem
            if not fullchain_pem:
                raise RuntimeError("Certificate not available")

            elapsed_ms = (time_module.perf_counter() - start_time_step) * 1000
            self.logger.info(f"✓ Certificate downloaded ({len(fullchain_pem)} bytes)")
            self.logger.info(f"  ⏱ Time: {elapsed_ms:.2f} ms")

            # Export private key
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Total ACME timing
            elapsed_total_ms = (time_module.perf_counter() - start_time_total) * 1000

            self.logger.info("\n" + "="*60)
            self.logger.info(f"✅ {cert_type} certificate successfully obtained!")
            self.logger.info(f"  ⏱ Total ACME flow time: {elapsed_total_ms:.2f} ms")
            self.logger.info("="*60)

            return fullchain_pem.encode(), key_pem

        except Exception as e:
            raise RuntimeError(f"Certificate download failed: {e}")
        finally:
            # Shutdown challenge server after ACME flow completes
            if challenge_server:
                challenge_server.shutdown()
                self.logger.info("✓ Challenge server stopped")

    def _start_challenge_server(
        self,
        port: int,
        tokens: dict
    ) -> http.server.HTTPServer:
        """
        Start HTTP server to respond to HTTP-01 challenges.

        Args:
            port: Port to listen on
            tokens: Dictionary mapping token -> validation string

        Returns:
            HTTPServer instance
        """
        class ChallengeHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.logger.info(f"Challenge request: {self.path}")
                # Extract token from path
                if self.path.startswith("/.well-known/acme-challenge/"):
                    requested_token = self.path.split("/")[-1]
                    if requested_token in tokens:
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(tokens[requested_token].encode())
                        self.server.logger.info(f"✓ Served validation for token: {requested_token}")
                    else:
                        self.server.logger.warning(f"Unknown token requested: {requested_token}")
                        self.server.logger.warning(f"  Available tokens: {list(tokens.keys())}")
                        self.send_error(404)
                else:
                    self.server.logger.warning(f"Invalid challenge path: {self.path}")
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # Silence default logs

        server = http.server.HTTPServer(('0.0.0.0', port), ChallengeHandler)
        server.logger = self.logger  # Pass logger to server for challenge handler
        server.tokens = tokens  # Store tokens reference in server
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        self.logger.info(f"✓ Challenge server started on port {port}")
        self.logger.info(f"  Serving {len(tokens)} token(s):")
        for token in tokens.keys():
            self.logger.info(f"    - {token}")
        return server


    def get_certificate_from_csr(
        self,
        csr_pem: bytes,
        private_key,
        challenge_port: int = 5002
    ) -> Tuple[bytes, bytes]:
        """
        Request certificate from Pebble CA using a pre-built CSR.

        Use this when you need full control over CSR extensions (e.g., embedding
        both a JWT token and a CA certificate as custom X.509 extensions).

        Args:
            csr_pem: Pre-built CSR in PEM format (may contain any extensions)
            private_key: RSA private key matching the CSR's public key
            challenge_port: Port for HTTP-01 challenge server

        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        import time as time_module
        start_time_total = time_module.perf_counter()

        self.logger.info("="*60)
        self.logger.info("ACME Certificate Request (pre-built CSR)")
        self.logger.info("="*60)

        return self._complete_acme_flow(
            csr_pem,
            private_key,
            challenge_port,
            start_time_total,
            cert_type="Custom"
        )


if __name__ == "__main__":
    # Test ACME client
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    print("Testing ACME client...")
    print("Note: This will fail without Pebble running\n")

    try:
        # Generate test key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Create ACME client
        acme_client = ACMEClient(logger=logger)

        # Try to get plain certificate
        cert_pem, key_pem = acme_client.get_certificate(
            private_key,
            common_name="localhost"
        )

        print(f"\n✅ Successfully obtained certificate!")
        print(f"Certificate: {len(cert_pem)} bytes")
        print(f"Key: {len(key_pem)} bytes")

    except Exception as e:
        print(f"\n⚠ Expected failure (no Pebble): {e}")
