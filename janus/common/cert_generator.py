# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Certificate Extensions Library - Pure Python Implementation

This module provides pure Python methods to generate X.509 certificates
with SGX attestation extensions embedded.

Usage:
    from janus.common.cert_generator import CertExtGenerator

    gen = CertExtGenerator()
    csr_pem = gen.create_csr_with_sgx_quote(private_key, common_name)
"""

import hashlib
import logging
from typing import Optional, Tuple, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from janus.common.attestation_verifier import get_attestation_verifier
except ImportError:
    from janus.common.attestation_verifier import get_attestation_verifier


class CertExtGenerator:
    """
    Pure Python certificate generator with SGX attestation extensions.

    This class provides methods to generate CSRs and certificates
    with SGX quotes embedded as X.509 extensions.
    """

    def __init__(self):
        """Initialize the certificate generator."""
        pass

    def read_sgx_quote(self) -> bytes:
        """
        Read SGX quote from /dev/attestation/quote.

        Returns:
            SGX quote as bytes

        Raises:
            RuntimeError: If quote cannot be read
        """
        try:
            with open("/dev/attestation/quote", "rb") as f:
                quote_bytes = f.read()
            if not quote_bytes:
                raise RuntimeError("SGX quote is empty")
            return quote_bytes
        except FileNotFoundError:
            raise RuntimeError("SGX attestation device not available: /dev/attestation/quote")
        except Exception as e:
            raise RuntimeError(f"Failed to read SGX quote: {e}")

    def write_report_data(self, data: bytes):
        """
        Write data to /dev/attestation/user_report_data.

        This data will be included in the REPORTDATA field of the next
        SGX quote read from /dev/attestation/quote.

        Args:
            data: Data to write (up to 64 bytes)
        """
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(data)
        except Exception as e:
            raise RuntimeError(f"Failed to write report data: {e}")

    def create_csr_with_sgx_quote(
        self,
        private_key,
        common_name: str,
        dns_names: Optional[list] = None,
        ip_addresses: Optional[list] = None,
        verify_attestation: bool = True,
        attestation_url: Optional[str] = None,
        expected_mrenclave: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ) -> Tuple[bytes, Optional[dict]]:
        """
        Create a Certificate Signing Request with SGX quote embedded as extension.

        This is the key function for the ACME flow: creates a CSR that can be
        sent to Pebble CA for signing.

        **NEW:** Now includes server-side attestation verification before CSR creation.

        Args:
            private_key: RSA private key (cryptography object)
            common_name: Common name for the certificate (e.g., "localhost")
            dns_names: Optional list of DNS SANs (defaults to [common_name])
            ip_addresses: Optional list of IP addresses to include in SAN (e.g., ["127.0.0.1"])
            verify_attestation: Whether to verify quote via Azure MAA (default: True)
            attestation_url: Azure MAA endpoint URL (optional)
            expected_mrenclave: Expected MRENCLAVE value for verification (optional)
            logger: Logger instance (optional)

        Returns:
            Tuple of (csr_pem: bytes, attestation_result: Optional[dict])

        Raises:
            RuntimeError: If quote cannot be read, verification fails, or CSR creation fails
        """
        if logger is None:
            logger = logging.getLogger(__name__)

        # Get public key in PEM format for attestation binding (matches Duet's approach)
        logger.info("Preparing public key for REPORTDATA binding...")
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Write SHA256(public_key_pem) to /dev/attestation/user_report_data
        # This MUST be done BEFORE reading the quote
        # Using PEM encoding to match Duet's implementation exactly
        report_data = hashlib.sha256(public_key_pem).digest()
        logger.info(f"Writing REPORTDATA: {report_data.hex()[:64]}...")
        self.write_report_data(report_data)
        logger.info("✓ REPORTDATA written to /dev/attestation/user_report_data")

        # NOW read SGX quote (it will contain the REPORTDATA we just wrote)
        logger.info("Reading SGX quote from enclave...")
        quote = self.read_sgx_quote()
        logger.info(f"✓ SGX quote read successfully ({len(quote)} bytes)")

        # Server-side attestation verification
        attestation_result = None
        if verify_attestation:
            logger.info("")
            logger.info("="*60)
            logger.info("SERVER-SIDE ATTESTATION VERIFICATION")
            logger.info("="*60)

            try:
                # Create attestation verifier
                verifier = get_attestation_verifier(
                    attestation_url=attestation_url,
                    expected_mrenclave=expected_mrenclave,
                    logger=logger
                )

                # Verify quote via Azure MAA
                # Pass PEM-encoded public key (matches Duet's client-side approach)
                success, attestation_result = verifier.verify_quote(
                    quote=quote,
                    public_key_pem=public_key_pem
                )

                if not success:
                    error_msg = "SGX quote verification FAILED via Azure MAA"
                    logger.error(error_msg)
                    if attestation_result:
                        logger.error(f"Details: {attestation_result}")
                    raise RuntimeError(error_msg)

                logger.info("="*60)
                logger.info("✅ Quote verification PASSED - Proceeding with CSR creation")
                logger.info("="*60)
                logger.info("")

            except Exception as e:
                logger.error(f"Attestation verification error: {e}")
                raise RuntimeError(f"Failed to verify SGX quote: {e}")
        else:
            logger.warning("⚠ Skipping attestation verification (verify_attestation=False)")
            logger.warning("  This should ONLY be used for testing!")

        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # DNS SANs
        if dns_names is None:
            dns_names = [common_name]

        san_list = [x509.DNSName(name) for name in dns_names]
        
        # IP address SANs
        if ip_addresses:
            import ipaddress
            for ip in ip_addresses:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    san_list.append(x509.IPAddress(ip_obj))
                    logger.info(f"✓ Added IP address to SAN: {ip}")
                except ValueError as e:
                    logger.warning(f"⚠ Invalid IP address '{ip}': {e}")
        
        san_extension = x509.SubjectAlternativeName(san_list)

        # Build CSR
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)

        # Add SAN extension
        csr_builder = csr_builder.add_extension(
            san_extension,
            critical=False
        )

        # Add attestation token (JWT) as extension
        # This contains all necessary information including REPORTDATA binding
        if attestation_result and attestation_result.get("token"):
            try:
                attestation_oid = x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1")
                token_bytes = attestation_result["token"].encode('utf-8')
                attestation_ext = x509.UnrecognizedExtension(attestation_oid, token_bytes)
                csr_builder = csr_builder.add_extension(
                    attestation_ext,
                    critical=False
                )
                logger.info("✓ Attestation token (JWT) added to CSR (OID 1.3.6.1.4.1.99999.3.1)")
                logger.info(f"  JWT contains x-ms-sgx-ehd (REPORTDATA) for public key binding")
            except Exception as e:
                logger.warning(f"Could not add attestation token to CSR: {e}")
        else:
            logger.warning("⚠ No attestation token available - CSR will not contain SGX attestation")

        # Sign CSR
        csr = csr_builder.sign(private_key, hashes.SHA256())

        logger.info(f"✓ CSR created and signed ({len(csr.public_bytes(serialization.Encoding.PEM))} bytes)")

        # Return PEM-encoded CSR and attestation result
        return csr.public_bytes(serialization.Encoding.PEM), attestation_result


# Singleton instance
_cert_generator = None


def get_cert_generator() -> CertExtGenerator:
    """
    Get or create the singleton CertExtGenerator instance.

    Returns:
        CertExtGenerator instance
    """
    global _cert_generator
    if _cert_generator is None:
        _cert_generator = CertExtGenerator()
    return _cert_generator


def read_sgx_quote() -> bytes:
    """
    Helper function to read SGX quote.

    Returns:
        SGX quote as bytes
    """
    return get_cert_generator().read_sgx_quote()
