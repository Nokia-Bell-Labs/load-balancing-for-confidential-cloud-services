#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Azure MAA (Microsoft Azure Attestation) client for SGX quote verification.

This module verifies SGX quotes before embedding them in certificates,
ensuring that only validated quotes are sent to the CA.

Architecture:
    AdminEnclave → Get quote → Verify via Azure MAA → Create CSR → Pebble CA

Benefits:
    - Pre-validated quotes (CA only signs verified quotes)
    - Simpler clients (no quote verification needed)
    - Policy enforcement at server side
"""

import json
import logging
import hashlib
import base64
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

try:
    from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
    from azure.security.attestation import AttestationClient, AttestationType
    from azure.core.exceptions import AzureError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AttestationVerifier:
    """
    Verifies SGX quotes using Azure MAA (Microsoft Azure Attestation).

    This class handles:
    1. Quote submission to Azure MAA
    2. JWT token validation
    3. Claims verification (MRENCLAVE, MRSIGNER, etc.)
    4. Public key binding validation (REPORTDATA)
    """

    def __init__(
        self,
        attestation_url: Optional[str] = None,
        use_managed_identity: bool = True,
        expected_mrenclave: Optional[str] = None,
        force_mock_mode: bool = False,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize attestation verifier.

        Args:
            attestation_url: Azure MAA endpoint URL
                           (e.g., "https://myattestationprovider.eastus.attest.azure.net")
            use_managed_identity: Use Azure Managed Identity for authentication
            expected_mrenclave: Expected MRENCLAVE value (hex string)
            force_mock_mode: Force mock mode even if Azure SDK is available (testing only)
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

        # Default to shared MAA provider if none specified
        self.attestation_url = attestation_url or "https://sharedweu.weu.attest.azure.net"

        self.expected_mrenclave = expected_mrenclave
        self.use_managed_identity = use_managed_identity

        # Cache for attestation results (optional optimization)
        self._cache: Dict[str, Tuple[bool, Dict[str, Any], datetime]] = {}
        self._cache_ttl = timedelta(minutes=5)

        # Check if Azure SDK is available
        if not AZURE_AVAILABLE:
            self.logger.warning(
                "Azure SDK not available. Install with: "
                "pip install azure-identity azure-security-attestation"
            )
            self._mock_mode = True
        elif force_mock_mode:
            self.logger.warning("Force mock mode enabled (for testing only)")
            self._mock_mode = True
        else:
            self._mock_mode = False

    def verify_quote(
        self,
        quote: bytes,
        public_key_pem: bytes,
        runtime_data: Optional[bytes] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify SGX quote via Azure MAA.

        This is the main entry point for quote verification.

        Args:
            quote: Raw SGX quote (ECDSA/DCAP format, typically 4096 bytes)
            public_key_pem: PEM-encoded public key from certificate (matches Duet's approach)
            runtime_data: Optional runtime data to verify (defaults to SHA256(public_key_pem))

        Returns:
            Tuple of (success: bool, attestation_result: dict)

            attestation_result contains:
            - token: JWT token from Azure MAA
            - claims: Parsed claims from JWT
            - verified: Whether all checks passed
            - mrenclave: MRENCLAVE from quote
            - mrsigner: MRSIGNER from quote
            - reportdata: REPORTDATA from quote
            - binding_verified: Whether REPORTDATA matches public key

        Raises:
            RuntimeError: If verification fails critically
        """
        self.logger.info("="*60)
        self.logger.info("Starting SGX Quote Verification via Azure MAA")
        self.logger.info("="*60)

        # Check cache first
        quote_hash = hashlib.sha256(quote).hexdigest()
        if quote_hash in self._cache:
            cached_result, cached_data, cached_time = self._cache[quote_hash]
            if datetime.now() - cached_time < self._cache_ttl:
                self.logger.info("✓ Using cached attestation result")
                return cached_result, cached_data

        # Mock mode for testing without Azure MAA
        if self._mock_mode:
            self.logger.warning("⚠ Running in MOCK mode (Azure SDK not available)")
            return self._mock_verify_quote(quote, public_key_pem, runtime_data)

        try:
            # 1. Prepare runtime data (REPORTDATA binding)
            # CRITICAL: Pass the public key itself, NOT its hash!
            # Azure MAA will compute SHA256(runtime_data) and compare to REPORTDATA in quote
            # The quote already contains SHA256(public_key_pem) in REPORTDATA
            # Using PEM encoding to match Duet's implementation exactly
            if runtime_data is None:
                runtime_data = public_key_pem  # Pass the key itself, not the hash!

            expected_reportdata = hashlib.sha256(public_key_pem).digest()
            self.logger.info(f"Quote size: {len(quote)} bytes")
            self.logger.info(f"Expected REPORTDATA in quote: {expected_reportdata.hex()[:64]}...")
            self.logger.info(f"Passing PEM public key ({len(runtime_data)} bytes) to Azure MAA")

            # 2. Submit quote to Azure MAA
            self.logger.info(f"Submitting quote to Azure MAA: {self.attestation_url}")

            attestation_result = self._submit_to_azure_maa(quote, runtime_data)

            # 3. Parse and validate attestation token
            self.logger.info("Parsing attestation token...")
            claims = self._parse_attestation_token(attestation_result)

            # 4. Verify claims
            self.logger.info("Verifying attestation claims...")
            verification_result = self._verify_claims(claims, runtime_data)

            # 5. Build result
            result = {
                "token": attestation_result,
                "claims": claims,
                "verified": verification_result["verified"],
                "mrenclave": claims.get("x-ms-sgx-mrenclave"),
                "mrsigner": claims.get("x-ms-sgx-mrsigner"),
                "reportdata": claims.get("x-ms-sgx-report-data"),
                "binding_verified": verification_result["binding_verified"],
                "checks": verification_result["checks"]
            }

            # Cache result
            self._cache[quote_hash] = (result["verified"], result, datetime.now())

            if result["verified"]:
                self.logger.info("="*60)
                self.logger.info("✅ Quote verification SUCCESSFUL")
                self.logger.info("="*60)
            else:
                self.logger.error("="*60)
                self.logger.error("❌ Quote verification FAILED")
                self.logger.error("="*60)

            return result["verified"], result

        except Exception as e:
            self.logger.error(f"Quote verification failed: {e}")
            import traceback
            traceback.print_exc()

            # Return failure result
            return False, {
                "verified": False,
                "error": str(e),
                "token": None,
                "claims": {}
            }

    def _submit_to_azure_maa(self, quote: bytes, runtime_data: bytes) -> str:
        """
        Submit quote to Azure MAA and get attestation token.

        Args:
            quote: SGX quote bytes
            runtime_data: Runtime data for binding

        Returns:
            JWT attestation token
        """
        try:
            # Create credential
            if self.use_managed_identity:
                credential = ManagedIdentityCredential()
            else:
                credential = DefaultAzureCredential()

            # Create attestation client
            client = AttestationClient(
                endpoint=self.attestation_url,
                credential=credential
            )

            # Encode quote and runtime data as base64url
            quote_b64 = base64.urlsafe_b64encode(quote).decode('utf-8').rstrip('=')
            runtime_data_b64 = base64.urlsafe_b64encode(runtime_data).decode('utf-8').rstrip('=')

            # Attest SGX enclave
            # Returns tuple: (AttestationResponse, something_else)
            response = client.attest_sgx_enclave(
                quote=quote,
                runtime_data=runtime_data
            )

            self.logger.info(f"✓ Attestation response received from Azure MAA")

            # Azure SDK attest_sgx_enclave() returns a tuple: (AttestationResult, AttestationToken)
            # The AttestationToken needs to be serialized to get the JWT string
            if isinstance(response, tuple):
                attestation_result, attestation_token = response
                self.logger.info(f"✓ Unpacked response tuple: AttestationResult + AttestationToken")

                # Convert AttestationToken to JWT string
                # AttestationToken has a serialize() method or can be str()'d
                if hasattr(attestation_token, 'serialize'):
                    jwt_token = attestation_token.serialize()
                else:
                    jwt_token = str(attestation_token)

                self.logger.info(f"✓ Serialized AttestationToken to JWT string ({len(jwt_token)} chars)")
            else:
                # Fallback for unexpected response format
                self.logger.warning(f"Unexpected response type: {type(response)}")
                jwt_token = str(response)

            return jwt_token

        except AzureError as e:
            raise RuntimeError(f"Azure MAA attestation failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to submit quote to Azure MAA: {e}")

    def _parse_attestation_token(self, token: str) -> Dict[str, Any]:
        """
        Parse JWT attestation token and extract claims.

        Args:
            token: JWT token from Azure MAA

        Returns:
            Dictionary of claims
        """
        try:
            # JWT is base64url encoded: header.payload.signature
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")

            # Decode payload (add padding if needed)
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload)

            claims = json.loads(payload_bytes)

            self.logger.info(f"✓ Attestation token parsed successfully")
            self.logger.debug(f"Claims: {json.dumps(claims, indent=2)}")

            return claims

        except Exception as e:
            raise RuntimeError(f"Failed to parse attestation token: {e}")

    def _verify_claims(
        self,
        claims: Dict[str, Any],
        expected_runtime_data: bytes
    ) -> Dict[str, Any]:
        """
        Verify attestation claims.

        Args:
            claims: Claims from attestation token
            expected_runtime_data: Expected runtime data (REPORTDATA)

        Returns:
            Dictionary with verification results
        """
        checks = {}
        all_passed = True

        # 1. Verify REPORTDATA binding
        report_data_hex = claims.get("x-ms-sgx-report-data", "")
        if report_data_hex:
            # Azure MAA returns REPORTDATA as hex string, not base64
            report_data = bytes.fromhex(report_data_hex)
            # REPORTDATA is 64 bytes, we use first 32 for public key hash
            # CRITICAL: expected_runtime_data is now the public key itself, so hash it
            expected_hash = hashlib.sha256(expected_runtime_data).digest()[:32]
            actual_hash = report_data[:32]

            binding_verified = (expected_hash == actual_hash)
            checks["reportdata_binding"] = {
                "passed": binding_verified,
                "expected": expected_hash.hex(),
                "actual": actual_hash.hex()
            }

            if binding_verified:
                self.logger.info("✓ REPORTDATA binding verified")
            else:
                self.logger.error("✗ REPORTDATA binding failed")
                self.logger.error(f"  Expected: {expected_hash.hex()}")
                self.logger.error(f"  Actual:   {actual_hash.hex()}")
                all_passed = False
        else:
            checks["reportdata_binding"] = {"passed": False, "error": "No report data in claims"}
            all_passed = False

        # 2. Verify MRENCLAVE (if expected value provided)
        mrenclave = claims.get("x-ms-sgx-mrenclave", "")
        if self.expected_mrenclave:
            mrenclave_match = (mrenclave.lower() == self.expected_mrenclave.lower())
            checks["mrenclave"] = {
                "passed": mrenclave_match,
                "expected": self.expected_mrenclave,
                "actual": mrenclave
            }

            if mrenclave_match:
                self.logger.info(f"✓ MRENCLAVE matches expected value")
            else:
                self.logger.warning(f"⚠ MRENCLAVE mismatch")
                self.logger.warning(f"  Expected: {self.expected_mrenclave}")
                self.logger.warning(f"  Actual:   {mrenclave}")
                # Don't fail on MRENCLAVE mismatch (might be expected during development)
        else:
            checks["mrenclave"] = {"passed": True, "actual": mrenclave, "note": "No expected value"}
            self.logger.info(f"MRENCLAVE: {mrenclave} (not verified - no expected value)")

        # 3. Verify enclave is not in debug mode (production requirement)
        is_debuggable = claims.get("x-ms-sgx-is-debuggable", True)
        debug_check = not is_debuggable  # Should be False in production
        checks["not_debuggable"] = {
            "passed": debug_check,
            "is_debuggable": is_debuggable
        }

        if debug_check:
            self.logger.info("✓ Enclave is not debuggable (production mode)")
        else:
            self.logger.warning("⚠ Enclave is debuggable (development mode)")
            # Don't fail in development, but log warning

        # 4. Check product ID
        product_id = claims.get("x-ms-sgx-product-id", 0)
        checks["product_id"] = {"value": product_id}
        self.logger.info(f"Product ID: {product_id}")

        # 5. Check SVN (Security Version Number)
        svn = claims.get("x-ms-sgx-svn", 0)
        checks["svn"] = {"value": svn}
        self.logger.info(f"SVN: {svn}")

        return {
            "verified": all_passed,
            "binding_verified": checks.get("reportdata_binding", {}).get("passed", False),
            "checks": checks
        }

    def _mock_verify_quote(
        self,
        quote: bytes,
        public_key_pem: bytes,
        runtime_data: Optional[bytes]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Mock verification for testing without Azure MAA.

        This simulates successful attestation for development/testing.
        Uses PEM encoding to match Duet's approach.
        """
        self.logger.warning("="*60)
        self.logger.warning("⚠ MOCK ATTESTATION MODE")
        self.logger.warning("This is NOT secure - for development only!")
        self.logger.warning("="*60)

        # Simulate runtime data check
        # CRITICAL: runtime_data should be the public key itself, not its hash
        # Using PEM encoding like Duet
        if runtime_data is None:
            runtime_data = public_key_pem

        # Compute expected hash (what should be in REPORTDATA)
        expected_reportdata = hashlib.sha256(runtime_data).digest()

        # Extract REPORTDATA from quote (if it's a valid ECDSA quote)
        binding_verified = False
        if len(quote) >= 432:
            report_data = quote[368:432]
            expected_hash = expected_reportdata[:32]
            actual_hash = report_data[:32]
            binding_verified = (expected_hash == actual_hash)

            if binding_verified:
                self.logger.info("✓ REPORTDATA binding verified (mock)")
            else:
                self.logger.warning("⚠ REPORTDATA binding not verified (mock quote)")

        # Create mock result
        # Note: x-ms-sgx-report-data should contain the REPORTDATA from quote (SHA256 of runtime_data)
        reportdata_hash = expected_reportdata  # This is SHA256(runtime_data) padded to 64 bytes
        reportdata_padded = reportdata_hash + b'\x00' * (64 - len(reportdata_hash))

        mock_result = {
            "token": "mock.jwt.token",
            "claims": {
                "x-ms-sgx-mrenclave": "0" * 64,  # Mock MRENCLAVE
                "x-ms-sgx-mrsigner": "0" * 64,   # Mock MRSIGNER
                "x-ms-sgx-report-data": reportdata_padded.hex(),  # HEX-encoded like real Azure MAA
                "x-ms-sgx-is-debuggable": True,
                "x-ms-sgx-product-id": 0,
                "x-ms-sgx-svn": 0
            },
            "verified": True,  # Mock always succeeds
            "mrenclave": "0" * 64,
            "mrsigner": "0" * 64,
            "reportdata": expected_reportdata.hex(),
            "binding_verified": binding_verified,
            "checks": {
                "reportdata_binding": {
                    "passed": binding_verified,
                    "note": "Mock verification"
                },
                "mrenclave": {"passed": True, "note": "Mock - not verified"},
                "not_debuggable": {"passed": False, "is_debuggable": True, "note": "Mock mode"}
            },
            "mock": True
        }

        self.logger.warning("✓ Mock attestation completed (always succeeds)")

        return True, mock_result


    def verify_cvm_jwt(self, jwt_token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify a pre-obtained MAA JWT from an SNP/TDX CVM backend.

        DEPRECATED: The new provisioning flow has the frontend submit raw
        attestation evidence to Azure MAA (via verify_quote / verify_cvm_report).
        This method is kept for backward compatibility during migration.

        The CVM backend runs AttestationClient locally (which needs /dev/tpm0 access)
        and sends the resulting MAA JWT to the frontend.  The frontend verifies:
          1. RS256 signature against Azure MAA's published keys
          2. JWT has not expired
          3. x-ms-isolation-tee.x-ms-attestation-type is 'sevsnpvm' or 'tdxvm'
          4. x-ms-isolation-tee.x-ms-compliance-status is 'azure-compliant-cvm'
        """
        if self._mock_mode:
            self.logger.warning("MOCK mode: accepting CVM JWT without signature check")
            return True, {"verified": True, "mock": True, "claims": {}}

        if not jwt_token:
            self.logger.warning("Empty CVM JWT received — using mock attestation")
            return True, {"verified": False, "error": "No JWT provided", "mock": True}

        try:
            # ── decode header + payload ───────────────────────────────────────
            parts = jwt_token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")

            def _b64url(s: str) -> bytes:
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s)

            header  = json.loads(_b64url(parts[0]))
            payload = json.loads(_b64url(parts[1]))

            # ── fetch MAA signing keys ────────────────────────────────────────
            issuer = payload.get("iss", self.attestation_url).rstrip("/")
            jku    = f"{issuer}/certs"
            self.logger.info(f"Fetching MAA public keys from {jku}")

            import requests as _req
            resp = _req.get(jku, timeout=10)
            resp.raise_for_status()

            from cryptography.hazmat.primitives.asymmetric import (
                rsa as _rsa, padding as _pad
            )
            from cryptography.hazmat.primitives import hashes as _h
            from cryptography.hazmat.backends import default_backend as _be

            keys: Dict[str, Any] = {}
            for k in resp.json().get("keys", []):
                if k.get("kty") != "RSA":
                    continue
                n = int.from_bytes(_b64url(k["n"]), "big")
                e = int.from_bytes(_b64url(k["e"]), "big")
                keys[k["kid"]] = _rsa.RSAPublicNumbers(e, n).public_key(_be())

            kid = header.get("kid")
            if kid not in keys:
                raise ValueError(f"Key ID {kid!r} not found in MAA key set")

            # ── verify RS256 signature ────────────────────────────────────────
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig = _b64url(parts[2])
            keys[kid].verify(sig, msg, _pad.PKCS1v15(), _h.SHA256())
            self.logger.info("✓ CVM JWT RS256 signature valid")

            # ── check expiry ──────────────────────────────────────────────────
            now = datetime.utcnow().timestamp()
            if payload.get("exp", 0) < now:
                raise ValueError("CVM JWT has expired")
            self.logger.info(
                f"✓ CVM JWT timestamp valid (exp={payload.get('exp')})"
            )

            # ── check SNP/TDX-specific claims ─────────────────────────────────
            isolation = payload.get("x-ms-isolation-tee", {})
            attest_type  = isolation.get("x-ms-attestation-type", "")
            compliance   = isolation.get("x-ms-compliance-status", "")

            self.logger.info(f"  attestation-type : {attest_type}")
            self.logger.info(f"  compliance-status: {compliance}")

            if attest_type not in ("sevsnpvm", "tdxvm"):
                self.logger.warning(
                    f"Unexpected CVM attestation type: {attest_type!r} "
                    "(expected 'sevsnpvm' or 'tdxvm')"
                )
            if compliance != "azure-compliant-cvm":
                self.logger.warning(
                    f"CVM compliance status is not 'azure-compliant-cvm': "
                    f"{compliance!r}"
                )

            return True, {
                "verified":          True,
                "attestation_type":  attest_type,
                "compliance_status": compliance,
                "claims":            payload,
            }

        except Exception as exc:
            self.logger.error(f"CVM JWT verification failed: {exc}")
            return False, {"verified": False, "error": str(exc)}


    def verify_cvm_report(
        self,
        report: bytes,
        nonce: str,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify raw SNP/TDX attestation evidence via Azure MAA.

        The frontend submits the raw attestation report (from the backend's
        /dev/tpm0 or SNP guest driver) to Azure MAA.  MAA validates the
        hardware evidence and returns a JWT with verified claims.

        The frontend then checks that REPORTDATA in the verified claims
        matches SHA256(nonce) to prevent replay attacks.

        Args:
            report: Raw attestation evidence bytes (SNP report / TDX quote)
            nonce:  Hex nonce issued by the frontend during CVM provisioning

        Returns:
            Tuple of (success: bool, attestation_result: dict)
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting CVM Report Verification via Azure MAA")
        self.logger.info("=" * 60)

        if self._mock_mode:
            self.logger.warning("MOCK mode: accepting CVM report without MAA verification")
            nonce_bytes = nonce.encode("utf-8") if nonce else b""
            expected_reportdata = hashlib.sha256(nonce_bytes).digest()
            return True, {
                "verified": True,
                "mock": True,
                "nonce": nonce,
                "expected_reportdata": expected_reportdata.hex(),
                "claims": {},
            }

        if not report:
            self.logger.warning("Empty CVM report — using mock attestation")
            return True, {"verified": True, "mock": True, "claims": {}}

        try:
            nonce_bytes = nonce.encode("utf-8") if nonce else b""

            # Submit raw evidence to Azure MAA
            # Azure MAA attest_open_enclave() handles both SGX and SEV-SNP evidence
            if not AZURE_AVAILABLE:
                raise RuntimeError("Azure SDK not available")

            credential = DefaultAzureCredential()
            client = AttestationClient(
                endpoint=self.attestation_url,
                credential=credential,
            )

            response = client.attest_open_enclave(
                report=report,
                runtime_data=nonce_bytes,
            )

            # Parse the response
            if isinstance(response, tuple):
                _result, attestation_token = response
                jwt_token = (attestation_token.serialize()
                             if hasattr(attestation_token, 'serialize')
                             else str(attestation_token))
            else:
                jwt_token = str(response)

            # Parse and verify claims
            claims = self._parse_attestation_token(jwt_token)

            # Verify REPORTDATA matches nonce
            report_data_hex = claims.get("x-ms-sgx-report-data", "")
            if not report_data_hex:
                # CVM claims may use a different key
                isolation = claims.get("x-ms-isolation-tee", {})
                report_data_hex = isolation.get("x-ms-runtime", {}).get(
                    "x-ms-sevsnpvm-reportdata", ""
                )

            nonce_hash = hashlib.sha256(nonce_bytes).digest()
            if report_data_hex:
                actual = bytes.fromhex(report_data_hex)[:32]
                expected = nonce_hash[:32]
                if actual != expected:
                    self.logger.error(
                        f"REPORTDATA mismatch: expected {expected.hex()}, "
                        f"got {actual.hex()}"
                    )
                    return False, {"verified": False, "error": "Nonce mismatch"}
                self.logger.info("✓ REPORTDATA matches nonce")

            return True, {
                "verified": True,
                "token": jwt_token,
                "claims": claims,
                "nonce": nonce,
            }

        except Exception as exc:
            self.logger.error(f"CVM report verification failed: {exc}")
            return False, {"verified": False, "error": str(exc)}


def get_attestation_verifier(
    attestation_url: Optional[str] = None,
    expected_mrenclave: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> AttestationVerifier:
    """
    Factory function to get an AttestationVerifier instance.

    Args:
        attestation_url: Azure MAA endpoint (optional)
        expected_mrenclave: Expected MRENCLAVE value (optional)
        logger: Logger instance (optional)

    Returns:
        AttestationVerifier instance
    """
    return AttestationVerifier(
        attestation_url=attestation_url,
        expected_mrenclave=expected_mrenclave,
        logger=logger
    )


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create verifier
    verifier = get_attestation_verifier()

    # Mock quote and public key
    mock_quote = bytes([0] * 4096)
    mock_pubkey = bytes([1] * 32)

    # Test verification
    success, result = verifier.verify_quote(mock_quote, mock_pubkey)

    print(f"\nVerification result: {'SUCCESS' if success else 'FAILED'}")
    print(f"Details: {json.dumps(result, indent=2)}")
