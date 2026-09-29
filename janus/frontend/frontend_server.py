# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Frontend Server for multi-server Janus

Extends the Janus attestation model to support a pool of attested back-end servers.
The frontend server runs in an Intel SGX enclave (Gramine) and acts as:
  1. Attestation root  – verifies back-end TEE attestation, signs DCs and CA certs
  2. HTTPS front-end   – exposes a TLS cert with SGX JWT + DelegationUsage extension
  3. Reverse proxy     – forwards client traffic to attested back-ends

Key management
──────────────
An ECDSA-P256 server keypair is sealed to the enclave on first startup and
reloaded from sealed storage on subsequent restarts. It serves a dual
purpose: the frontend's own TLS certificate, and DC signing for backends
(the DC's signature scheme matches the issuer cert's algorithm per RFC 9345,
so this is ECDSA-P256-SHA256 in both roles).

REPORTDATA binding
──────────────────
  SHA256(server_public_key_pem)
written to /dev/attestation/user_report_data before the SGX quote is read.

TLS certificate
───────────────
The frontend requests a certificate from Pebble via ACME.  The CSR carries:
  OID 1.3.6.1.4.1.99999.3.1  – Azure MAA JWT (contains REPORTDATA binding)
  OID 1.3.6.1.4.1.44363.44   – DelegationUsage (enables DC signing per RFC 9345)
Clients use the JWT extension to verify the enclave.  DC-capable clients
(Firefox) validate DCs signed by this certificate.

Back-end provisioning
─────────────────────
The frontend provisions CVMs and passes a random nonce.  The backend
includes the nonce in its attestation REPORTDATA.  The frontend submits
raw attestation evidence to Azure MAA and verifies REPORTDATA == nonce.
On success, the frontend signs both a Delegated Credential (for DC clients)
and a CA-signed certificate (fallback).

Freshness
─────────
Normal connections derive freshness from TLS 1.3 client_random +
CertificateVerify (sealed-key liveness proof).  No per-connection quote
is generated.  The optional /attest/fresh endpoint is rate-limited to at
most one new quote per MIN_FRESH_INTERVAL seconds.
"""

from argparse import ArgumentParser
import base64
import datetime
import hashlib
import json
import logging
from logging.config import dictConfig
import os
import signal
import struct
import sys
import time
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils as asym_utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from typing import Optional

from flask import Flask, request, jsonify, abort, redirect

# ── path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..', '..'))  # repo root (parent of janus/)

from janus.common.attestation_verifier import get_attestation_verifier
from janus.common.acme_client import ACMEClient
from janus.frontend.key_store import FrontendKeyStore
from janus.frontend.backend_provisioner import BackendProvisioner

# ── constants ─────────────────────────────────────────────────────────────────
SGX_JWT_OID            = x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1")
DELEGATION_USAGE_OID   = x509.ObjectIdentifier("1.3.6.1.4.1.44363.44")

# Registration challenge nonces (design §4.3 Steps 2/5) expire after this
# many seconds; a backend fetches one from /nonce immediately before it
# produces its evidence, so a few minutes is ample.
NONCE_TTL_S = int(os.environ.get("JANUS_NONCE_TTL_S", "300"))
# Mock attestation (empty evidence accepted) is a development convenience for
# direct mode only, and must be asked for explicitly.
ALLOW_MOCK_ATTESTATION = os.environ.get("JANUS_ALLOW_MOCK_ATTESTATION") == "1"
# Certificate lifecycle (design §4.2): re-attest and re-issue when either the
# X.509 validity or the embedded AS JWT has less than RENEW_MARGIN_S left,
# checked every RENEW_CHECK_S.
RENEW_MARGIN_S = int(os.environ.get("JANUS_RENEW_MARGIN_S", "3600"))
RENEW_CHECK_S  = int(os.environ.get("JANUS_RENEW_CHECK_S", "60"))
ATTESTATION_URL  = "https://sharedweu.weu.attest.azure.net"
MIN_FRESH_INTERVAL = 60   # seconds – rate limit on /attest/fresh

# Admission policy: when set (hex string), a registering backend's attested
# SNP launch measurement must match it exactly; unset accepts any measurement
# that MAA signs (the JWT still records the actual value for the client).
EXPECTED_BACKEND_MEASUREMENT = os.environ.get("EXPECTED_BACKEND_MEASUREMENT") or None

# Only redirection mode needs an RFC 9345 Delegated Credential (clients
# connect straight to the backend); proxy mode keeps TLS terminated at the
# frontend. Set ISSUE_DC=0 to skip issuance in proxy-only deployments.
ISSUE_DC = os.environ.get("ISSUE_DC", "1").lower() not in ("0", "false", "no")


def _san_dnsnames(ip_address):
    """Frontend-cert DNS SANs: localhost + the configured address + any names in
    JANUS_EXTRA_SANS (comma-separated). In redirection mode the frontend cert is
    also presented by backends (via the DC), so it must hostname-match every
    name a browser dials -- the service name and each backend name."""
    names = ["localhost", ip_address]
    names += [x.strip() for x in os.environ.get("JANUS_EXTRA_SANS", "").split(",") if x.strip()]
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(x509.DNSName(n))
    return out


dictConfig({
    "version": 1,
    "formatters": {"default": {
        "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    }},
    "handlers": {"wsgi": {"class": "logging.StreamHandler", "formatter": "default"}},
    "root": {"level": "INFO", "handlers": ["wsgi"]},
})

app = Flask(__name__)

# Disable Nagle on the dev server's connection sockets.  Without this, the
# first request on every fresh connection eats a Nagle/delayed-ACK stall
# (~13 ms) because the small HTTP response is split across segments and the
# server holds the second segment until the client's delayed ACK arrives.
# The control/routing exchange uses one connection per request (Connection:
# close), so it would otherwise pay that stall on every attempt even though
# the handler itself is ~0.04 ms.
from werkzeug.serving import WSGIRequestHandler as _WSGIRequestHandler
_WSGIRequestHandler.disable_nagle_algorithm = True
FRONTEND_SERVER   = None
CVMs        = {}   # cvm_id → ConfidentialVM (in-memory)
PROVISIONER = None


# ═══════════════════════════════════════════════════════════════════════════════
# Core server class (direct / non-SGX mode)
# ═══════════════════════════════════════════════════════════════════════════════

class FrontendServer:
    """
    Frontend Janus server (direct mode, for testing without SGX).
    Manages two keypairs, a CA certificate, and the back-end key store.
    """

    # Subclasses can set this to False to require explicit /mark_cvm calls.
    _auto_promote_to_service = True

    def __init__(self, environment: str, logger: logging.Logger):
        self._logger = logger
        self._environment = environment
        self._ip_address = "localhost"

        # keypair (set by _init_server_keypair)
        self._server_private_key = None
        self._server_public_key  = None

        # service owner public key (RSA-PSS auth for privileged operations)
        self._service_owner_public_key_pem: bytes = b""
        self._service_owner_key_configured = False

        # rate-limit state for /attest/fresh
        self._last_fresh_at: float = 0.0
        self._fresh_lock = threading.Lock()

        # nonce tracking for backend attestation (nonce → {ip, cvm_type, timestamp})
        self._pending_nonces: dict = {}
        self._used_nonces: set = set()

        # Per-backend HTTPS upstream session pool — keyed by (ip, port).
        # `requests.Session` keeps a TCP+TLS connection pool per host, so
        # `/forward` requests after the first reuse the existing connection.
        self._backend_sessions: dict = {}
        self._backend_sessions_lock = threading.Lock()
        # Round-robin cursor for select_backend()
        self._rr_index: int = 0
        self._rr_lock = threading.Lock()
        # Certificate lifecycle state (design §4.2): the server-side TLS
        # context is kept so a renewal can be hot-loaded into the running
        # listener, and the renew lock serialises re-issuance.
        self._ssl_ctx = None
        self._renew_lock = threading.Lock()

        # sealed directory (also used as key-store location)
        if environment == "direct":
            # JANUS_SEALED_DIR lets several direct-mode instances coexist on one host.
            self._sealed_dir = os.environ.get("JANUS_SEALED_DIR", "/tmp/janus_frontend_sealed")
        else:
            app_home = os.environ.get('APP_HOME') or os.path.expanduser('~')
            self._sealed_dir = f"{app_home}/janus/frontend/sealed"

        os.makedirs(self._sealed_dir, exist_ok=True)

        self._server_key_file = os.path.join(self._sealed_dir, "server_private_key.pem")
        self._tls_cert_file   = os.path.join(self._sealed_dir, "tls_certificate.pem")

        # key store (SQLite in sealed dir)
        self._key_store = FrontendKeyStore(self._sealed_dir, logger=self._logger)

        self._load_service_owner_public_key()
        self._init_server_keypair()
        # Design §4.2, "Persistence and Fault Tolerance": a restart unseals
        # the certificate and keypair and resumes immediately; issuance runs
        # only when nothing usable is sealed (first start, expiry, update).
        if self._sealed_certificate_valid(RENEW_MARGIN_S, self._required_jwt_issuer()):
            self._logger.info(
                "Unsealed a valid TLS certificate "
                f"({self._certificate_remaining_s(self._required_jwt_issuer()) / 3600:.1f} h left) "
                "— skipping attestation and certificate issuance")
        else:
            self._init_tls_certificate()

    # ── key initialisation ──────────────────────────────────────────────────

    def _init_server_keypair(self):
        """Generate (or load) the server TLS keypair."""
        if os.path.isfile(self._server_key_file):
            with open(self._server_key_file, "rb") as f:
                pem = f.read()
            self._server_private_key = serialization.load_pem_private_key(pem, password=None)
            self._server_public_key  = self._server_private_key.public_key()
            self._logger.info("Loaded server keypair from sealed storage")
        else:
            self._server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self._server_public_key  = self._server_private_key.public_key()
            with open(self._server_key_file, "wb") as f:
                f.write(self._server_private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ))
            self._logger.info("Generated new server keypair")

    def _init_tls_certificate(self):
        """
        Obtain a TLS certificate via Pebble ACME with mock-attestation extensions
        (OID 3.1 = mock JWT, OID 3.2 = frontend CA cert).  Falls back to a plain
        self-signed cert if Pebble is unavailable.
        """
        try:
            self._logger.info("Requesting TLS certificate via Pebble ACME (direct/mock mode)…")

            # Build a proper mock JWT with the correct REPORTDATA binding
            # so the client can parse it (signature verification is skipped
            # in --mock mode since there's no real Azure MAA).
            jwt_token = self._build_mock_jwt()

            # Build CSR with OID 3.1 (mock JWT) and DelegationUsage extension (RFC 9345).
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self._ip_address),
            ])
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .add_extension(
                    x509.SubjectAlternativeName(_san_dnsnames(self._ip_address)),
                    critical=False,
                )
                .add_extension(
                    x509.UnrecognizedExtension(SGX_JWT_OID, jwt_token.encode("utf-8")),
                    critical=False,
                )
                .add_extension(
                    x509.UnrecognizedExtension(DELEGATION_USAGE_OID, b"\x05\x00"),
                    critical=False,
                )
                .sign(self._server_private_key, hashes.SHA256(), default_backend())
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            # Submit CSR to Pebble
            acme = ACMEClient(
                pebble_url="https://localhost:14000/dir",
                verify_ssl=False,
                logger=self._logger,
            )
            cert_pem, _key_pem = acme.get_certificate_from_csr(
                csr_pem=csr_pem,
                private_key=self._server_private_key,
                challenge_port=5002,
            )
            with open(self._tls_cert_file, "wb") as f:
                f.write(cert_pem)
            self._logger.info("TLS certificate with mock extensions obtained from Pebble")

        except Exception as e:
            self._logger.warning(f"Pebble ACME failed: {e} — using plain self-signed cert")
            self._init_tls_certificate_plain()

    def _init_tls_certificate_plain(self):
        """Plain self-signed cert fallback (no SGX extensions)."""
        now  = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self._ip_address)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._server_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName(_san_dnsnames(self._ip_address)),
                critical=False,
            )
            .sign(self._server_private_key, hashes.SHA256(), default_backend())
        )
        with open(self._tls_cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self._logger.info("Generated plain self-signed TLS certificate (no SGX extensions)")

    def _build_mock_jwt(self) -> str:
        """
        Build a minimal mock JWT with the correct x-ms-sgx-ehd (REPORTDATA) claim
        so that the client can verify the binding in step 4 even without real SGX.
        The signature field is the literal string "mock" — clients must use
        --mock to skip signature verification.
        """
        import time as time_mod
        pk_srv_pem = self._server_public_key_pem()
        reportdata = hashlib.sha256(pk_srv_pem).digest()
        ehd_b64    = base64.urlsafe_b64encode(reportdata).rstrip(b"=").decode()

        now = int(time_mod.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": "mock-key-1",
                  "jku": "https://mock.local/certs"}
        payload = {
            "iss": "mock",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "x-ms-sgx-ehd":           ehd_b64,
            "x-ms-sgx-mrenclave":     "0" * 64,
            "x-ms-sgx-mrsigner":      "0" * 64,
            "x-ms-sgx-is-debuggable": True,
        }
        def _b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{_b64(header)}.{_b64(payload)}.mock"

    # ── public key helpers ──────────────────────────────────────────────────

    def _server_public_key_pem(self) -> bytes:
        return self._server_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _load_service_owner_public_key(self):
        """
        Load the service owner's RSA public key for verifying privileged requests.

        Lookup order:
          1. SERVICE_OWNER_PUBLIC_KEY_PATH env var
          2. service_owner_public_key.pub in the sealed directory
        """
        candidates = [
            os.environ.get("SERVICE_OWNER_PUBLIC_KEY_PATH", ""),
            os.path.join(self._sealed_dir, "service_owner_public_key.pub"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                with open(path, "rb") as f:
                    self._service_owner_public_key_pem = f.read()
                self._service_owner_key_configured = True
                self._logger.info(f"Loaded service owner public key from {path}")
                return
        self._logger.warning(
            "Service owner public key not found — "
            "privileged operations (/start_cvm, /stop_cvm, /mark_cvm) "
            "will be open in direct mode and blocked in SGX mode"
        )

    # ── certificate lifecycle (design §4.2 "Persistence and Fault Tolerance") ──
    def _required_jwt_issuer(self) -> str:
        """Issuer prefix a sealed certificate's JWT must carry to count as
        usable.  Empty in direct mode (mock JWTs); the enclave overrides it
        with the real AS so a mock certificate is never mistaken for a
        real one."""
        return ""

    # PAPER: §4.2 'Persistence and Fault Tolerance' — restart unseals cert+key and resumes; re-attest only near JWT/cert expiry.
    def _certificate_remaining_s(self, require_issuer: str = "") -> float:
        """Seconds until the sealed certificate stops being usable, or -1.

        Usable means: the file exists, its public key is our sealed keypair's,
        the X.509 validity has not lapsed, and the embedded AS JWT — which
        clients check for nbf/exp — has not expired.
        """
        try:
            with open(self._tls_cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        except Exception:
            return -1.0
        try:
            cert_pub = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if cert_pub != self._server_public_key_pem():
                self._logger.warning("Sealed certificate does not match the sealed keypair")
                return -1.0
            ext = cert.extensions.get_extension_for_oid(SGX_JWT_OID)
            token = ext.value.value.decode("utf-8")
            payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        except Exception:
            return -1.0
        if require_issuer and not str(payload.get("iss", "")).startswith(require_issuer):
            return -1.0
        now = time.time()
        try:
            not_after = cert.not_valid_after_utc.timestamp()
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc).timestamp()
        remaining = not_after - now
        exp = payload.get("exp")
        if exp:
            remaining = min(remaining, float(exp) - now)
        return remaining

    def _sealed_certificate_valid(self, margin_s: int = RENEW_MARGIN_S,
                                  require_issuer: str = "") -> bool:
        return self._certificate_remaining_s(require_issuer) > margin_s

    def _reissue_certificate(self) -> None:
        """Re-attest and re-issue the certificate (enclave overrides)."""
        self._init_tls_certificate()

    def ssl_context(self):
        """Server-side SSLContext for the HTTPS listener.  Kept on the
        instance so a renewal can hot-load the new chain without restarting
        the server."""
        import ssl as _ssl
        if self._ssl_ctx is None:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            cert_file, key_file = self.get_tls_certificate_filenames()
            ctx.load_cert_chain(cert_file, key_file)
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def _reload_ssl_context(self) -> None:
        if self._ssl_ctx is not None:
            cert_file, key_file = self.get_tls_certificate_filenames()
            self._ssl_ctx.load_cert_chain(cert_file, key_file)
            self._logger.info("Renewed certificate loaded into the running TLS listener")

    # PAPER: §4.3 'Handling Backend Irregularities' — on certificate renewal, re-sign all in-service DCs and send them to the backends.
    def _resign_and_push_dcs(self) -> None:
        """Design §4.3: when the frontend's certificate is renewed, re-sign
        every in-service backend's DC under the new certificate and send it.
        A DC signature covers the delegating certificate's DER (RFC 9345
        §4.1.2), so DCs issued under the old certificate are void."""
        if not ISSUE_DC:
            return
        chain_pem = self.get_frontend_cert_chain_pem()
        for be in self._key_store.list_backends(mode="in-service"):
            pub_pem = (be.get("public_key_pem") or "").encode()
            ip, port = be["ip_address"], be["port"]
            if not pub_pem:
                self._logger.warning(
                    f"Backend {ip}:{port} has no recorded public key; it must re-register")
                continue
            try:
                dc_b64 = base64.b64encode(self.sign_dc(pub_pem)).decode()
                sess = self.get_backend_session(ip, port, be.get("cert_fp", ""))
                # verify=False as in /forward: the peer presents its
                # self-signed certificate and the session's fingerprint pin is
                # the authentication; requests would otherwise force CA
                # verification and reject it.
                resp = sess.post(f"https://{ip}:{port}/renew_dc",
                                 json={"dc_b64": dc_b64,
                                       "frontend_cert_chain_pem": chain_pem},
                                 timeout=15, verify=False)
                if resp.status_code == 200:
                    self._logger.info(f"Re-signed DC pushed to {ip}:{port}")
                else:
                    self._logger.warning(
                        f"Backend {ip}:{port} rejected renewed DC: "
                        f"{resp.status_code} {resp.text[:120]}")
            except Exception as e:
                self._logger.warning(f"Could not push renewed DC to {ip}:{port}: {e}")

    def _renewal_loop(self) -> None:
        while True:
            time.sleep(RENEW_CHECK_S)
            try:
                with self._renew_lock:
                    if self._sealed_certificate_valid(RENEW_MARGIN_S, self._required_jwt_issuer()):
                        continue
                    self._logger.info(
                        "Certificate or AS JWT nearing expiry — re-attesting and re-issuing")
                    self._reissue_certificate()
                    self._reload_ssl_context()
                    self._resign_and_push_dcs()
            except Exception as e:
                self._logger.error(f"Certificate renewal failed: {e}")

    def start_renewal_thread(self) -> None:
        t = threading.Thread(target=self._renewal_loop, name="cert-renewal", daemon=True)
        t.start()
        self._logger.info(
            f"Certificate renewal watchdog started (margin {RENEW_MARGIN_S}s, "
            f"check every {RENEW_CHECK_S}s)")

    def get_tls_certificate_filenames(self):
        return self._tls_cert_file, self._server_key_file

    # ── Delegated Credential signing ──────────────────────────────────────

    # TLS 1.3 SignatureScheme values
    _SIG_RSA_PSS_RSAE_SHA256  = 0x0804
    _SIG_ECDSA_P256_SHA256    = 0x0403

    # PAPER: §4.3 Step 7 / 'DC in Redirection Mode' — RFC 9345 Delegated Credential over the backend's public key, ≤7 days, one local signature.
    def sign_dc(self, backend_public_key_pem: bytes, valid_seconds: int = 86400) -> bytes:
        """
        Sign a Delegated Credential (RFC 9345) binding a backend's public key
        to this frontend's certificate.

        The DC allows the backend to present the frontend's certificate and
        prove possession of its own key via CertificateVerify. Clients (Firefox)
        verify the DC signature against the certificate's public key.

        Args:
            backend_public_key_pem: PEM-encoded public key from the backend's CSR
            valid_seconds: DC lifetime in seconds (max 604800 = 7 days)

        Returns:
            Raw DelegatedCredential bytes (for the backend to use in TLS)
        """
        assert valid_seconds <= 604800, f"DC max lifetime is 7 days, got {valid_seconds}s"

        # Load backend public key and get SPKI DER
        backend_pub = serialization.load_pem_public_key(backend_public_key_pem)
        spki_der = backend_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Determine dc_cert_verify_alg based on backend's key type
        from cryptography.hazmat.primitives.asymmetric import ec
        if isinstance(backend_pub, ec.EllipticCurvePublicKey):
            dc_cert_verify_alg = self._SIG_ECDSA_P256_SHA256
        else:
            dc_cert_verify_alg = self._SIG_RSA_PSS_RSAE_SHA256

        # Build Credential structure: valid_time(4) + dc_alg(2) + spki_len(3) + spki
        credential = (
            struct.pack(">I", valid_seconds)
            + struct.pack(">H", dc_cert_verify_alg)
            + struct.pack(">I", len(spki_der))[1:]  # 3-byte length
            + spki_der
        )

        # Signing algorithm — frontend uses ECDSA-P256, so ECDSA-P256-SHA256.
        # Per RFC 9345 the DC's signature scheme is determined by the issuer
        # certificate's pubkey algorithm.
        algorithm = self._SIG_ECDSA_P256_SHA256

        # Load frontend certificate DER
        with open(self._tls_cert_file, "rb") as f:
            cert_pem_bytes = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Build signing input — NSS Bug 2018200 workaround:
        # algorithm is placed AFTER the Credential bytes
        sign_input = (
            b"\x20" * 64
            + b"TLS, server delegated credentials\x00"
            + cert_der
            + credential
            + struct.pack(">H", algorithm)
        )

        # Sign with frontend's ECDSA private key (ECDSA-P256 over SHA-256).
        signature = self._server_private_key.sign(
            sign_input,
            ec.ECDSA(hashes.SHA256()),
        )

        # Assemble DelegatedCredential: credential + algorithm(2) + sig_len(2) + sig
        dc_bytes = (
            credential
            + struct.pack(">H", algorithm)
            + struct.pack(">H", len(signature))
            + signature
        )

        self._logger.info(
            f"Signed DC: valid_time={valid_seconds}s, "
            f"SPKI={len(spki_der)}B, sig={len(signature)}B, total={len(dc_bytes)}B"
        )
        return dc_bytes

    def get_frontend_cert_chain_pem(self) -> str:
        """Return the frontend's certificate chain (PEM) for backends."""
        with open(self._tls_cert_file, "r") as f:
            return f.read()

    # ── back-end provisioning ───────────────────────────────────────────────

    def register_nonce(self, nonce: str, ip_address: str, cvm_type: str):
        """Register a nonce issued during CVM provisioning (called by BackendProvisioner)."""
        self._pending_nonces[nonce] = {
            "ip": ip_address,
            "cvm_type": cvm_type,
            "timestamp": time.time(),
        }
        self._logger.info(f"Registered nonce {nonce[:16]}… for {ip_address}")

    # PAPER: §4.3 Steps 5–6 — verify nonce + key binding in the evidence, submit to the AS once per registration, admit to the pool.
    def register_backend(
        self,
        csr_pem: bytes,
        quote_bytes: bytes,
        nonce: str,
        cvm_type: str,
        ip_address: str,
        port: int = 443,
        cert_pem: str = "",
    ) -> dict:
        """
        Verify a back-end's attestation, sign a Delegated Credential, and
        record it in the key store.

        The frontend submits the raw attestation evidence to Azure MAA and
        verifies that REPORTDATA matches the nonce issued during provisioning.

        Returns dict with:
            success                 – bool
            dc_b64                  – base64-encoded Delegated Credential
            frontend_cert_chain_pem – frontend cert chain (PEM, used as leaf
                                      in the backend's TLS handshake)
            error                   – error message on failure
        """
        self._logger.info(f"Provisioning back-end at {ip_address}:{port} (type={cvm_type})")

        # 1. Extract public key from CSR
        csr = x509.load_pem_x509_csr(csr_pem)
        backend_pub_key_pem = csr.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 2. Verify the challenge nonce (design §4.3 Steps 2 and 5).  It must
        # have been issued by this frontend (/nonce, or the provisioner), be
        # unused, and be younger than NONCE_TTL_S.  No nonce, no admission:
        # without it the evidence carries no TPM quote and the frontend could
        # not verify that this CVM holds the key in the CSR.
        if not nonce:
            return {"success": False,
                    "error": "Missing challenge nonce — obtain one from /nonce first"}
        if nonce in self._used_nonces:
            return {"success": False, "error": "Nonce already used (replay attack)"}
        pending = self._pending_nonces.get(nonce)
        if pending is None:
            self._logger.warning(f"Unknown nonce {nonce[:16]}… — rejecting")
            return {"success": False, "error": "Unknown nonce"}
        if time.time() - float(pending.get("timestamp", 0)) > NONCE_TTL_S:
            self._pending_nonces.pop(nonce, None)
            self._logger.warning(f"Expired nonce {nonce[:16]}… — rejecting")
            return {"success": False, "error": "Nonce expired"}

        # 3. Verify the attestation. The path depends on the backend's TEE
        # flavour: SGX uses Azure MAA's attest_open_enclave (SDK); SNP/TDX
        # CVMs use our /attest/SevSnpVm REST helper which expects an evidence
        # bundle (HCL report || PEM chain || optional TPM quote).
        try:
            t0_backend_maa = time.time()

            if cvm_type in ("snp", "tdx") and len(quote_bytes) > 0:
                from janus.common.snp_attestation import verify_snp_bundle
                nonce_bytes = nonce.encode("utf-8") if nonce else None
                # Recompute the registration binding from the CSR's public key —
                # must be byte-identical to what the backend bound into the
                # quote's qualifyingData (design.tex Steps 3/5), so the quote is
                # tied to BOTH the nonce and this backend's TLS identity.
                backend_pub_key_der = csr.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                success, attest_result = verify_snp_bundle(
                    quote_bytes,
                    expected_nonce=nonce_bytes,
                    expected_pubkey_spki_der=backend_pub_key_der,
                    expected_measurement=EXPECTED_BACKEND_MEASUREMENT,
                    maa_url=ATTESTATION_URL,
                    logger=self._logger,
                )
            else:
                verifier = get_attestation_verifier(
                    attestation_url=ATTESTATION_URL,
                    logger=self._logger,
                )
                if len(quote_bytes) == 0:
                    # Fail closed: empty evidence is never admitted unless the
                    # operator explicitly enabled mock attestation, and even
                    # then only in direct (non-TEE, development) mode.
                    if not (self._environment == "direct" and ALLOW_MOCK_ATTESTATION):
                        self._logger.warning("Backend sent empty evidence — rejecting")
                        return {"success": False,
                                "error": "Empty attestation evidence rejected"}
                    self._logger.warning(
                        "Backend sent empty quote — MOCK attestation "
                        "(JANUS_ALLOW_MOCK_ATTESTATION=1, direct mode only)"
                    )
                    verifier._mock_mode = True
                nonce_bytes = nonce.encode("utf-8") if nonce else b""
                success, attest_result = verifier.verify_quote(
                    quote_bytes, nonce_bytes, runtime_data=nonce_bytes
                )

            backend_maa_ms = (time.time() - t0_backend_maa) * 1000
            self._logger.info(f"Attestation verification (backend)  ⏱ {backend_maa_ms:.2f} ms")
            if not success:
                err = attest_result.get("error", "verification returned False") \
                    if isinstance(attest_result, dict) else "verification failed"
                return {"success": False, "error": f"Attestation verification failed: {err}"}
        except Exception as e:
            self._logger.error(f"Attestation error: {e}")
            return {"success": False, "error": f"Attestation error: {e}"}

        # 4. Mark nonce as used
        if nonce:
            self._used_nonces.add(nonce)
            self._pending_nonces.pop(nonce, None)

        # 5a. Sign a Delegated Credential for the backend (redirection mode
        # only — the backend ignores an empty dc_b64 and proxy mode never
        # presents a DC to clients)
        dc_b64 = ""
        if ISSUE_DC:
            dc_bytes = self.sign_dc(backend_pub_key_pem)
            dc_b64 = base64.b64encode(dc_bytes).decode()

        # 5b. Get frontend cert chain for the backend
        frontend_cert_chain_pem = self.get_frontend_cert_chain_pem()

        # 6. Derive a stable cvm_id = SHA256(public_key_pem)
        cvm_id = hashlib.sha256(backend_pub_key_pem).hexdigest()

        # 7. Persist in key store
        # The backend's self-signed X.509 certificate (same key as the CSR) is
        # what its dc_proxy presents to clients without DC support — i.e. to
        # this frontend's proxy-mode hop.  Record its fingerprint so that hop
        # can be pinned to the admitted key (design §4.4, proxy mode).
        cert_fp = ""
        if cert_pem:
            try:
                be_cert = x509.load_pem_x509_certificate(cert_pem.encode())
                be_cert_pub = be_cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            except Exception as e:
                return {"success": False, "error": f"Invalid backend certificate: {e}"}
            if be_cert_pub != backend_pub_key_pem:
                return {"success": False,
                        "error": "Backend certificate key does not match the CSR key"}
            cert_fp = hashlib.sha256(
                be_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self._key_store.add_backend(
            cvm_id=cvm_id,
            ip_address=ip_address,
            port=port,
            public_key_pem=backend_pub_key_pem.decode(),
            cert_fp=cert_fp,
        )
        if self._auto_promote_to_service or len(quote_bytes) == 0 or attest_result.get("verified", False):
            self._key_store.set_cvm_mode(cvm_id, "in-service")

        self._logger.info(f"Back-end provisioned: cvm_id={cvm_id[:16]}…")
        return {
            "success": True,
            "cvm_id": cvm_id,
            "dc_b64": dc_b64,
            "frontend_cert_chain_pem": frontend_cert_chain_pem,
        }

    # ── back-end selection ──────────────────────────────────────────────────

    # PAPER: §4.4 — backend selection (round-robin; selection policy is outside the paper's scope, footnote 1).
    def select_backend(self) -> Optional[dict]:
        """
        Select a back-end by round-robin over in-service back-ends.
        Returns the backend dict, or None if no back-ends are in service.
        """
        backends = self._key_store.list_backends(mode="in-service")
        if not backends:
            return None
        with self._rr_lock:
            idx = self._rr_index % len(backends)
            self._rr_index = (self._rr_index + 1) % max(len(backends), 1)
        return backends[idx]

    # PAPER: §4.4 Proxy mode — TLS from the frontend to the selected backend's TEE, authenticated with the key recorded at registration.
    def get_backend_session(self, ip_address: str, port: int, cert_fp: str = ""):
        """Return a `requests.Session` pre-configured for the upstream backend.

        Sessions are cached per (ip, port, pin) so the underlying TCP+TLS
        connection is reused across `/forward` calls — `requests`'
        urllib3-backed pool manager keeps the socket open between requests.

        TLS 1.3 is pinned on the internal hop because `dc_proxy` (the
        backend's TLS 1.3-only DC-aware terminator) won't negotiate down
        anyway; pinning here makes the forward path's wire behavior match
        what we measure for the RATLS/HTTPA baselines.

        Authentication of the hop (design §4.4, proxy mode: the frontend
        "has all necessary TLS- and TEE-related information about the
        selected backend during backend registration").  dc_proxy serves two
        credentials: the frontend certificate + DC to DC-capable clients, and
        the backend's self-signed X.509 certificate — same key — to clients
        without DC support, such as this session.  We pin that certificate's
        SHA-256 fingerprint, recorded at registration; TLS 1.3's
        CertificateVerify then proves the peer holds the admitted key, and a
        mismatch aborts the handshake inside urllib3.  CA verification stays
        off (the certificate is self-signed by design), so the pin is the
        authentication.  A backend registered without a certificate cannot be
        forwarded to unless JANUS_ALLOW_UNPINNED_UPSTREAM=1 (testing only).
        """
        import requests as _requests
        from requests.adapters import HTTPAdapter
        from urllib3.poolmanager import PoolManager
        import ssl as _ssl

        if not cert_fp and os.environ.get("JANUS_ALLOW_UNPINNED_UPSTREAM") != "1":
            raise RuntimeError(
                f"backend {ip_address}:{port} has no pinned certificate; "
                "refusing an unauthenticated upstream hop")

        key = (ip_address, port, cert_fp)
        with self._backend_sessions_lock:
            sess = self._backend_sessions.get(key)
            if sess is not None:
                return sess

            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE

            class _TLS13Adapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    kwargs["ssl_context"] = ctx
                    if cert_fp:
                        kwargs["assert_fingerprint"] = cert_fp
                    super().init_poolmanager(*args, **kwargs)

            sess = _requests.Session()
            adapter = _TLS13Adapter(pool_connections=4, pool_maxsize=16,
                                     max_retries=0)
            sess.mount("https://", adapter)
            sess.mount("http://", adapter)
            self._backend_sessions[key] = sess
            return sess

    # ── owner signature verification ────────────────────────────────────────

    def verify_owner_signature(self, request_data: dict) -> bool:
        """
        Verify RSA-PSS signature from the service owner (privileged operations).
        The owner signs JSON.dumps(params, sort_keys=True).

        In direct mode with no service owner key configured, all privileged
        operations are permitted (development / testing convenience).
        In SGX mode, a key must be configured — requests without a valid
        signature are always rejected.
        """
        if not self._service_owner_key_configured:
            if self._environment == "direct":
                self._logger.warning(
                    "No owner key — allowing privileged op (direct/test mode)"
                )
                return True
            self._logger.warning("No service owner public key configured – rejecting privileged op")
            return False
        try:
            params    = request_data["params"]
            sig_b64   = request_data["signature"]
            signature = base64.b64decode(sig_b64)
            message   = json.dumps(params, sort_keys=True).encode()

            pub_key = serialization.load_pem_public_key(
                self._service_owner_public_key_pem, backend=default_backend()
            )
            pub_key.verify(
                signature, message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            self._logger.warning(f"Owner signature verification failed: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# SGX / Gramine variant
# ═══════════════════════════════════════════════════════════════════════════════

class FrontendServerEnclave(FrontendServer):
    """
    Frontend server running inside an Intel SGX enclave (Gramine).

    Differences from FrontendServer:
      - Keypairs are loaded from / persisted to Gramine's sealed directory
      - REPORTDATA = SHA256(pk_srv_pem || pk_CA_pem) written before quote read
      - TLS cert obtained from Pebble ACME with JWT + CA cert extensions
      - /attest/fresh reads a fresh SGX quote and resubmits to Azure MAA
    """

    # Require explicit /mark_cvm call from the enclave owner.
    _auto_promote_to_service = False

    def _init_tls_certificate(self):
        # No-op: the base constructor's direct-mode (mock JWT) issuance is
        # not wanted in an enclave; certificate issuance is done by
        # _init_tls_certificate_with_sgx() after REPORTDATA is written.
        return

    def _required_jwt_issuer(self) -> str:
        return ATTESTATION_URL

    def _reissue_certificate(self) -> None:
        self._write_enclave_report_data()
        self._init_tls_certificate_with_sgx()

    def __init__(self, environment: str, logger: logging.Logger):
        # super().__init__ calls _init_server_keypair and _init_tls_certificate
        # (the latter is overridden to no-op here — we do SGX version after).
        super().__init__(environment, logger)
        # Design §4.2: if the sealed certificate (issued under this sealed
        # keypair, with an unexpired real-AS JWT) is still usable, resume with
        # no new quote, no AS round trip and no CA issuance.  Otherwise write
        # REPORTDATA and run the SGX attestation + ACME flow.
        if self._sealed_certificate_valid(RENEW_MARGIN_S, ATTESTATION_URL):
            self._logger.info(
                "Unsealed a valid attested certificate "
                f"({self._certificate_remaining_s(ATTESTATION_URL) / 3600:.1f} h left) "
                "— skipping quote, AS and CA issuance")
        else:
            self._write_enclave_report_data()
            self._init_tls_certificate_with_sgx()

        self._logger.info("=" * 60)
        self._logger.info("FRONTEND STARTUP LATENCY SUMMARY")
        self._logger.info("=" * 60)
        for label, key in [
            ("TLS key generation (server + CA)", "_keygen_ms"),
            ("SGX Quote generation", "_quote_gen_ms"),
            ("Azure MAA verification (own)", "_maa_verify_ms"),
            ("ACME certificate issuance", "_acme_ms"),
        ]:
            val = getattr(self, key, None)
            if val is not None:
                self._logger.info(f"  {label:45s} ⏱ {val:.2f} ms")
        self._logger.info("=" * 60)

    # ── sealed key management (override base class) ─────────────────────────

    def _init_server_keypair(self):
        """Load sealed server keypair or generate + seal a new one."""
        t0 = time.time()
        if os.path.isfile(self._server_key_file):
            with open(self._server_key_file, "rb") as f:
                pem = f.read()
            self._server_private_key = serialization.load_pem_private_key(pem, password=None)
            self._server_public_key  = self._server_private_key.public_key()
            self._logger.info("Loaded sealed server keypair")
        else:
            self._server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self._server_public_key  = self._server_private_key.public_key()
            self._persist_pem(
                self._server_key_file,
                self._server_private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            self._logger.info("Generated and sealed new server keypair")
        self._server_keygen_ms = (time.time() - t0) * 1000
        self._keygen_ms = self._server_keygen_ms

    def _persist_pem(self, path: str, data: bytes):
        """Write PEM data, retrying on transient sealed-storage errors."""
        while True:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                break
            except Exception as exc:
                self._logger.error(f"Failed to write {path}: {exc} — retrying…")
                time.sleep(1)

    # ── REPORTDATA ──────────────────────────────────────────────────────────

    # PAPER: §4.2 Step 2 — REPORTDATA = SHA-256(frontend TLS public key); no nonce (TLS supplies per-connection freshness).
    def _write_enclave_report_data(self):
        """
        Bind the server key into the SGX quote REPORTDATA:
            SHA256(server_public_key_pem)
        Must be called after the server keypair is initialised and before get_quote().
        """
        reportdata = hashlib.sha256(self._server_public_key_pem()).digest()
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(reportdata)
            self._logger.info(
                f"REPORTDATA written: SHA256(pk_srv)={reportdata.hex()[:32]}…"
            )
        except Exception as exc:
            self._logger.warning(f"Could not write REPORTDATA: {exc}")

    def get_quote(self) -> bytes:
        with open("/dev/attestation/quote", "rb") as f:
            return f.read()

    # ── TLS certificate (ACME + dual extensions) ─────────────────────────────

    # PAPER: §4.2 Steps 1–6 — keypair, quote, AS (MAA) JWT, CSR with JWT + DelegationUsage extensions, CA (Pebble/ACME) issuance.
    def _init_tls_certificate_with_sgx(self):
        """
        Obtain TLS certificate from Pebble ACME, embedding:
          OID 1.3.6.1.4.1.99999.3.1 – Azure MAA JWT (from SGX quote)
          OID 1.3.6.1.4.1.99999.3.2 – Frontend CA certificate (DER bytes)
        Falls back to self-signed cert if Pebble is unavailable.
        """
        try:
            self._logger.info("Requesting TLS certificate via ACME (SGX + CA cert extensions)…")

            # 1. Read SGX quote
            t0_quote = time.time()
            quote          = self.get_quote()
            self._quote_gen_ms = (time.time() - t0_quote) * 1000
            self._logger.info(f"SGX quote generated ({len(quote)} bytes)  ⏱ {self._quote_gen_ms:.2f} ms")

            # 2. Get Azure MAA JWT
            t0_maa = time.time()
            server_pub_pem = self._server_public_key_pem()
            verifier       = get_attestation_verifier(
                attestation_url=ATTESTATION_URL, logger=self._logger
            )
            ok, attest = verifier.verify_quote(quote, server_pub_pem, runtime_data=server_pub_pem)
            if not ok or not attest.get("token"):
                raise RuntimeError("Azure MAA attestation failed")
            self._maa_verify_ms = (time.time() - t0_maa) * 1000
            self._logger.info(f"Azure MAA verification (own)  ⏱ {self._maa_verify_ms:.2f} ms")

            jwt_token = attest["token"]
            self._logger.info(f"Azure MAA JWT obtained ({len(jwt_token)} chars)")

            # 3. Build CSR with two custom extensions
            csr_pem = self._build_csr_with_extensions(jwt_token)

            # 4. Submit CSR to Pebble via ACME
            t0_acme = time.time()
            acme = ACMEClient(
                pebble_url="https://localhost:14000/dir",
                verify_ssl=False,
                logger=self._logger,
            )
            cert_pem, _key_pem = acme.get_certificate_from_csr(
                csr_pem=csr_pem,
                private_key=self._server_private_key,
                challenge_port=5002,
            )
            self._acme_ms = (time.time() - t0_acme) * 1000
            self._logger.info(f"ACME certificate issuance  ⏱ {self._acme_ms:.2f} ms")

            with open(self._tls_cert_file, "wb") as f:
                f.write(cert_pem)
            self._logger.info("TLS certificate with SGX extensions obtained from ACME")

        except Exception as e:
            self._logger.error(f"ACME flow failed: {e} — falling back to self-signed cert")
            self._init_tls_certificate_sgx_fallback()

    # PAPER: §4.2 Step 5 — CSR carries the AS-signed JWT (OID 1.3.6.1.4.1.99999.3.1) and RFC 9345 DelegationUsage.
    def _build_csr_with_extensions(self, jwt_token: str) -> bytes:
        """
        Build a CSR carrying:
          OID 3.1 – JWT token bytes (UTF-8)
          DelegationUsage – enables DC signing (OID 1.3.6.1.4.1.44363.44)
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self._ip_address),
        ])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectAlternativeName(_san_dnsnames(self._ip_address)),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(SGX_JWT_OID, jwt_token.encode("utf-8")),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(DELEGATION_USAGE_OID, b"\x05\x00"),
                critical=False,
            )
            .sign(self._server_private_key, hashes.SHA256(), default_backend())
        )
        return csr.public_bytes(serialization.Encoding.PEM)

    def _init_tls_certificate_sgx_fallback(self):
        """Self-signed fallback: embed JWT + DelegationUsage in the cert directly."""
        try:
            quote          = self.get_quote()
            server_pub_pem = self._server_public_key_pem()
            verifier       = get_attestation_verifier(
                attestation_url=ATTESTATION_URL, logger=self._logger
            )
            ok, attest = verifier.verify_quote(quote, server_pub_pem, runtime_data=server_pub_pem)
            jwt_token  = attest.get("token", "") if ok else ""
        except Exception:
            jwt_token = ""

        now    = datetime.datetime.now(datetime.timezone.utc)
        name   = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self._ip_address)])

        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._server_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName(_san_dnsnames(self._ip_address)),
                critical=False,
            )
        )
        if jwt_token:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(SGX_JWT_OID, jwt_token.encode("utf-8")),
                critical=False,
            )
        builder = builder.add_extension(
            x509.UnrecognizedExtension(DELEGATION_USAGE_OID, b"\x05\x00"),
            critical=False,
        )
        cert = builder.sign(self._server_private_key, hashes.SHA256(), default_backend())
        with open(self._tls_cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self._logger.info("Self-signed TLS certificate with extensions created (fallback)")

    # ── /attest/fresh support ────────────────────────────────────────────────

    def attest_fresh(self, nonce: str) -> dict:
        """
        Generate a fresh SGX quote bound to the nonce and resubmit to Azure MAA.
        Rate-limited to MIN_FRESH_INTERVAL seconds between invocations.

        Returns dict with:
            success   – bool
            jwt_token – fresh JWT on success
            error     – error message on failure
        """
        with self._fresh_lock:
            now = time.time()
            if (now - self._last_fresh_at) < MIN_FRESH_INTERVAL:
                remaining = int(MIN_FRESH_INTERVAL - (now - self._last_fresh_at))
                return {
                    "success": False,
                    "error": f"Rate limited – retry after {remaining}s",
                    "retry_after": remaining,
                }
            self._last_fresh_at = now

        # SHA256(nonce || pk_srv) → REPORTDATA
        nonce_bytes   = nonce.encode("utf-8")
        server_pub_pem = self._server_public_key_pem()
        reportdata    = hashlib.sha256(nonce_bytes + server_pub_pem).digest()
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(reportdata)
            quote = self.get_quote()
        except Exception as exc:
            return {"success": False, "error": f"Quote generation failed: {exc}"}

        try:
            verifier  = get_attestation_verifier(
                attestation_url=ATTESTATION_URL, logger=self._logger
            )
            # runtime_data must match REPORTDATA: SHA256(nonce + pk_srv)
            fresh_runtime = nonce_bytes + server_pub_pem
            ok, attest = verifier.verify_quote(quote, server_pub_pem, runtime_data=fresh_runtime)
            if not ok:
                return {"success": False, "error": "Azure MAA verification failed"}
        except Exception as exc:
            return {"success": False, "error": f"Attestation error: {exc}"}

        return {"success": True, "jwt_token": attest.get("token", "")}


# ═══════════════════════════════════════════════════════════════════════════════
# Factory
# ═══════════════════════════════════════════════════════════════════════════════

class FrontendServerFactory:
    @staticmethod
    def create(environment: str = "direct") -> FrontendServer:
        if environment == "direct":
            return FrontendServer(environment, app.logger)
        elif environment == "sgx":
            return FrontendServerEnclave(environment, app.logger)
        else:
            raise ValueError(f"Unknown environment: {environment}")


# ═══════════════════════════════════════════════════════════════════════════════
# Flask routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def handle_index():
    return jsonify({
        "service": "Janus Frontend Server",
        "backends": len(FRONTEND_SERVER._key_store.list_backends(mode="in-service")),
    })


@app.route("/quote", methods=["GET"])
def handle_quote():
    """Return the SGX quote and TLS certificate (used by the client)."""
    result = {"tls_certificate": ""}
    try:
        with open(FRONTEND_SERVER._tls_cert_file, "r") as f:
            result["tls_certificate"] = f.read()
    except Exception:
        pass

    if isinstance(FRONTEND_SERVER, FrontendServerEnclave):
        try:
            result["quote"] = base64.b64encode(FRONTEND_SERVER.get_quote()).decode()
        except Exception:
            result["quote"] = ""
    else:
        result["quote"] = ""

    return jsonify(result)


@app.route("/attest/fresh", methods=["GET"])
def handle_attest_fresh():
    """
    Re-attest with a fresh SGX quote bound to the caller-supplied nonce.
    Rate-limited to MIN_FRESH_INTERVAL seconds.
    """
    nonce = request.args.get("nonce", "")
    if not nonce:
        abort(400, description="nonce parameter required")

    if not isinstance(FRONTEND_SERVER, FrontendServerEnclave):
        abort(501, description="Fresh attestation requires SGX mode")

    result = FRONTEND_SERVER.attest_fresh(nonce)
    if not result["success"]:
        status = 429 if "retry_after" in result else 500
        return jsonify(result), status
    return jsonify(result)


@app.route("/nonce", methods=["GET"])
# PAPER: §4.3 Step 2 — the backend contacts the frontend, which responds with a unique challenge nonce.
def handle_nonce():
    """Challenge nonce for a backend's registration evidence (design §4.3
    Step 2).  The backend binds SHA256(nonce ‖ its TLS public key) into its
    quote; /register_backend verifies that binding and consumes the nonce.
    Nonces are single-use and expire after NONCE_TTL_S."""
    n = os.urandom(32).hex()
    FRONTEND_SERVER.register_nonce(
        n, request.args.get("ip", request.remote_addr),
        request.args.get("cvm_type", "snp"))
    return jsonify({"nonce": n, "ttl_s": NONCE_TTL_S})


@app.route("/register_backend", methods=["POST"])
@app.route("/provision_backend", methods=["POST"])  # legacy alias
def handle_register_backend():
    """
    Back-end registration endpoint.
    Called by a newly provisioned CVM to obtain its DC and signed certificate.

    Expected JSON body:
        csr_pem    – PEM-encoded CSR (contains backend's public key)
        quote_b64  – base64-encoded raw attestation evidence (SNP report / SGX quote)
        nonce      – hex nonce issued by the frontend during CVM provisioning
        cvm_type   – 'snp', 'tdx', or 'gramine'
        ip_address – back-end IP (as seen from the frontend)
        port       – back-end HTTPS port (default 443)
    """
    data = request.get_json(force=True)
    try:
        csr_pem  = data["csr_pem"].encode()
        quote    = base64.b64decode(data.get("quote_b64") or "")
        nonce    = data.get("nonce", "")
        cvm_type = data.get("cvm_type", "snp")
        ip       = data["ip_address"]
        port     = int(data.get("port", 443))
        cert_pem = data.get("cert_pem") or ""
    except (KeyError, ValueError) as e:
        abort(400, description=f"Invalid request: {e}")

    result = FRONTEND_SERVER.register_backend(
        csr_pem, quote, nonce, cvm_type, ip, port, cert_pem
    )

    # Cross-reference: map TLS cvm_id → provisioned CVM object (so stop_cvm works)
    if result.get("success") and PROVISIONER is not None:
        PROVISIONER.link_backend_to_cvm(ip, result["cvm_id"])

    status = 200 if result["success"] else 500
    return jsonify(result), status


@app.route("/pool_status", methods=["GET"])
def handle_pool_status():
    backends = FRONTEND_SERVER._key_store.list_backends()
    return jsonify({"backends": backends, "count": len(backends)})


@app.route("/route", methods=["GET"])
# PAPER: §4.4 Redirection mode — the frontend returns the selected backend's address; the client then connects to it directly.
def handle_route():
    """Redirection-mode routing (control plane).

    The frontend is the entry point; this hands the client an in-service
    backend it then connects to directly, so the frontend stays off the data
    path. Selection is round-robin via select_backend().

      - Browser navigation (Accept: text/html): HTTP 302 to the backend URL,
        which the browser follows natively.
      - Programmatic client (default): JSON {backend_host, backend_port, url}.
      - ?pool=1: JSON list of all in-service backends, for a client that
        validates the frontend once and then fans out across the pool (the
        amortized steady-state regime in sec:eval-performance).

    Note: the served leaf cert (the frontend's, presented by the backend with
    a Delegated Credential) must hostname-match whatever name the client dials,
    so the 302/pool targets must be covered by the frontend cert's SAN.
    """
    if request.args.get("pool"):
        pool = FRONTEND_SERVER._key_store.list_backends(mode="in-service")
        return jsonify({
            "backends": [{"backend_host": b["ip_address"],
                          "backend_port": b["port"]} for b in pool],
            "count": len(pool),
        })
    b = FRONTEND_SERVER.select_backend()
    if not b:
        return jsonify({"error": "no backends in service"}), 503
    url = f"https://{b['ip_address']}:{b['port']}/"
    if "text/html" in request.headers.get("Accept", ""):
        return redirect(url, code=302)
    return jsonify({"backend_host": b["ip_address"],
                    "backend_port": b["port"], "url": url})


@app.route("/mark_cvm", methods=["POST"])
def handle_mark_cvm():
    """Mark a CVM as 'in-service' or 'in-update' (privileged)."""
    data = request.get_json(force=True)
    if not FRONTEND_SERVER.verify_owner_signature(data):
        return jsonify({"success": False, "error": "Signature verification failed"}), 403

    cvm_id   = data["params"]["cvm_id"]
    cvm_mode = data["params"]["cvm_mode"]
    try:
        FRONTEND_SERVER._key_store.set_cvm_mode(cvm_id, cvm_mode)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    return jsonify({"success": True, "cvm_id": cvm_id, "cvm_mode": cvm_mode})


@app.route("/start_cvm", methods=["POST"])
def handle_start_cvm():
    """
    Provision a new back-end CVM (privileged).

    Expected JSON body:
        params.cvm_type   – 'snp' or 'tdx'
        signature         – RSA-PSS signature over JSON(params, sort_keys=True)
    """
    data = request.get_json(force=True)
    if not FRONTEND_SERVER.verify_owner_signature(data):
        return jsonify({"success": False, "error": "Signature verification failed"}), 403

    cvm_type = data["params"].get("cvm_type", "snp")
    if cvm_type not in ("snp", "tdx"):
        return jsonify({"success": False, "error": f"Unknown cvm_type: {cvm_type}"}), 400

    if PROVISIONER is None:
        return jsonify({"success": False, "error": "Provisioner not initialised"}), 500

    result = PROVISIONER.provision_cvm(cvm_type)
    status = 200 if result["success"] else 500
    return jsonify(result), status


@app.route("/stop_cvm", methods=["POST"])
def handle_stop_cvm():
    """Remove a back-end from the pool and delete its Azure resources (privileged)."""
    data = request.get_json(force=True)
    if not FRONTEND_SERVER.verify_owner_signature(data):
        return jsonify({"success": False, "error": "Signature verification failed"}), 403

    cvm_id = data["params"]["cvm_id"]

    # Delete Azure resources if provisioner knows this CVM
    if PROVISIONER is not None and cvm_id in CVMs:
        PROVISIONER.delete_cvm(cvm_id)

    FRONTEND_SERVER._key_store.remove_backend(cvm_id)
    return jsonify({"success": True, "cvm_id": cvm_id})


# RFC 7230 §6.1: hop-by-hop headers must not be forwarded.  Flask/Werkzeug
# re-encodes the response body, so passing through the upstream's
# Transfer-Encoding/Content-Length verbatim corrupts chunked responses.
_HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
})


@app.route("/forward", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"], strict_slashes=False)
@app.route("/forward/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
# PAPER: §4.4 Proxy mode — the frontend transparently proxies client requests to the selected backend over a TEE-bound TLS session.
def handle_forward(path):
    """Proxy mode: forward the incoming request to a back-end.

    The back-end is selected round-robin over in-service back-ends.  The
    upstream HTTPS connection is taken from a per-backend `requests.Session`
    pool, so a steady-state forward pays *one* request/response RTT — not
    the TCP+TLS handshake the previous implementation paid (twice) on every
    call.

    Response headers `X-Forward-Ms` and `X-Forward-Backend` surface the
    upstream-hop latency for benchmarking; clients can decompose total
    request time into client→frontend RTT and frontend→backend RTT.
    """
    backend = FRONTEND_SERVER.select_backend()
    if not backend:
        return jsonify({"error": "No back-ends available"}), 503

    # Forward over the backend's TEE-terminating dc_proxy (DC-TLS) port so the
    # frontend->backend hop is encrypted and terminates inside the backend's
    # TEE (design Goal 2), instead of crossing the network in cleartext.
    # dc_proxy decrypts inside the enclave and relays to the co-located app.
    target_url = f"https://{backend['ip_address']}:{backend['port']}/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode()}"

    fwd_headers = {k: v for k, v in request.headers
                   if k.lower() not in _HOP_BY_HOP_HEADERS and k.lower() != "host"}

    try:
        sess = FRONTEND_SERVER.get_backend_session(
            backend["ip_address"], backend["port"], backend.get("cert_fp", ""))
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    try:
        t0_fwd = time.time()
        resp = sess.request(
            method=request.method,
            url=target_url,
            headers=fwd_headers,
            data=request.get_data(),
            verify=False,
            timeout=30,
            allow_redirects=False,
            stream=True,               # relay the body as it arrives (streaming apps, e.g. LLM tokens)
        )
        fwd_ms = (time.time() - t0_fwd) * 1000   # time to the upstream response headers
    except Exception as e:
        app.logger.error(f"Forward to {backend['ip_address']} failed: {e}")
        return jsonify({"error": f"Backend unavailable: {e}"}), 502

    app.logger.info(
        f"Forward {request.method} {target_url} → {resp.status_code}  ⏱ {fwd_ms:.2f} ms"
    )

    out_headers = {k: v for k, v in resp.headers.items()
                   if k.lower() not in _HOP_BY_HOP_HEADERS}
    out_headers["X-Forward-Ms"] = f"{fwd_ms:.3f}"
    out_headers["X-Forward-Backend"] = f"{backend['ip_address']}:{backend['port']}"

    from flask import Response
    # Bytes are relayed unmodified (no content decoding), so the upstream
    # Content-Length / Content-Encoding headers stay valid for the client.
    return Response(resp.raw.stream(8192, decode_content=False),
                    status=resp.status_code, headers=out_headers, direct_passthrough=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-p", "--port",  default=6037, type=int)
    parser.add_argument("-t", "--type",  choices=["direct", "sgx"], default="sgx")
    return parser.parse_args()


def handle_sigint(sig, frame):
    app.logger.info("SIGINT received – stopping frontend server")
    sys.exit(0)


def main():
    app.logger.setLevel(logging.INFO)
    logging.getLogger("azure").setLevel(logging.WARNING)

    signal.signal(signal.SIGINT, handle_sigint)

    args = parse_args()
    app.logger.info(f"Starting Janus frontend server in '{args.type}' mode…")

    global FRONTEND_SERVER, PROVISIONER
    FRONTEND_SERVER = FrontendServerFactory.create(args.type)

    # Use private IP so CVM backends on the same VNet can reach the frontend.
    # Falls back to localhost if IMDS is unavailable (e.g. local dev).
    import subprocess as _sp
    try:
        _priv_ip = _sp.check_output(
            ["curl", "-sf", "--max-time", "2", "-H", "Metadata: true",
             "http://169.254.169.254/metadata/instance/network/interface/0/"
             "ipv4/ipAddress/0/privateIpAddress?api-version=2021-02-01&format=text"],
            stderr=_sp.DEVNULL,
        ).decode().strip()
    except Exception:
        _priv_ip = ""
    frontend_host = _priv_ip or "localhost"
    frontend_url = f"https://{frontend_host}:{args.port}"
    app.logger.info(f"Frontend URL for backends: {frontend_url}")
    PROVISIONER = BackendProvisioner(
        frontend_url=frontend_url,
        frontend_https_port=args.port,
        cvms=CVMs,
        frontend_server=FRONTEND_SERVER,
        logger=app.logger,
    )

    # Redirection mode is direct-talk: the frontend is on the admission path
    # only (HTTPS API on `args.port`); clients open TLS+DC straight to the
    # backend's dc_proxy. No data-plane relay runs in the frontend.

    cert_file, key_file = FRONTEND_SERVER.get_tls_certificate_filenames()

    # The TLS first flight carries the AS-JWT certificate (~7.5 KB), whose
    # final sub-MSS segment Nagle holds back until the in-flight segments are
    # ACKed -- turning the 1-RTT TLS 1.3 handshake into 2 RTTs on every
    # connection.  TCP_NODELAY must be on the socket BEFORE the handshake;
    # werkzeug's disable_nagle_algorithm only applies in setup(), after the
    # SSL wrap.  Set it on the listening socket (inherited by every accepted
    # socket) -- same fix as the HTTPA baseline server and dc_proxy.
    import socket as _socket
    from werkzeug.serving import BaseWSGIServer as _BaseWSGIServer
    _orig_server_bind = _BaseWSGIServer.server_bind

    def _server_bind_nodelay(self):
        self.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        return _orig_server_bind(self)

    _BaseWSGIServer.server_bind = _server_bind_nodelay

    # Serve from a reloadable SSLContext (built from cert_file/key_file) so a
    # certificate renewal reaches the running listener, and start the
    # lifecycle watchdog that re-attests near expiry and re-signs the DCs.
    FRONTEND_SERVER.start_renewal_thread()
    app.run(
        port=args.port, host="0.0.0.0",
        threaded=True, load_dotenv=False,
        ssl_context=FRONTEND_SERVER.ssl_context(),
    )


if __name__ == "__main__":
    main()
