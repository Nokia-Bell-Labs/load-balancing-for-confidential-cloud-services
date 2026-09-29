#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
RATLS HTTP Server - Flask server with RATLS attestation

Serves HTTP content over RATLS-attested TLS connections, parallel to cTLS server.py
but uses per-connection attestation via TLS extensions.

Usage:
    python ratls_http_server.py --port 5001 --type snp
"""

from argparse import ArgumentParser
import hashlib
import logging
from logging.config import dictConfig
import os
import sys
import ssl
import signal
import threading
import time

from flask import Flask, request

# Add parent directories to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))  # repo root

try:
    import ratls_bridge
except ImportError:
    print("❌ ERROR: ratls_bridge module not found")
    print("   Make sure you're using the RATLS Python build")
    sys.exit(1)

# Configure logging - same as server.py
dictConfig({
    "version": 1,
    "formatters": {"default": {
        "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    }},
    "handlers": {"wsgi": {
        "class": "logging.StreamHandler",
        "formatter": "default"
    }},
    "root": {
        "level": "INFO",
        "handlers": ["wsgi"]
    }
})

# Create Flask app - same as server.py
app = Flask(__name__, static_folder=None)

RATLS_SERVER = None

# ── Optional per-request backend-work cap (scalability microbenchmark) ────────
# Equal-setting scale-out figure: every protocol's backend does the SAME
# representative work (CTLS_SERVICE_MS at CTLS_MAX_INFLIGHT concurrency) on top
# of its own attestation.  RA+TLS pays a fresh in-handshake vTPM quote per
# connection; the capped /health below models the identical downstream service
# a \sys{} backend performs.  No-op when CTLS_SERVICE_MS is unset.
_CAP_SVC_S = float(os.environ.get("CTLS_SERVICE_MS", "0") or "0") / 1000.0
_CAP_INFLIGHT = int(os.environ.get("CTLS_MAX_INFLIGHT", "0") or "0")
_CAP_SEM = threading.Semaphore(_CAP_INFLIGHT) if _CAP_INFLIGHT > 0 else None


def _cap_backend_work() -> bool:
    """Serialise + delay to model the shared per-request backend cost."""
    if _CAP_SVC_S <= 0:
        return True
    if _CAP_SEM is not None and not _CAP_SEM.acquire(timeout=max(_CAP_SVC_S, 0.001)):
        return False
    try:
        time.sleep(_CAP_SVC_S)
    finally:
        if _CAP_SEM is not None:
            _CAP_SEM.release()
    return True

# Per-connection quote generation. The paravisor-mediated vTPM is a serial
# resource; concurrent in-handshake quote generation contends on it (profiling
# showed throughput does not rise -- and degrades -- with added concurrency,
# whether via threads, a process pool, or multiple clients). Connection-rate
# throughput is therefore reported at the vTPM quote ceiling (a hardware bound
# both attested-TLS baselines share), not this server's contended rate.
QUOTE_LOCK = threading.Lock()

# Cached AMD cert chain (per-VM stable). First handshake fetches from KDS
# (~1s); subsequent handshakes reuse the cached chain.
_VCEK_CHAIN_CACHE: bytes = None


class RATLSServer:
    """
    RATLS server class - parallel to CTLSServer.

    Provides per-connection attestation using TLS extensions.
    Unlike cTLS which attests once at startup, RATLS generates
    a fresh quote for each TLS handshake.
    """

    def __init__(self, environment, logger):
        self._logger = logger
        self._environment = environment           # 'snp' or 'direct' (mock)
        self._ip_address = "localhost"

        if self._environment not in ("snp", "direct"):
            raise ValueError(f"Unknown environment {environment!r}; "
                             f"expected 'snp' or 'direct'")

        if self._environment == "direct":
            self._local_tmp_path = "/tmp/"
            self._home_filepath = os.path.dirname(os.path.abspath(__file__)) + "/"
        else:  # snp
            app_home = os.getenv('APP_HOME', '/home/janus')
            self._local_tmp_path = f"{app_home}/ratls/server/sealed/"
            self._home_filepath = f"{app_home}/ratls/server/"
            os.makedirs(self._local_tmp_path, exist_ok=True)

        self._tls_certificate_filename = self._local_tmp_path + "tls_certificate.pem"
        self._tls_key_filename = self._local_tmp_path + "private_key.pem"

        # On Azure SEV-SNP CVMs, /dev/sev-guest does NOT exist (the paravisor
        # mediates AMD-SP access; we use the vTPM at /dev/tpm0 instead — see
        # common/snp_attestation.py for the full path). So the right liveness
        # signal is the presence of the vTPM.
        self._in_snp = (
            self._environment == "snp"
            and (os.path.exists("/dev/sev-guest") or os.path.exists("/dev/tpm0"))
        )

        self._ensure_certificates()

        self._logger.info(f"RATLS Server initialized in '{environment}' mode")
        self._logger.info(f"  SEV-SNP available: {self._in_snp}")
        self._logger.info(f"  OpenSSL: {ssl.OPENSSL_VERSION}")
        self._logger.info(f"  Certificate: {self._tls_certificate_filename}")

    def _ensure_certificates(self):
        """
        Generate self-signed TLS certificates if they don't exist.
        For RATLS, the certificate is just for the TLS connection - attestation happens via extensions.
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime

        # Check if certificates already exist
        if os.path.exists(self._tls_certificate_filename) and os.path.exists(self._tls_key_filename):
            self._logger.info("Using existing TLS certificates")
            return

        self._logger.info("Generating self-signed TLS certificates...")

        try:
            # ECDSA-P256 to match HTTPA + cTLS-backend; keeps the TLS-handshake
            # crypto cost comparable across the three baselines.
            private_key = ec.generate_private_key(ec.SECP256R1())

            # Create self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, self._ip_address),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(private_key, hashes.SHA256())

            # Write private key
            with open(self._tls_key_filename, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Write certificate
            with open(self._tls_certificate_filename, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self._logger.info("✅ Generated self-signed TLS certificates")
        except Exception as e:
            self._logger.error(f"Failed to generate certificates: {e}")
            raise

    def generate_quote(self, binder_secret: bytes) -> bytes:
        """
        Generate an SEV-SNP attestation evidence bundle bound to the
        TLS binder_secret.  Called by the C bridge (ratls_python_bridge.c)
        from inside the TLS handshake — runs in-process (no subprocess,
        no fresh Python interpreter), so the per-call cost is the same
        as HTTPA/2's `_generate_attestation()` route handler.

        The bundle (HCL report + VCEK chain + TPM2 quote bound to
        SHA256(binder_secret)) is produced by
        common.snp_attestation.build_snp_evidence_bundle and shipped to
        the client via TLS extension 421.
        """
        if len(binder_secret) != 48:
            raise ValueError(f"Expected 48-byte binder_secret, got {len(binder_secret)}")

        # Simulation mode for tests / direct mode (no real TPM).
        if not self._in_snp:
            reportdata = hashlib.sha256(binder_secret).digest()
            quote = b"FAKE_SNP_REPORT_" + reportdata + binder_secret[:16]
            self._logger.info(f"Generated simulated quote: {len(quote)} bytes")
            return quote

        global _VCEK_CHAIN_CACHE
        from janus.common.snp_attestation import (build_snp_evidence_bundle,
                                            parse_snp_evidence_bundle)
        with QUOTE_LOCK:
            bundle = build_snp_evidence_bundle(
                nonce=binder_secret, vcek_chain_cache=_VCEK_CHAIN_CACHE)
            if _VCEK_CHAIN_CACHE is None:
                _VCEK_CHAIN_CACHE = parse_snp_evidence_bundle(bundle).pem_chain

        self._logger.info(f"Generated SEV-SNP bundle: {len(bundle)} bytes")
        return bundle
    
    def get_tls_certificate_filenames(self):
        """Get certificate filenames - parallel to CTLSServer method."""
        return self._tls_certificate_filename, self._tls_key_filename
    
    def create_ssl_context(self):
        """
        Create SSL context with RATLS extensions.
        Returns SSLContext object that can be passed to Flask.
        """
        cert_file, key_file = self.get_tls_certificate_filenames()
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Pin TLS 1.3. The RATLS extension (id 421) is registered for the
        # TLS 1.3 EncryptedCertificate context only (see ratls_python_bridge.c).
        # On TLS 1.2 the server response would silently lack the attestation
        # extension, and the handshake would also pay an extra round trip
        # vs TLS 1.3's 1-RTT. Reference impl does the same via
        # SSL_OP_NO_TLSv1_2 in ratls-external/src/ratls/demo-server.cpp.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert_file, key_file)

        # Register RATLS TLS extension handlers
        self._logger.info("Registering RATLS TLS extension 421...")
        ratls_bridge.setup_ratls_server(context, self.generate_quote)
        self._logger.info("✅ RATLS SSL context ready")
        
        return context


class RATLSServerFactory:
    """Factory for creating RATLS server - parallel to CTLSServerFactory."""
    
    @staticmethod
    def create_ratls_server(environment):
        """Create RATLS server instance."""
        logger = logging.getLogger(__name__)
        return RATLSServer(environment, logger)


# Reverse-proxy to a backend application (e.g. the hotelReservation
# frontend) so RA+TLS can front a real application for the application
# benchmarks.  Set HOTEL_URL=http://<host>:<port> to enable.
import os as _os
_HOTEL_URL = _os.environ.get("HOTEL_URL", "")
# Front a streaming LLM endpoint for the LLM-inference benchmark.
_LLM_URL = _os.environ.get("LLM_URL", "")


@app.route("/reservation")
def handle_reservation():
    import requests as _rq
    if not _HOTEL_URL:
        return "HOTEL_URL not set", 503
    r = _rq.get(f"{_HOTEL_URL}/reservation", params=request.args, timeout=15)
    return (r.content, r.status_code,
            {"Content-Type": r.headers.get("content-type", "application/json")})


@app.route("/generate", methods=["GET", "POST"])
def handle_generate():
    # Forward to the LLM server's /generate; with max_tokens=1 the (non-stream)
    # response returns ~at first token so the client's total time ≈ TTFT.
    import requests as _rq
    if not _LLM_URL:
        return "LLM_URL not set", 503
    j = request.get_json(silent=True) or {}
    prompt = request.args.get("prompt", j.get("prompt", ""))
    max_tokens = int(request.args.get("max_tokens", j.get("max_tokens", 1)))
    r = _rq.post(f"{_LLM_URL}/generate",
                 json={"prompt": prompt, "max_tokens": max_tokens}, timeout=300)
    return (r.content, r.status_code, {"Content-Type": "text/event-stream"})


# Flask routes - same structure as server.py
@app.route("/health")
def handle_health():
    """Capped health endpoint for the equal-setting scale-out microbenchmark.
    The per-connection RA quote runs in the TLS handshake; this models the same
    downstream backend work a \\sys{} backend serves (no-op unless capped)."""
    if not _cap_backend_work():
        return "overloaded", 503
    return "ok\n", 200


@app.route("/")
def handle_index():
    """Serve the index page."""
    from pathlib import Path
    
    admin_dir = Path(__file__).parent
    index_path = admin_dir / 'static' / 'index.html'
    
    if index_path.exists():
        try:
            html_content = index_path.read_text()
            # Add RATLS indicator
            html_content = html_content.replace(
                '</body>',
                '<div style="position:fixed;bottom:10px;right:10px;background:#4CAF50;color:white;padding:10px;border-radius:5px;font-family:monospace;">RATLS Mode</div></body>'
            )
            return html_content, 200, {'Content-Type': 'text/html; charset=utf-8'}
        except Exception as e:
            app.logger.error(f"Error reading index.html: {e}")
    
    # Fallback
    return "<html><body><h1>RATLS Server</h1><p>Running in RATLS mode (per-connection attestation)</p></body></html>"


@app.route("/static/<path:filename>")
def handle_static(filename):
    """Serve static files - parallel to server.py."""
    from pathlib import Path
    from flask import send_file
    
    admin_dir = Path(__file__).parent
    file_path = admin_dir / 'static' / filename
    
    if file_path.exists() and file_path.is_file():
        return send_file(str(file_path))
    else:
        return "Not Found", 404


@app.route("/quote")
def handle_quote():
    """Quote API endpoint - for compatibility with cTLS."""
    from flask import jsonify
    return jsonify({
        "status": "RATLS uses per-connection attestation via TLS extensions",
        "method": "TLS extension 421 during handshake"
    })


def parse_args():
    """Parse arguments - same as server.py."""
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=5001, help="Server port")
    parser.add_argument("-t", "--type", choices=["direct", "snp"], default="snp",
                        help="TEE type: 'snp' for Azure SEV-SNP CVM, 'direct' for non-TEE mock testing")
    args = parser.parse_args()
    return args


def handle_sigint(signal_, frame_):
    """Signal handler - same as server.py."""
    app.logger.info("SIGINT received. Stopping RATLS Server...")
    sys.exit()


def main():
    """Main function - parallel to server.py main()."""
    app.logger.setLevel(logging.INFO)
    
    # Suppress verbose Azure logging
    logger = logging.getLogger("azure")
    logger.setLevel(logging.WARNING)
    
    logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    logger.setLevel(logging.ERROR)
    
    signal.signal(signal.SIGINT, handle_sigint)
    
    args = parse_args()
    port = args.port
    
    app.logger.info(f"Starting RATLS server in '{args.type}' mode...")
    
    # Create RATLS server instance
    global RATLS_SERVER
    RATLS_SERVER = RATLSServerFactory.create_ratls_server(args.type)
    
    # Create SSL context with RATLS extensions
    ssl_context = RATLS_SERVER.create_ssl_context()
    
    # TCP_NODELAY needs to be set BEFORE the TLS handshake. Werkzeug's
    # disable_nagle_algorithm flag is set in WSGIRequestHandler.setup(), which
    # runs *after* SSL wrap — too late for the handshake itself. tcpdump shows
    # OpenSSL splits our server flight into "bulk + 513-B Finished trailer"
    # and Nagle holds the trailer ~40 ms (one RTT) waiting for an ACK,
    # exactly cancelling RA+TLS's architectural 1-RTT advantage. Patching
    # server_bind sets TCP_NODELAY on the listening socket so Linux inherits
    # it onto every accept()'d socket pre-handshake.
    import socket as _socket
    from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler
    _orig_bind = BaseWSGIServer.server_bind
    def _bind_nodelay(self):
        _orig_bind(self)
        self.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    BaseWSGIServer.server_bind = _bind_nodelay
    WSGIRequestHandler.disable_nagle_algorithm = True

    # Run Flask with custom SSL context
    # Key difference from cTLS: we pass SSLContext object instead of (cert, key) tuple
    # threaded=True: handle concurrent connections like a real server (and like
    # Janus, which is measured with its natural concurrency). Single-threading
    # artificially caps throughput below the hardware's concurrent quote-gen rate.
    app.run(
        port=port,
        host="0.0.0.0",
        threaded=True,
        load_dotenv=False,
        ssl_context=ssl_context  # SSLContext object with RATLS extensions!
    )


if __name__ == "__main__":
    main()
