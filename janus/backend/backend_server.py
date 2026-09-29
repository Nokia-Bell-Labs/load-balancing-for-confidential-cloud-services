# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Back-end server for multi-server Janus

Runs inside a CVM (AMD SEV-SNP / Intel TDX) or SGX enclave.  On startup it:

  1. Generates a fresh ECDSA-P256 keypair on every start (design §4.3
     Step 1; a restarted backend re-registers as a fresh one).  The
     algorithm matches the DC signature scheme expected by clients.
  2. Obtains a single-use challenge nonce from the frontend's /nonce
     endpoint (Step 2) unless one was injected by the provisioner (NONCE).
  3. Binds SHA256(nonce ‖ TLS public key) into the evidence: the vTPM
     quote's qualifyingData on SEV-SNP/TDX, REPORTDATA on SGX (Step 3).
  4. Reads the raw attestation evidence (SNP report / SGX quote)
  5. Constructs a CSR and POSTs it, the evidence, the nonce and a
     self-signed certificate over the same key (for the frontend's pinned
     proxy-mode hop) to the frontend's /register_backend endpoint
  6. The frontend verifies attestation via Azure MAA, then returns:
     - A Delegated Credential (DC, RFC 9345) for DC-capable clients
     - The frontend's certificate chain
  7. Keeps the credentials in the sealed directory — RAM-backed on a CVM,
     so the private key never reaches the OS disk
  8. Starts the Flask service; /renew_dc accepts a DC re-signed by the
     frontend after it renews its certificate (design §4.3)

Environment variables:
    FRONTEND_URL          – base URL of the frontend server (required)
    FRONTEND_CA_CERT_PATH – path to the frontend CA cert for TLS verification
                            (set to 'insecure' to skip — useful during testing)
    CVM_TYPE        – 'snp', 'tdx', or 'gramine'  (default: snp)
    BACKEND_PORT    – HTTPS port to listen on      (default: 8443)
    APP_HOME        – base path for sealed storage (default: $HOME)
    NONCE           – attestation nonce from frontend (set during provisioning)
"""

from argparse import ArgumentParser
import base64
import hashlib
import json
import logging
from logging.config import dictConfig
import os
import signal
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from flask import Flask, jsonify, Response, request

import requests

# ── path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..', '..'))   # repo root (parent of janus/)

# ── logging ───────────────────────────────────────────────────────────────────
dictConfig({
    "version": 1,
    "formatters": {"default": {
        "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    }},
    "handlers": {"wsgi": {"class": "logging.StreamHandler", "formatter": "default"}},
    "root": {"level": "INFO", "handlers": ["wsgi"]},
})

app     = Flask(__name__, static_folder=None)
BACKEND = None

_STATIC_DIR = os.path.join(_HERE, "static")


# ═══════════════════════════════════════════════════════════════════════════════
# BackendServer
# ═══════════════════════════════════════════════════════════════════════════════

class BackendServer:
    """
    Janus backend running in an AMD SEV-SNP confidential VM (the SGX/Gramine
    and TDX paths are wired but not part of the evaluation).

    Generates its TLS keypair inside the TEE, registers with the frontend on
    nonce-bound evidence (paper §4.3), and receives an RFC 9345 Delegated
    Credential plus the frontend's certificate chain.  It never obtains a
    certificate from a CA; the self-signed X.509 certificate it writes over
    the same key is what the frontend pins for the proxy-mode hop.
    """

    # Attestation device paths per platform
    _REPORT_DATA_PATHS = {
        "snp":     "/dev/tpm0",
        "tdx":     "/dev/tdx_guest",
        "gramine": "/dev/attestation/user_report_data",
    }
    _QUOTE_PATHS = {
        "snp":     "/dev/tpm0",
        "tdx":     "/dev/tdx_guest",
        "gramine": "/dev/attestation/quote",
    }

    def __init__(
        self,
        frontend_url: str,
        cvm_type: str,
        environment: str,
        logger: logging.Logger,
    ):
        self._frontend_url      = frontend_url.rstrip("/")
        self._cvm_type    = cvm_type      # 'snp', 'tdx', or 'gramine' (testing)
        self._environment = environment   # 'direct' or 'cvm'
        self._logger      = logger

        app_home = os.environ.get("APP_HOME") or os.path.expanduser("~")
        # Design §3 ("all TLS private keys are generated and sealed inside
        # TEEs") and §4.3 (a restarted backend re-registers as a fresh one):
        # on a CVM the TEE boundary is the VM's memory, so the key lives in a
        # RAM-backed directory that never reaches the (unencrypted) OS disk
        # and does not survive a reboot.  Direct/mock mode keeps the on-disk
        # path so the docker-compose test needs no tmpfs.
        default_dir = os.path.join(app_home, "janus", "backend", "sealed")
        if cvm_type in ("snp", "tdx") and os.path.isdir("/dev/shm"):
            default_dir = "/dev/shm/janus-backend-sealed"
        self._sealed_dir = os.environ.get("JANUS_BACKEND_SEALED_DIR", default_dir)
        os.makedirs(self._sealed_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self._sealed_dir, 0o700)
        except OSError:
            pass

        self._private_key_file    = os.path.join(self._sealed_dir, "private_key.pem")
        self._dc_file             = os.path.join(self._sealed_dir, "delegated_credential.bin")
        self._frontend_chain_file = os.path.join(self._sealed_dir, "frontend_chain.pem")
        # Self-signed X.509 certificate over the same key: what dc_proxy
        # presents to clients without DC support (the frontend's proxy-mode
        # hop), which the frontend pins at registration (design §4.4).
        self._cert_file           = os.path.join(self._sealed_dir, "certificate.pem")
        # dc_proxy writes its pid here so a renewed DC can be hot-loaded.
        # One pidfile per dc_proxy instance (dc_proxy.<port>.pid): a CVM may run
        # several terminators on the same credentials (e.g. one per application).
        self._dc_proxy_pidglob    = os.path.join(self._sealed_dir, "dc_proxy*.pid")
        # Frontend public key pinned at registration; a renewed DC is only
        # accepted if it is signed by this key.
        self._frontend_public_key = None

        self._private_key  = None
        self._public_key   = None
        self._frontend_ca_verify  = os.environ.get("FRONTEND_CA_CERT_PATH", "insecure")

        # DC and frontend cert chain (received during provisioning)
        self._dc_bytes            = None
        self._frontend_cert_chain = None

        # nonce for attestation (passed by frontend during CVM provisioning)
        self._nonce = os.environ.get("NONCE", "")

        self._cvm_id = ""

        # Cached AMD cert chain (VCEK || ASK || ARK) for SNP/TDX CVMs; depends
        # only on chip ID + TCB version so it's stable for the VM lifetime.
        # Lazily populated on first use by build_snp_evidence_bundle().
        self._vcek_chain_cache: bytes = None

    # ── keypair ──────────────────────────────────────────────────────────────

    def _init_keypair(self):
        """
        Generate a fresh EC P-256 keypair (every start; nothing is reloaded).

        EC P-256 is required because BoringSSL enforces RFC 9345's prohibition
        on RSA keys in Delegated Credentials (rsaEncryption OID). The backend's
        DC key must be ECDSA-P256-SHA256 (TLS 1.3 signature scheme 0x0403).
        """
        t0 = time.time()
        # Design §4.3 Step 1 / "a restarted backend re-registers precisely as
        # a fresh one would": every start generates a fresh keypair.  Nothing
        # is loaded from storage, so a key never outlives the process that
        # made it.  The PEM exists only so dc_proxy (same TEE) can read it;
        # it is written 0600 into the RAM-backed sealed directory.
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()
        pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        for stale in (self._private_key_file, self._dc_file, self._cert_file):
            try:
                os.remove(stale)
            except FileNotFoundError:
                pass
        fd = os.open(self._private_key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        self._logger.info("Generated fresh EC P-256 keypair (never persisted across restarts)")
        self._keygen_ms = (time.time() - t0) * 1000
        self._logger.info(f"TLS key generation  ⏱ {self._keygen_ms:.2f} ms")

    # ── attestation ──────────────────────────────────────────────────────────

    # ── registration challenge, proxy-hop certificate, DC renewal ────────────

    # PAPER: §4.3 Step 2 — obtain the challenge nonce from the frontend.
    def _fetch_nonce(self, my_ip: str) -> str:
        """Design §4.3 Step 2: obtain a single-use challenge nonce from the
        frontend's /nonce endpoint.  Retries while the frontend starts."""
        verify = (False if self._frontend_ca_verify == "insecure"
                  else self._frontend_ca_verify)
        url = f"{self._frontend_url}/nonce"
        last = None
        for attempt in range(1, 11):
            try:
                r = requests.get(url, params={"ip": my_ip, "cvm_type": self._cvm_type},
                                 verify=verify, timeout=10)
                r.raise_for_status()
                nonce = r.json()["nonce"]
                self._logger.info(f"Challenge nonce obtained from frontend ({nonce[:16]}…)")
                return nonce
            except Exception as exc:
                last = exc
                self._logger.warning(f"Nonce fetch attempt {attempt}/10 failed: {exc}")
                time.sleep(3)
        raise RuntimeError(f"could not obtain a challenge nonce from {url}: {last}")

    def _write_self_signed_cert(self, my_ip: str) -> bytes:
        """Self-signed X.509 certificate over this backend's TLS key.

        dc_proxy presents it to clients that do not offer Delegated
        Credentials — in practice the frontend's proxy-mode hop — and the
        frontend pins its fingerprint at registration (design §4.4).  It
        carries no trust of its own: the pin is the authentication."""
        import datetime as _dt
        import ipaddress as _ip
        now = _dt.datetime.now(_dt.timezone.utc)
        san = []
        try:
            san.append(x509.IPAddress(_ip.ip_address(my_ip)))
        except ValueError:
            san.append(x509.DNSName(my_ip))
        # The name lives in the SAN; the CN is informational and X.520 caps it at 64 chars
        # (a cloud-internal FQDN can be longer).
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, my_ip[:64])])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(self._private_key, hashes.SHA256(), default_backend())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(self._cert_file, "wb") as f:
            f.write(pem)
        return pem

    def _notify_dc_proxy(self) -> None:
        """Ask every running dc_proxy instance (one pidfile each in the sealed
        dir) to reload the credentials on disk: after a DC renewal, and after a
        restart of this process, whose fresh key and DC the terminators would
        otherwise keep ignoring.  Pidfiles of exited instances are removed."""
        import glob
        pidfiles = sorted(glob.glob(self._dc_proxy_pidglob))
        if not pidfiles:
            self._logger.info("No dc_proxy pidfile; nothing to reload")
            return
        for pf in pidfiles:
            try:
                with open(pf) as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGHUP)
                self._logger.info(f"dc_proxy (pid {pid}) signalled to reload credentials")
            except ProcessLookupError:
                self._logger.info(f"dc_proxy pidfile {os.path.basename(pf)} is stale; removed")
                try:
                    os.unlink(pf)
                except OSError:
                    pass
            except Exception as exc:
                self._logger.warning(f"Could not signal dc_proxy via {pf}: {exc}")

    # PAPER: §4.3 'Handling Backend Irregularities' — accept a DC re-signed by the frontend after its certificate renewal.
    def install_renewed_dc(self, dc: bytes, chain_pem: str) -> None:
        """Validate and install a DC re-signed by the frontend under its
        renewed certificate (design §4.3).  Raises ValueError if the chain
        is not from the pinned frontend key or the DC does not verify."""
        from janus.common.dc import verify_dc
        if self._frontend_public_key is None:
            raise ValueError("no frontend key pinned; backend has not registered")
        leaf = x509.load_pem_x509_certificate(chain_pem.encode())
        pinned = self._frontend_public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        offered = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if pinned != offered:
            raise ValueError("renewed chain is not signed by the pinned frontend key")
        verify_dc(dc, leaf, expected_holder_public_key=self._public_key)
        # Atomic replace so dc_proxy never reads a half-written file.
        for path, data, mode in ((self._frontend_chain_file, chain_pem.encode(), "wb"),
                                 (self._dc_file, dc, "wb")):
            tmp = path + ".tmp"
            with open(tmp, mode) as f:
                f.write(data)
            os.replace(tmp, path)
        self._frontend_cert_chain = chain_pem
        self._dc_bytes = dc
        self._logger.info(f"Renewed DC installed ({len(dc)} B)")
        self._notify_dc_proxy()

    def _public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _write_report_data(self):
        """
        Bind the nonce into the platform attestation report:
            REPORTDATA = SHA256(nonce)
        The nonce is provided by the frontend during CVM provisioning.

        Only meaningful for the Gramine SGX path. On Azure SEV-SNP CVMs, the
        SNP report's REPORT_DATA is fixed at boot by the paravisor (set to
        SHA256(vTPM AK pub)); per-connection freshness rides on a TPM2 quote
        whose qualifyingData is bound to this nonce — see
        common.snp_attestation.build_snp_evidence_bundle().
        """
        if self._cvm_type in ("snp", "tdx"):
            return  # paravisor-mediated, no per-call REPORT_DATA write

        nonce_bytes = self._nonce.encode("utf-8") if self._nonce else b""
        reportdata = hashlib.sha256(nonce_bytes).digest()
        path = self._REPORT_DATA_PATHS.get(self._cvm_type,
                                            "/dev/attestation/user_report_data")
        try:
            with open(path, "wb") as f:
                f.write(reportdata)
            self._logger.info(
                f"Report data written: SHA256(nonce)={reportdata.hex()[:32]}…"
            )
        except Exception as exc:
            self._logger.warning(f"Could not write report data to {path}: {exc}")

    # PAPER: §4.3 Step 3 — evidence bound to SHA-256(nonce ‖ TLS public key) (vTPM quote on SNP/TDX, REPORTDATA on SGX).
    def _read_quote(self) -> bytes:
        """Produce raw attestation evidence for the frontend to verify.

        - SGX/Gramine path: read the SGX quote from /dev/attestation/quote
          (REPORT_DATA was already written by _write_report_data()).
        - SEV-SNP / TDX CVM path: build an evidence bundle (HCL report from
          NV 0x01400001 + VCEK chain + optional TPM2 quote signing the
          per-connection nonce). The frontend submits this to Azure MAA's
          /attest/SevSnpVm and verifies the returned JWT.
        """
        if self._cvm_type in ("snp", "tdx"):
            from janus.common.snp_attestation import (build_snp_evidence_bundle,
                                                parse_snp_evidence_bundle)
            nonce_bytes = self._nonce.encode("utf-8") if self._nonce else None
            # Bind the quote to this backend's TLS public key (SPKI DER), not
            # just the nonce (paper §4.3 Steps 3 and 5). The frontend recomputes the
            # same binding from the CSR's public key at registration.
            pubkey_der = self._public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            try:
                bundle = build_snp_evidence_bundle(
                    nonce=nonce_bytes,
                    pubkey_spki_der=pubkey_der,
                    vcek_chain_cache=self._vcek_chain_cache,
                )
                if self._vcek_chain_cache is None:
                    self._vcek_chain_cache = parse_snp_evidence_bundle(bundle).pem_chain
                self._logger.info(
                    f"SNP evidence bundle built ({len(bundle)} bytes; "
                    f"bound={'nonce+pubkey' if nonce_bytes else 'none'})"
                )
                return bundle
            except Exception as exc:
                self._logger.error(f"Failed to build SNP evidence bundle: {exc}")
                return b""

        path = self._QUOTE_PATHS.get(self._cvm_type, "/dev/attestation/quote")
        try:
            with open(path, "rb") as f:
                quote = f.read()
            self._logger.info(f"Quote read ({len(quote)} bytes)")
            return quote
        except Exception as exc:
            self._logger.warning(f"Could not read quote from {path}: {exc}")
            return b""

    def _get_cvm_attestation_jwt(self) -> str:
        """
        Legacy/optional: obtain an MAA JWT directly via Azure's AttestationClient
        (github.com/Azure/confidential-computing-cvm-guest-attestation).

        NOT used by the live registration flow, which sends *raw* SNP evidence
        built by get_quote()/build_snp_evidence_bundle() for the frontend to
        verify at MAA. Kept as a dormant fallback; the binary is no longer
        installed by default (install_backend.sh now installs snpguest +
        tpm2-tools), so this returns "" unless you build AttestationClient
        yourself. Needs sudo because /dev/tpm0 is owned by tss:root.
        """
        import subprocess
        candidates = [
            os.path.expanduser(
                "~/confidential-computing-cvm-guest-attestation-main/"
                "cvm-attestation-sample-app/AttestationClient"
            ),
            "/usr/local/bin/AttestationClient",
        ]
        attest_bin = next((c for c in candidates if os.path.isfile(c)), None)
        if attest_bin is None:
            self._logger.warning(
                "AttestationClient not found – this optional/legacy JWT path is "
                "unavailable (the live flow uses raw SNP evidence and does not "
                "need it). Build AttestationClient manually if you want it."
            )
            return ""
        try:
            result = subprocess.run(
                ["sudo", attest_bin, "-o", "token"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                jwt = result.stdout.strip()
                self._logger.info(f"CVM attestation JWT obtained ({len(jwt)} chars)")
                return jwt
            self._logger.warning(
                f"AttestationClient returned {result.returncode}: "
                f"{result.stderr[:200]}"
            )
        except Exception as exc:
            self._logger.warning(f"Could not obtain CVM attestation JWT: {exc}")
        return ""

    # ── CSR ──────────────────────────────────────────────────────────────────

    def _build_csr(self, my_ip: str = None) -> bytes:
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ctls-backend"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               f"Janus backend ({self._cvm_type})"),
        ])
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        # Add IP SAN so the frontend can verify TLS by IP address
        if my_ip:
            import ipaddress
            try:
                san = x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address(my_ip))
                ])
                builder = builder.add_extension(san, critical=False)
            except ValueError:
                pass  # not a valid IP, skip SAN
        csr = builder.sign(self._private_key, hashes.SHA256(), default_backend())
        return csr.public_bytes(serialization.Encoding.PEM)

    # ── registration with frontend ──────────────────────────────────────────

    # PAPER: §4.3 Step 4 — CSR + evidence (+ nonce) sent to the frontend; Step 7 — DC and frontend chain received.
    def register_with_frontend(self, my_ip: str, my_port: int = 8443) -> bool:
        """
        Obtain raw attestation evidence, POST CSR + quote + nonce to /register_backend.
        On success, stores the DC and the frontend certificate chain in the sealed
        directory (RAM-backed /dev/shm/janus-backend-sealed on a CVM).
        Retries up to 10 times on network errors (frontend may still be starting).

        The frontend submits the raw evidence to Azure MAA and verifies that the
        quote's qualifyingData binds the challenge nonce together with this
        backend's TLS public key, preventing replay and key substitution.
        """
        t0_quote = time.time()
        # Write nonce-based REPORTDATA and read raw attestation evidence
        self._write_report_data()
        quote = self._read_quote()
        self._quote_gen_ms = (time.time() - t0_quote) * 1000
        self._logger.info(f"Quote generation  ⏱ {self._quote_gen_ms:.2f} ms")

        csr_pem = self._build_csr(my_ip)

        payload = {
            "csr_pem":    csr_pem.decode(),
            "quote_b64":  base64.b64encode(quote).decode(),
            "nonce":      self._nonce,
            "cvm_type":   self._cvm_type,
            "ip_address": my_ip,
            "port":       my_port,
            # Self-signed certificate over the CSR key, for the frontend to
            # pin its proxy-mode hop to this backend (design §4.4).
            "cert_pem":   self._write_self_signed_cert(my_ip).decode(),
        }

        verify = (False if self._frontend_ca_verify == "insecure"
                  else self._frontend_ca_verify)
        url    = f"{self._frontend_url}/register_backend"

        for attempt in range(1, 11):
            try:
                self._logger.info(
                    f"Registering with frontend at {url} (attempt {attempt}/10)…"
                )
                t0_reg = time.time()
                resp = requests.post(url, json=payload, verify=verify, timeout=30)

                if resp.status_code == 200:
                    self._cert_issuance_ms = (time.time() - t0_reg) * 1000
                    data = resp.json()

                    # Store DC (base64-encoded raw bytes)
                    dc_b64 = data.get("dc_b64", "")
                    if dc_b64:
                        self._dc_bytes = base64.b64decode(dc_b64)
                        with open(self._dc_file, "wb") as f:
                            f.write(self._dc_bytes)
                        self._logger.info(f"DC stored ({len(self._dc_bytes)}B)")

                    # Store frontend certificate chain (used as leaf in DC TLS)
                    frontend_chain_pem = data.get("frontend_cert_chain_pem", "")
                    if frontend_chain_pem:
                        self._frontend_cert_chain = frontend_chain_pem
                        with open(self._frontend_chain_file, "w") as f:
                            f.write(frontend_chain_pem)
                        # Pin the frontend's public key: a renewed DC pushed
                        # later (/renew_dc) is accepted only under this key.
                        self._frontend_public_key = x509.load_pem_x509_certificate(
                            frontend_chain_pem.encode()).public_key()

                    self._cvm_id = data.get("cvm_id", "")
                    self._logger.info(
                        f"Registered: cvm_id={self._cvm_id[:16]}… "
                        f"DC={len(self._dc_bytes or b'')}B"
                    )
                    self._logger.info(
                        f"Credential issuance (E2E with frontend)  ⏱ {self._cert_issuance_ms:.2f} ms"
                    )
                    return True

                self._logger.error(
                    f"Frontend returned {resp.status_code}: {resp.text[:200]}"
                )
            except Exception as exc:
                self._logger.warning(f"Attempt {attempt} failed: {exc}")

            time.sleep(10)

        self._logger.error("Could not register with frontend after 10 attempts")
        return False

    # ── public helpers ────────────────────────────────────────────────────────

    # PAPER: §4.3 Step 1 — fresh TLS keypair in the TEE; a restarted backend re-registers as a fresh one.
    def initialise(self, my_ip: str, my_port: int = 8443) -> bool:
        """Full initialisation: fresh keypair, challenge nonce, registration.

        Design §4.3: a restarted backend re-registers exactly as a fresh one
        would — there is no credential reuse across starts."""
        self._init_keypair()
        if not self._nonce:
            # Step 2: the backend contacts the frontend, which responds with a
            # unique challenge nonce (bound into the evidence in Step 3).
            self._nonce = self._fetch_nonce(my_ip)
        ok = self.register_with_frontend(my_ip, my_port)
        if ok:
            # Terminators that are already running (this process restarted
            # under live dc_proxy instances) must load the fresh key and DC.
            self._notify_dc_proxy()
        if ok:
            self._logger.info("=" * 60)
            self._logger.info("BACKEND STARTUP LATENCY SUMMARY")
            self._logger.info("=" * 60)
            for label, key in [
                ("TLS key generation", "_keygen_ms"),
                ("SGX Quote generation", "_quote_gen_ms"),
                ("Credential issuance (DC E2E with frontend)", "_cert_issuance_ms"),
            ]:
                val = getattr(self, key, None)
                if val is not None:
                    self._logger.info(f"  {label:45s} ⏱ {val:.2f} ms")
            self._logger.info("=" * 60)
        return ok

    def get_tls_context_files(self):
        # Used only by the fallback HTTPS path (--plain=False). When running
        # behind dc_proxy (the normal path), Flask serves plain HTTP instead.
        # Returns (cert_file, key_file) using the frontend cert chain as leaf.
        return self._frontend_chain_file, self._private_key_file

    def get_public_key_pem(self) -> str:
        return self._public_key_pem().decode()

    def get_cvm_info(self) -> dict:
        """Return a summary dict for use in /quote and the web page."""
        dc_expires = ""
        if self._dc_bytes and self._frontend_cert_chain:
            try:
                import struct as _struct
                from datetime import timedelta as _td, timezone as _tz
                valid_time = _struct.unpack(">I", self._dc_bytes[:4])[0]
                fe = x509.load_pem_x509_certificate(self._frontend_cert_chain.encode())
                try:
                    not_before = fe.not_valid_before_utc
                except AttributeError:
                    not_before = fe.not_valid_before.replace(tzinfo=_tz.utc)
                dc_expires = (not_before + _td(seconds=valid_time)).isoformat()
            except Exception:
                pass
        return {
            "cvm_id":      self._cvm_id,
            "cvm_type":    self._cvm_type,
            "dc_expires":  dc_expires,
            "environment": self._environment,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Flask routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def handle_index():
    """Serve the attested web page."""
    index_path = os.path.join(_STATIC_DIR, "index.html")
    try:
        with open(index_path, "r") as f:
            html = f.read()
        # Inject runtime CVM info into the page
        if BACKEND:
            info = BACKEND.get_cvm_info()
            html = html.replace("{{CVM_TYPE}}", info["cvm_type"].upper())
            html = html.replace("{{CVM_ID}}", info["cvm_id"][:32] if info["cvm_id"] else "N/A")
            html = html.replace("{{CERT_EXPIRES}}", info.get("dc_expires", ""))
        return Response(html, mimetype="text/html")
    except FileNotFoundError:
        # Minimal fallback if static dir wasn't deployed
        info = BACKEND.get_cvm_info() if BACKEND else {}
        return jsonify({"service": "Janus Backend Server", **info})


# ── Rate cap for the §6.1 scalability experiment ────────────────────────────
# Model a heavier, more realistic backend with a fixed per-request service time
# and bounded concurrency, so the backend's max serving rate ~= workers/service.
# Both the proxy (/forward) path and the redirect data path terminate at this
# Flask server, so capping here caps both modes. Controlled by env vars:
#   CTLS_SERVICE_MS    fixed per-request service time (ms); 0 = uncapped (default)
#   CTLS_MAX_INFLIGHT  concurrent service slots; <=0 = unbounded (default)
# Overflow beyond the slots is rejected (503) so the process stays stable under
# open-loop overload; the achieved 200-rate saturates at the cap.
_SERVICE_S = float(os.environ.get("CTLS_SERVICE_MS", "0") or "0") / 1000.0
_MAX_INFLIGHT = int(os.environ.get("CTLS_MAX_INFLIGHT", "0") or "0")
_CAP_SEM = threading.Semaphore(_MAX_INFLIGHT) if _MAX_INFLIGHT > 0 else None


def _serve_capped(make_response):
    """Apply the configured service-time + concurrency cap, then build the
    response. No-op when CTLS_SERVICE_MS is unset (uncapped baseline)."""
    if _CAP_SEM is not None:
        if not _CAP_SEM.acquire(timeout=max(_SERVICE_S, 0.001)):
            return Response(status=503)
        try:
            if _SERVICE_S:
                time.sleep(_SERVICE_S)
            return make_response()
        finally:
            _CAP_SEM.release()
    if _SERVICE_S:
        time.sleep(_SERVICE_S)
    return make_response()


@app.route("/payload", methods=["GET"])
def handle_payload():
    """Serve a response of configurable size — for scalability tests where
    we want backends to do meaningful per-request work. Use ?bytes=N to
    request N bytes (max 16 MB). Honours the CTLS_SERVICE_MS rate cap."""
    from flask import request as _req
    n = min(int(_req.args.get("bytes", "65536")), 16 * 1024 * 1024)
    return _serve_capped(
        lambda: Response(b"x" * n, mimetype="application/octet-stream"))


@app.route("/static/<path:filename>", methods=["GET"])
def handle_static(filename):
    from flask import abort as _abort
    path = os.path.realpath(os.path.join(_STATIC_DIR, filename))
    if not path.startswith(os.path.realpath(_STATIC_DIR)):
        _abort(403)
    if not os.path.isfile(path):
        _abort(404)
    with open(path, "rb") as f:
        return Response(f.read())


@app.route("/quote", methods=["GET"])
def handle_quote():
    """
    Return the back-end's DC, frontend cert chain, and attestation info.

    In redirection mode with DC, the backend presents the frontend's cert
    as the leaf in its TLS handshake and the DC as a TLS extension.  This
    endpoint lets clients fetch the DC + chain for offline verification
    (since BoringSSL's client side cannot yet process DC extensions in
    the TLS handshake itself).
    """
    result = {
        "public_key_pem":  BACKEND.get_public_key_pem()  if BACKEND else "",
        "cvm_info":        BACKEND.get_cvm_info()         if BACKEND else {},
    }

    # DC (for client-side offline DC verification)
    if BACKEND and BACKEND._dc_bytes:
        result["dc_b64"] = base64.b64encode(BACKEND._dc_bytes).decode()
    else:
        result["dc_b64"] = ""

    # Frontend cert chain (needed to verify the DC signature)
    if BACKEND and BACKEND._frontend_cert_chain:
        result["frontend_cert_chain_pem"] = BACKEND._frontend_cert_chain
    else:
        result["frontend_cert_chain_pem"] = ""

    # Include raw SNP/TDX quote if available (for advanced clients)
    if BACKEND and BACKEND._cvm_type in ("snp", "tdx", "gramine"):
        try:
            quote_path = BackendServer._QUOTE_PATHS.get(
                BACKEND._cvm_type, "/dev/attestation/quote"
            )
            with open(quote_path, "rb") as f:
                result["quote_b64"] = base64.b64encode(f.read()).decode()
        except Exception:
            result["quote_b64"] = ""

    return jsonify(result)


@app.route("/renew_dc", methods=["POST"])
def handle_renew_dc():
    """Design §4.3: when the frontend renews its certificate it re-signs this
    backend's DC and pushes it here (reached through dc_proxy's relay).

    Body: {"dc_b64": ..., "frontend_cert_chain_pem": ...}.  Accepted only if
    the new chain's leaf carries the frontend public key pinned at
    registration and the DC verifies under that leaf for our own key."""
    data = request.get_json(force=True) or {}
    try:
        dc = base64.b64decode(data.get("dc_b64") or "")
        chain_pem = data.get("frontend_cert_chain_pem") or ""
        if not dc or not chain_pem:
            return jsonify({"success": False, "error": "dc_b64 and frontend_cert_chain_pem required"}), 400
        BACKEND.install_renewed_dc(dc, chain_pem)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 403
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    return jsonify({"success": True})


@app.route("/health", methods=["GET"])
def handle_health():
    # Honours the CTLS_SERVICE_MS rate cap so the scalability run can model a
    # heavier backend on the same trivial endpoint the 1->32 run used.
    return _serve_capped(lambda: jsonify({"status": "ok"}))


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        "--frontend-url", default=os.environ.get("FRONTEND_URL", "https://localhost:6037")
    )
    parser.add_argument(
        "--cvm-type", default=os.environ.get("CVM_TYPE", "snp"),
        choices=["snp", "tdx", "gramine"],
    )
    parser.add_argument(
        "--type", choices=["direct", "cvm"], default="direct", dest="environment"
    )
    parser.add_argument("--my-ip", default=os.environ.get("MY_IP", "127.0.0.1"))
    parser.add_argument(
        "-p", "--port", type=int,
        default=int(os.environ.get("BACKEND_PORT", 8443)),
    )
    parser.add_argument(
        "--public-port", type=int,
        default=int(os.environ.get("BACKEND_PUBLIC_PORT", 0)),
        help="Externally-visible port to register with frontend "
             "(defaults to --port; set to dc_proxy listen port when behind dc_proxy)"
    )
    parser.add_argument(
        "--bind", default=os.environ.get("BACKEND_BIND", "0.0.0.0"),
        help="Interface to bind on (default: 0.0.0.0; use 127.0.0.1 when behind dc_proxy)"
    )
    parser.add_argument(
        "--plain", action="store_true",
        default=os.environ.get("BACKEND_PLAIN", "") == "1",
        help="Serve plain HTTP (no TLS) — use when behind dc_proxy"
    )
    return parser.parse_args()


def handle_sigint(sig, frame):
    app.logger.info("SIGINT received – stopping backend server")
    sys.exit(0)


def main():
    app.logger.setLevel(logging.INFO)
    signal.signal(signal.SIGINT, handle_sigint)

    args = parse_args()
    app.logger.info(f"Starting Janus backend server (type={args.cvm_type})…")

    global BACKEND
    BACKEND = BackendServer(
        frontend_url=args.frontend_url,
        cvm_type=args.cvm_type,
        environment=args.environment,
        logger=app.logger,
    )

    register_port = args.public_port or args.port
    ok = BACKEND.initialise(my_ip=args.my_ip, my_port=register_port)
    if not ok:
        app.logger.error("Initialisation failed – exiting")
        sys.exit(1)

    if args.plain:
        app.logger.info(f"Starting Flask HTTP on {args.bind}:{args.port} (behind dc_proxy)")
        app.run(
            port=args.port, host=args.bind,
            threaded=True, load_dotenv=False,
        )
    else:
        cert_file, key_file = BACKEND.get_tls_context_files()
        app.logger.info(f"Starting Flask HTTPS on {args.bind}:{args.port}")
        app.run(
            port=args.port, host=args.bind,
            threaded=True, load_dotenv=False,
            ssl_context=(cert_file, key_file),
        )


if __name__ == "__main__":
    main()
