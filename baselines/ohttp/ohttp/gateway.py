# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""OHTTP+KMS baseline -- the gateway (backend) role.

Runs inside each SEV-SNP CVM in the slot ``dc_proxy`` occupies for Janus:
terminates the (untrusted) HTTPS hop from the front end, decapsulates the
HPKE-sealed request, relays the plaintext request to the unmodified
application on loopback, and streams the response back sealed chunk by
chunk (RFC 9458 s4.4 keys, chunked framing).

Key acquisition is *lazy*, as in Azure's design ("if the gateway sees a
request encrypted with a key identifier it hasn't cached yet, it must obtain
the private key from the KMS"): on an unknown key_id the gateway builds its
SNP evidence bundle (janus.common.snp_attestation), POSTs it with its CSR to
the KMS's /release_key, and unwraps the returned private key.  The evidence
and CSR code is the Janus backend's own (``BackendServer``), so the gateway
attests exactly as a Janus backend does; the cost is paid once per key
epoch per gateway and reported to the caller via ``X-Key-Fetch-Ms``.

Replay protection follows RFC 9458 s6.5: the inner request must carry a
``Date`` within the window and each ``enc`` is accepted once.

Environment (same names as the Janus backend where the meaning is the same):
    KMS_URL            https://<kms-host>:6038
    FRONTEND_URL       untrusted front end to register with (optional;
                       plain forwarding instance, mock attestation accepted)
    MY_IP, BACKEND_PORT, CVM_TYPE, APP_HOME, NONCE, FRONTEND_CA_CERT_PATH
    OHTTP_TARGET       app URL on loopback (default http://127.0.0.1:8080)
    OHTTP_MOCK_ATTEST  1 -> send an empty quote (frontend mock path), for tests
"""
from __future__ import annotations

import base64
import functools
import logging
import os
import ssl
import sys
import threading
import time
from argparse import ArgumentParser
from pathlib import Path

import requests
from cryptography import x509
from flask import Flask, Response, request, stream_with_context

_HERE = Path(__file__).resolve()
_CODEBASE = _HERE.parents[3]
for p in (str(_CODEBASE), str(_HERE.parents[1])):
    if p not in sys.path:
        sys.path.insert(0, p)

from janus.backend.backend_server import BackendServer  # noqa: E402
from janus.client import attest  # noqa: E402
from janus.common import snp_attestation as _snp  # noqa: E402
from ohttp import wire  # noqa: E402

# The gateway attests on every key fetch (BackendServer._read_quote). A Janus backend measures its code
# once, at registration. Measure once per gateway process too: hash the code and extend PCR 15 on the
# first key fetch only. Every key fetch still sends a fresh quote bound to its nonce, and the quote
# still covers PCR 15, so the KMS checks the same values.
_snp.janus_measurement_entries = functools.lru_cache(maxsize=None)(_snp.janus_measurement_entries)
_snp.app_measurement_entries = functools.lru_cache(maxsize=None)(_snp.app_measurement_entries)
_extend_code_pcr_orig, _pcr_extended, _pcr_lock = _snp.extend_code_pcr, set(), threading.Lock()


def _extend_once(janus_digest: bytes, app_digest: bytes) -> None:
    with _pcr_lock:
        if (janus_digest, app_digest) not in _pcr_extended:
            _extend_code_pcr_orig(janus_digest, app_digest)
            _pcr_extended.add((janus_digest, app_digest))


_snp.extend_code_pcr = _extend_once

log = logging.getLogger("ohttp-gateway")
app = Flask(__name__)

TARGET = os.environ.get("OHTTP_TARGET", "http://127.0.0.1:8080").rstrip("/")
MOCK_ATTEST = os.environ.get("OHTTP_MOCK_ATTEST") == "1"
REPLAY = wire.ReplayWindow(window_s=int(os.environ.get("OHTTP_REPLAY_WINDOW_S", "60")))
# The attestation service the KMS's certificate must come from (issuer pin, as the
# Janus client pins it for the frontend).  Unset = the JWT's own issuer, unpinned.
MAA_ISSUER = (os.environ.get("MAA_URL") or os.environ.get("MAA_ISSUER") or "").rstrip("/")
_UPSTREAM = threading.local()


def _upstream_session() -> requests.Session:
    """One keep-alive connection pool per worker thread to the application, as the
    Janus dc_proxy keeps its upstream connection open, instead of a new loopback
    TCP connection per request."""
    s = getattr(_UPSTREAM, "session", None)
    if s is None:
        s = _UPSTREAM.session = requests.Session()
    return s


class _MemJwks:
    """In-memory AS signing-key cache for the gateway's verification of the KMS."""
    def __init__(self):
        self._d: dict = {}

    def get(self, issuer, kid):
        return self._d.get((issuer, kid))

    def put(self, issuer, kid, entry):
        self._d[(issuer, kid)] = entry

    def evict(self, issuer, kid):
        self._d.pop((issuer, kid), None)
GW = None  # Gateway


class Gateway:
    """Key cache + lazy release from the KMS, reusing the Janus backend's
    key generation and evidence code."""

    def __init__(self, kms_url: str, my_ip: str, my_port: int, cvm_type: str):
        self.kms_url = kms_url.rstrip("/")
        self.my_ip, self.my_port = my_ip, my_port
        self._be = BackendServer(frontend_url=kms_url, cvm_type=cvm_type,
                                 environment="direct", logger=log)
        self._be._init_keypair()                 # sealed P-256 key (the "attested key")
        self._load_or_persist_key()
        self._keys: dict[int, tuple[bytes, float]] = {}   # key_id -> (HPKE private key, not_after)
        self._lock = threading.Lock()
        # One key fetch at a time: all fetches share the BackendServer's nonce (and the first one
        # extends PCR 15), so concurrent misses on different key ids must not interleave.
        self._fetch_lock = threading.Lock()
        self._kms = requests.Session()           # keep-alive to the KMS: one TLS handshake, not one per call
        self._jwks = _MemJwks()
        self.last_fetch_ms: float = 0.0
        self._verify = (False if self._be._frontend_ca_verify == "insecure"
                        else self._be._frontend_ca_verify)

    def _evidence(self) -> bytes:
        if MOCK_ATTEST:
            return b""
        self._be._write_report_data()
        evidence = self._be._read_quote()
        # BackendServer reports collection failures as an empty byte string.
        # Do not send that to the shared verifier's mock-admission fallback:
        # a successful release must have paid for real, key-bound evidence.
        if not evidence:
            raise RuntimeError("SNP evidence generation failed; refusing key release with empty evidence")
        from janus.common.snp_attestation import parse_snp_evidence_bundle
        bundle = parse_snp_evidence_bundle(evidence)
        if not bundle.tpm_quote_msg or not bundle.tpm_quote_sig:
            raise RuntimeError("Gateway admission requires a TPM quote and signature")
        return evidence

    def fetch_key(self, key_id: int) -> bytes:
        """Attest to the KMS and obtain ``key_id``'s private key (lazy path)."""
        t0 = time.time()
        # Challenge nonce from the KMS; bound with our public key into the
        # TPM quote (SHA256(nonce || pubkey) as qualifyingData) so the KMS
        # verifies both freshness and that the released key goes to this key.
        r = self._kms.get(f"{self.kms_url}/nonce", params={"ip": self.my_ip},
                          verify=self._verify, timeout=30)
        r.raise_for_status()
        self._be._nonce = r.json()["nonce"]
        if not isinstance(self._be._nonce, str) or not self._be._nonce:
            raise RuntimeError("KMS supplied no admission nonce")
        t_nonce = time.time()
        evidence = self._evidence()            # vTPM quote + SNP report (+VCEK once)
        t_evidence = time.time()
        payload = {
            "csr_pem": self._be._build_csr(self.my_ip).decode(),
            "quote_b64": base64.b64encode(evidence).decode(),
            "nonce": self._be._nonce,
            "cvm_type": self._be._cvm_type,
            "ip_address": self.my_ip,
            "port": self.my_port,
            "key_id": key_id,
        }
        resp = self._kms.post(f"{self.kms_url}/release_key", json=payload,
                              verify=self._verify, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"KMS refused key release: {resp.status_code} {resp.text[:200]}")
        t_release = time.time()
        data = resp.json()
        # The key comes from an attested KMS: verify the AS-signed evidence in the
        # KMS's certificate chain (the same checks the client runs on the KMS and
        # the Janus client on the frontend) before trusting the released key.
        self._verify_kms_identity(data.get("kms_cert_chain_pem", ""))
        sk = wire.unwrap_private_key(base64.b64decode(data["wrapped_key_b64"]),
                                     self._be._private_key)
        with self._lock:
            self._keys[int(data["key_id"])] = (sk, float(data.get("not_after") or 0))
        self.last_fetch_ms = (time.time() - t0) * 1000
        log.info(f"Obtained key_id={data['key_id']} from KMS  ⏱ {self.last_fetch_ms:.2f} ms "
                 f"(KMS attest {data.get('attest_ms')} ms)")
        # Registration breakdown (Table 1 analogue for the gateway).
        log.info("Key fetch breakdown: nonce %.2f ms, evidence %.2f ms, "
                 "release %.2f ms (KMS attest %s ms), unwrap %.2f ms",
                 (t_nonce - t0) * 1000, (t_evidence - t_nonce) * 1000,
                 (t_release - t_evidence) * 1000, data.get("attest_ms"),
                 (time.time() - t_release) * 1000)
        return sk

    def _verify_kms_identity(self, chain_pem: str) -> None:
        if MOCK_ATTEST:
            return
        cert = x509.load_pem_x509_certificates(chain_pem.encode())[0]
        token = attest.extract_jwt(cert)
        header, payload, _ = attest.parse_jwt(token)
        jwks = attest.get_maa_public_key(payload.get("iss", ""), header.get("kid", ""),
                                         header.get("jku", ""), self._jwks, 15,
                                         trusted_issuer=MAA_ISSUER or None)
        attest.verify_jwt_rs256(token, jwks.public_key)
        attest.verify_jwt_validity(payload)
        attest.verify_reportdata_ctls(cert, payload)

    def key_for(self, key_id: int) -> tuple[bytes, float]:
        """Return (private key, fetch_ms); fetch_ms is 0 on a cache hit.  A key past
        its not_after is dropped (RFC 9458 key configurations expire).  Concurrent
        misses on one key id share a single fetch."""
        with self._lock:
            ent = self._keys.get(key_id)
            if ent is not None and ent[1] and time.time() > ent[1]:
                self._keys.pop(key_id, None)
                ent = None
            if ent is not None:
                return ent[0], 0.0
        with self._fetch_lock:
            with self._lock:
                ent = self._keys.get(key_id)
            if ent is not None:
                return ent[0], 0.0
            return self.fetch_key(key_id), self.last_fetch_ms

    def evict(self, key_id: int) -> None:
        """Drop a cached key.  The RFC 9458 key identifier is one byte, so
        after 256 rotations an id names a *new* key; a decapsulation failure
        with a cached key is treated as a cache miss (refetch from the KMS)."""
        with self._lock:
            self._keys.pop(key_id, None)

    def _load_or_persist_key(self) -> None:
        """gunicorn loads the certificate in its master process and builds the
        application (this object) in a worker, so the key must survive across
        processes: reuse the key in the sealed directory if one exists, else keep
        the fresh one there (0600, RAM-backed on a CVM)."""
        from cryptography.hazmat.primitives import serialization as _ser
        kf = self._be._private_key_file
        if os.path.isfile(kf):
            with open(kf, "rb") as f:
                self._be._private_key = _ser.load_pem_private_key(f.read(), password=None)
            self._be._public_key = self._be._private_key.public_key()
            return
        pem = self._be._private_key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                                  _ser.NoEncryption())
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    def tls_files(self) -> tuple[str, str]:
        """(certificate, key) files the gateway serves on its TLS port: a self-signed
        certificate over its attested key, as a Janus backend's dc_proxy serves,
        so the front end's pinned upstream connection matches the registration."""
        if not os.path.isfile(self._be._cert_file):
            self._be._write_self_signed_cert(self.my_ip)
        return self._be._cert_file, self._be._private_key_file

    def register_with_frontend(self, frontend_url: str):
        """Join the untrusted front end's pool.  The front end is not a TEE and does
        not attest gateways (the KMS does, at key release); it only keeps the pool,
        so the registration carries no evidence.  It still needs the front end's
        challenge nonce, which the registration path requires."""
        fe = frontend_url.rstrip("/")
        for attempt in range(1, 21):
            try:
                nonce = requests.get(f"{fe}/nonce", params={"ip": self.my_ip},
                                     verify=False, timeout=15).json()["nonce"]
                payload = {"csr_pem": self._be._build_csr(self.my_ip).decode(), "quote_b64": "",
                           "nonce": nonce, "cvm_type": self._be._cvm_type,
                           "ip_address": self.my_ip, "port": self.my_port,
                           # the certificate this gateway serves on its TLS port (over its
                           # attested key); the front end pins it for the forwarding hop
                           "cert_pem": open(self.tls_files()[0]).read()}
                r = requests.post(f"{fe}/register_backend",
                                  json=payload, verify=False, timeout=15)
                if r.status_code == 200:
                    log.info(f"Registered with front end {frontend_url}")
                    return True
                log.warning(f"front end returned {r.status_code}: {r.text[:120]}")
            except Exception as exc:
                log.warning(f"front end registration attempt {attempt}: {exc}")
            time.sleep(3)
        return False


# ── request handling ────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return {"ok": True, "keys": sorted(GW._keys)}


@app.route("/ohttp", methods=["POST"])
@app.route("/ohttp/<path:_ignored>", methods=["POST"])
def ohttp(_ignored: str = ""):
    """Decapsulate, relay to the app, stream the sealed response."""
    encapsulated = request.get_data()
    if request.headers.get("Content-Type", "") != wire.MT_REQUEST or len(encapsulated) < 7 + 65 + 16:
        return Response("bad encapsulated request", status=400)
    key_id = wire.peek_key_id(encapsulated)
    try:
        sk, fetch_ms = GW.key_for(key_id)
    except Exception as exc:
        log.error(f"key fetch failed: {exc}")
        return Response("key unavailable", status=422)   # RFC 9458 s5.3
    try:
        rctx = wire.RecipientContext(sk, encapsulated)
    except Exception:
        if fetch_ms:                       # freshly fetched key: a real failure
            return Response("decapsulation failed", status=400)
        GW.evict(key_id)                   # stale cached key (id wrapped)
        try:
            sk, fetch_ms = GW.key_for(key_id)
            rctx = wire.RecipientContext(sk, encapsulated)
        except Exception as exc:
            log.error(f"decapsulation after refetch failed: {exc}")
            return Response("decapsulation failed", status=400)
    try:
        method, path, headers, body = wire.decode_inner_request(rctx.inner_request)
    except Exception as exc:
        return Response(f"bad inner request: {exc}", status=400)
    if not REPLAY.check(rctx.enc, headers.get("date")):
        return Response("replayed or stale request", status=400)

    upstream = _upstream_session().request(method, f"{TARGET}{path}", headers=headers,
                                           data=body, stream=True, timeout=300)
    sealer = rctx.response_sealer()

    def gen():
        # Inner response head, then body chunks; each becomes one AEAD record.
        head = f"{upstream.status_code}\n".encode() + "".join(
            f"{k}: {v}\n" for k, v in upstream.headers.items()
            if k.lower() not in ("transfer-encoding", "content-length", "connection")
        ).encode() + b"\n"
        try:
            yield sealer.header()
            yield sealer.seal_record(head)
            for chunk in upstream.iter_content(chunk_size=None):
                if chunk:
                    yield sealer.seal_record(chunk)
            yield sealer.final()
        finally:
            upstream.close()

    return Response(stream_with_context(gen()), mimetype=wire.MT_CHUNKED_RESPONSE,
                    headers={"X-Key-Fetch-Ms": f"{fetch_ms:.3f}"})


# ── entry point ─────────────────────────────────────────────────────────────

def parse_args():
    p = ArgumentParser()
    p.add_argument("--kms-url", default=os.environ.get("KMS_URL", "https://localhost:6038"))
    p.add_argument("--frontend-url", default=os.environ.get("FRONTEND_URL", ""))
    p.add_argument("--my-ip", default=os.environ.get("MY_IP", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("BACKEND_PORT", "8443")))
    p.add_argument("--cvm-type", default=os.environ.get("CVM_TYPE", "snp"))
    p.add_argument("--print-tls-files", action="store_true",
                   help="write the certificate over the attested key and print '<cert> <key>' for gunicorn")
    p.add_argument("--prefetch", action="store_true",
                   help="obtain the current key at startup instead of lazily")
    return p.parse_args()


def create_app():
    """WSGI entry point for a production-grade server (gunicorn), e.g.
        gunicorn --worker-class gthread --threads 32 --keep-alive 75 \
                 --certfile <sealed>/certificate.pem --keyfile <sealed>/private_key.pem \
                 -b 0.0.0.0:8443 'ohttp.gateway:create_app()'
    (the files under the backend's sealed directory, $APP_HOME/janus/backend/sealed,
    written by ``python3 -m ohttp.gateway --print-tls-files``; the front end pins
    that certificate at registration).
    Configuration comes from the environment (KMS_URL, FRONTEND_URL, MY_IP,
    BACKEND_PORT, CVM_TYPE).  Unlike the development
    server, gunicorn keeps TLS connections alive, so the front end's pooled
    connection to the gateway is reused across requests (a production
    gateway's behaviour; the dev server closes every connection, which
    costs a TLS handshake per forwarded request).
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    global GW
    if GW is None:
        GW = Gateway(os.environ.get("KMS_URL", "https://localhost:6038"),
                     os.environ.get("MY_IP", "127.0.0.1"),
                     int(os.environ.get("BACKEND_PORT", "8443")),
                     os.environ.get("CVM_TYPE", "snp"))
        fe = os.environ.get("FRONTEND_URL", "")
        if fe:
            GW.register_with_frontend(fe)
        cert, key = GW.tls_files()
        log.info(f"OHTTP gateway (WSGI) -> {TARGET}; KMS {GW.kms_url}; lazy key fetch; "
                 f"serve with --certfile {cert} --keyfile {key}")
    return app


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args()
    global GW
    GW = Gateway(args.kms_url, args.my_ip, args.port, args.cvm_type)
    if args.print_tls_files:
        # a fresh identity for this start: drop an older certificate, keep the key just persisted
        if os.path.isfile(GW._be._cert_file):
            os.remove(GW._be._cert_file)
        print(*GW.tls_files())
        return
    if args.prefetch:
        GW.fetch_key(requests.get(f"{args.kms_url}/", verify=False, timeout=15).json()["key_id"])
    if args.frontend_url:
        GW.register_with_frontend(args.frontend_url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(*GW.tls_files())     # the certificate registered with the front end
    log.info(f"OHTTP gateway on :{args.port} -> {TARGET}; KMS {args.kms_url}; lazy key fetch")
    # TCP_NODELAY on accepted sockets: without it the development server's
    # TLS responses wait on Nagle/delayed-ACK (measured +10 ms per request
    # on the CVM), which is an artefact of the server, not of the protocol.
    from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler
    WSGIRequestHandler.disable_nagle_algorithm = True
    # ... and on the listening socket, so it is set BEFORE the TLS handshake
    # (see kms.py:_nodelay_before_handshake).
    import socket as _socket
    _orig_bind = BaseWSGIServer.server_bind

    def _server_bind_nodelay(self):
        self.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        return _orig_bind(self)
    BaseWSGIServer.server_bind = _server_bind_nodelay
    # HTTP/1.1 keep-alive so the front end's pooled connection to the
    # gateway is reused across requests (the dev server defaults to
    # HTTP/1.0 + Connection: close, i.e. a TLS handshake per forward).
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run(host="0.0.0.0", port=args.port, threaded=True, load_dotenv=False, ssl_context=ctx)


if __name__ == "__main__":
    main()
