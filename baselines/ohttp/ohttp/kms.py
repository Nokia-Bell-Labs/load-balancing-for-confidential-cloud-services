# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""OHTTP+KMS baseline -- the KMS role.

Models the confidential, transparent KMS of Azure AI confidential inferencing
(techcommunity.microsoft.com/.../azure-ai-confidential-inferencing-technical-deep-dive):

  * generates and periodically rotates the OHTTP (HPKE) key pair;
  * releases the private key only to gateways that pass attestation, wrapped
    under the gateway's attested key;
  * publishes the current public key configuration together with evidence
    that the key is managed by an attested KMS.

It is built ON the Janus frontend: a ``FrontendServer`` instance provides
the attested TLS identity (the ACME certificate carrying the MAA JWT, sealed
keys) and ``register_backend()`` provides gateway attestation via MAA with
the TPM-quote binding of the gateway's key.  Only the endpoints below are
new; they live in this baseline module rather than in ``janus/frontend`` so
the Janus code path is untouched (same layout as ``baselines/httpa``).

Endpoints
    GET  /keyconfig      current key config + KMS evidence (frontend chain
                         with its JWT) + KMS signature over the config
    POST /release_key    same body as /register_backend; on success returns
                         the epoch private key wrapped to the gateway's CSR key
    POST /rotate         force a rotation (evaluation only; guarded by env)
    GET  /               health

Run inside the SGX enclave via the gramine module ``ohttp_kms`` (see
``baselines/ohttp/gramine``) or in direct mode for local tests:
    python3 -m ohttp.kms --type direct --port 6038
"""
from __future__ import annotations

import base64
import json
import logging
import os
import signal
import sys
import threading
import time
from argparse import ArgumentParser
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, jsonify, request

_HERE = Path(__file__).resolve()
_CODEBASE = _HERE.parents[3]  # .../Janus
if str(_CODEBASE) not in sys.path:
    sys.path.insert(0, str(_CODEBASE))
if str(_HERE.parents[1]) not in sys.path:
    sys.path.insert(0, str(_HERE.parents[1]))

# The KMS releases an HPKE key, not a TLS credential: the reused admission path
# must not sign a Delegated Credential (a Janus-only step) at every key release.
os.environ.setdefault("ISSUE_DC", "0")
from janus.frontend.frontend_server import FrontendServerFactory  # noqa: E402
from ohttp import wire  # noqa: E402

log = logging.getLogger("ohttp-kms")
app = Flask(__name__)

KMS = None          # FrontendServer (attested identity + gateway verification)
KEYS = None         # KeyRing
_KEYCONFIG_CACHE: dict = {}   # the signed key configuration of the current key id (signed once per key)

ROTATION_INTERVAL_S = int(os.environ.get("OHTTP_ROTATION_S", str(24 * 3600)))
RETENTION_S = int(os.environ.get("OHTTP_RETENTION_S", str(24 * 3600)))
ALLOW_ROTATE_API = os.environ.get("OHTTP_ALLOW_ROTATE_API", "0") == "1"


class KeyRing:
    """Epoch key pairs, sealed alongside the frontend's own keys.

    ``current`` is the key clients are told to use; older keys are retained
    for ``retention_s`` so requests sealed just before a rotation still
    decrypt (RFC 9458 s6.4 recommends overlapping validity).
    """

    def __init__(self, sealed_dir: str, signer: ec.EllipticCurvePrivateKey):
        self._path = os.path.join(sealed_dir, "ohttp_kms_keys.json")
        self._signer = signer
        self._lock = threading.Lock()
        self.keys: dict[int, dict] = {}      # key_id -> {pk, sk, created}
        self.current_id: int = -1
        self._load()
        if self.current_id < 0:
            self.rotate()

    def _load(self):
        if not os.path.isfile(self._path):
            return
        with open(self._path) as f:
            data = json.load(f)
        self.keys = {int(k): {"pk": base64.b64decode(v["pk"]),
                              "sk": base64.b64decode(v["sk"]),
                              "created": v["created"]} for k, v in data["keys"].items()}
        self.current_id = data["current"]
        log.info(f"Loaded {len(self.keys)} OHTTP key(s); current key_id={self.current_id}")

    def _save(self):
        data = {"current": self.current_id,
                "keys": {str(k): {"pk": base64.b64encode(v["pk"]).decode(),
                                  "sk": base64.b64encode(v["sk"]).decode(),
                                  "created": v["created"]} for k, v in self.keys.items()}}
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self._path)

    def rotate(self) -> int:
        t0 = time.time()
        pk, sk = wire.generate_keypair()
        with self._lock:
            new_id = (self.current_id + 1) % 256
            self.keys[new_id] = {"pk": pk, "sk": sk, "created": time.time()}
            self.current_id = new_id
            cutoff = time.time() - RETENTION_S
            for k in [k for k, v in self.keys.items() if v["created"] < cutoff and k != new_id]:
                del self.keys[k]
            self._save()
        log.info(f"OHTTP key rotated -> key_id={new_id}  ⏱ {(time.time()-t0)*1000:.2f} ms")
        return new_id

    def config(self) -> wire.KeyConfig:
        with self._lock:
            return wire.KeyConfig(self.current_id, self.keys[self.current_id]["pk"])

    def not_after(self, key_id: int) -> int:
        return int(self.keys[key_id]["created"] + ROTATION_INTERVAL_S + RETENTION_S)

    def private_key(self, key_id: int) -> bytes | None:
        with self._lock:
            k = self.keys.get(key_id)
            if k is None or time.time() > self.not_after(key_id):
                return None                 # unknown, or past its not_after: never released again
            return k["sk"]

    def sign(self, data: bytes) -> bytes:
        return self._signer.sign(data, ec.ECDSA(hashes.SHA256()))


def _rotation_loop():
    while True:
        time.sleep(ROTATION_INTERVAL_S)
        try:
            KEYS.rotate()
        except Exception as exc:  # pragma: no cover
            log.error(f"rotation failed: {exc}")


# ── endpoints ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({"role": "ohttp-kms", "key_id": KEYS.current_id,
                    "rotation_s": ROTATION_INTERVAL_S})


@app.route("/keyconfig", methods=["GET"])
def keyconfig():
    """Public key configuration + evidence that an attested KMS manages it.

    The evidence is the KMS's own TLS certificate chain, which embeds the
    MAA JWT over the KMS enclave (the same object a Janus client verifies on
    the frontend), plus an ECDSA signature by the KMS's TLS key over
    ``key_config || not_after`` so the config is bound to that identity even
    when cached or relayed.
    """
    key_id = KEYS.current_id
    cached = _KEYCONFIG_CACHE.get(key_id)
    if cached is None:
        # Signed once per key: a production KMS publishes a signed configuration,
        # it does not re-read its certificate and re-sign on every fetch.
        cfg = wire.KeyConfig(key_id, KEYS.keys[key_id]["pk"]).encode()
        not_after = KEYS.not_after(key_id)
        signed = cfg + not_after.to_bytes(8, "big")
        cached = {
            "key_config_b64": base64.b64encode(cfg).decode(),
            "key_id": key_id,
            "not_after": not_after,
            "kms_cert_chain_pem": KMS.get_frontend_cert_chain_pem(),
            "kms_sig_b64": base64.b64encode(KEYS.sign(signed)).decode(),
        }
        _KEYCONFIG_CACHE.clear()
        _KEYCONFIG_CACHE[key_id] = cached
    return jsonify(cached)


@app.route("/nonce", methods=["GET"])
def nonce():
    """Challenge nonce for a gateway's attestation (design Step 2).

    The gateway binds SHA256(nonce || its CSR public key) into its TPM quote;
    /release_key verifies that binding.  Registered with the frontend's
    single-use nonce tracking so a bundle cannot be replayed.
    """
    n = os.urandom(32).hex()
    KMS.register_nonce(n, request.args.get("ip", request.remote_addr),
                       request.args.get("cvm_type", "snp"))
    return jsonify({"nonce": n})


@app.route("/release_key", methods=["POST"])
def release_key():
    """Attest the gateway and release the requested epoch's private key.

    Body: as /register_backend (csr_pem, quote_b64, nonce, cvm_type,
    ip_address, port) plus optional ``key_id`` (default: current).  The
    attestation check is exactly the frontend's: MAA verification of the SNP
    bundle and the TPM-quote binding of the CSR public key.  On success the
    private key is HPKE-wrapped to that CSR public key.
    """
    data = request.get_json(force=True)
    try:
        csr_pem = data["csr_pem"].encode()
        quote = base64.b64decode(data.get("quote_b64") or "")
        nonce = data.get("nonce", "")
        cvm_type = data.get("cvm_type", "snp")
        ip = data["ip_address"]
        port = int(data.get("port", 443))
        key_id = int(data.get("key_id", KEYS.current_id))
    except (KeyError, ValueError) as e:
        return jsonify({"success": False, "error": f"Invalid request: {e}"}), 400
    # The gateways are SEV-SNP CVMs. Admit only that evidence type: another type would take the
    # frontend's SGX path, which neither binds the CSR key nor checks PCR 15 and the platform claims.
    if cvm_type != "snp":
        return jsonify({"success": False, "error": "only SEV-SNP gateways are admitted"}), 403

    t0 = time.time()
    result = KMS.register_backend(csr_pem, quote, nonce, cvm_type, ip, port)
    attest_ms = (time.time() - t0) * 1000
    if not result.get("success"):
        return jsonify(result), 403

    sk = KEYS.private_key(key_id)
    if sk is None:
        return jsonify({"success": False, "error": f"unknown key_id {key_id}"}), 404
    gw_pub_pem = x509.load_pem_x509_csr(csr_pem).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    wrapped = wire.wrap_private_key(sk, gw_pub_pem)
    log.info(f"Released key_id={key_id} to {ip}:{port}  attest ⏱ {attest_ms:.2f} ms")
    return jsonify({
        "success": True,
        "key_id": key_id,
        "current_key_id": KEYS.current_id,
        "wrapped_key_b64": base64.b64encode(wrapped).decode(),
        "not_after": KEYS.not_after(key_id),
        "kms_cert_chain_pem": KMS.get_frontend_cert_chain_pem(),
        "attest_ms": round(attest_ms, 3),
    })


@app.route("/rotate", methods=["POST"])
def rotate():
    if not ALLOW_ROTATE_API:
        return jsonify({"error": "rotation API disabled"}), 403
    return jsonify({"key_id": KEYS.rotate()})


# ── entry point ─────────────────────────────────────────────────────────────

def parse_args():
    p = ArgumentParser()
    p.add_argument("-p", "--port", type=int, default=6038)
    p.add_argument("-t", "--type", choices=["direct", "sgx"], default="sgx")
    return p.parse_args()


def _nodelay_before_handshake():
    """TCP_NODELAY on the listening socket, so accepted sockets inherit it BEFORE
    the TLS handshake.  werkzeug's disable_nagle_algorithm applies only in setup(),
    after the handshake, and the KMS certificate carries the AS JWT (~7.5 KB), whose
    last sub-MSS segment Nagle would hold back: a 2-RTT handshake instead of 1.  The
    Janus frontend applies the same patch to itself (frontend_server.py)."""
    import socket as _socket
    from werkzeug.serving import BaseWSGIServer
    _orig = BaseWSGIServer.server_bind

    def _server_bind_nodelay(self):
        self.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        return _orig(self)
    BaseWSGIServer.server_bind = _server_bind_nodelay


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("azure").setLevel(logging.WARNING)
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    args = parse_args()
    global KMS, KEYS
    t0 = time.time()
    KMS = FrontendServerFactory.create(args.type)          # attested identity (ACME + JWT)
    KEYS = KeyRing(KMS._sealed_dir, KMS._server_private_key)
    log.info(f"KMS ready in {args.type} mode  ⏱ {(time.time()-t0)*1000:.0f} ms; "
             f"rotation every {ROTATION_INTERVAL_S}s")
    threading.Thread(target=_rotation_loop, daemon=True).start()
    # Renew the certificate and its MAA JWT before they expire, as the Janus frontend does, and serve
    # from the frontend's reloadable SSLContext so a renewal reaches the running listener.
    # A renewal replaces the chain (new MAA JWT), so it also drops the cached key configuration.
    _reload_ssl_context = KMS._reload_ssl_context

    def _reload_and_refresh() -> None:
        _reload_ssl_context()
        _KEYCONFIG_CACHE.clear()
    KMS._reload_ssl_context = _reload_and_refresh
    KMS.start_renewal_thread()
    # TCP_NODELAY on accepted sockets: without it the development server's
    # TLS responses wait on Nagle/delayed-ACK (measured +10 ms per request
    # on the CVM), which is an artefact of the server, not of the protocol.
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.disable_nagle_algorithm = True
    _nodelay_before_handshake()
    # HTTP/1.1 keep-alive so the front end's pooled connection to the
    # gateway is reused across requests (the dev server defaults to
    # HTTP/1.0 + Connection: close, i.e. a TLS handshake per forward).
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run(host="0.0.0.0", port=args.port, threaded=True, load_dotenv=False,
            ssl_context=KMS.ssl_context())


if __name__ == "__main__":
    main()
