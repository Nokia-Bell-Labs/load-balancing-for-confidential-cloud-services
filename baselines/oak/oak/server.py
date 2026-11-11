# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Oak baseline -- attested-session server (backend side).

Proof-of-concept of Project Oak's attested session (github.com/project-oak/oak,
``oak_session``), in the style of ``baselines/httpa``: a Noise NN session
nested inside plain, untrusted outer TLS, with the server binding the
session to per-connection attestation evidence by signing the Noise
handshake hash with an evidence-bound key.  This is the protocol shape Oak
documents ("e; e, ee, sign(h)"; FOSDEM'25 "Attested Noise Protocol") and the
one its transparent proxy (``oak_proxy``) ships, which re-attests on every
connection.

Per connection, inside the outer TLS:
    1. ATTESTATION  client -> "ATTEST"; server -> evidence:
         binding public key (P-256), SNP evidence bundle whose TPM-quote
         qualifyingData binds that key (janus.common.snp_attestation,
         the same binding a Janus backend uses), and the MAA JWT the server
         obtained for that bundle (server-side attestation-service call, as
         oak_proxy does via the Confidential Space launcher).
    2. HANDSHAKE    Noise_NN_25519_ChaChaPoly_SHA256 (2 messages); the
         server's message carries sign(handshake_hash) under the binding key.
    3. OPEN         application bytes as Noise-encrypted records
         [4-byte len | ct], relayed to the unmodified app on loopback.

Fresh binding key + fresh evidence + fresh MAA token per connection, i.e.
the same fresh-per-connection policy under which RA+TLS and HTTPA/2 run.
Cryptography: the Noise library uses the ``cryptography`` package, the same
engine behind Python's TLS, so per-operation cost matches the other rows.

Env: OAK_MOCK_ATTEST=1 -> stub evidence (no TEE, for local tests);
     OAK_TARGET       -> app address, default 127.0.0.1:8080.
Usage: python3 -m oak.server --port 8543 --cert cert.pem --key key.pem
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from noise.connection import NoiseConnection

_HERE = Path(__file__).resolve()
_CODEBASE = _HERE.parents[3]
for p in (str(_CODEBASE), str(_HERE.parents[1])):
    if p not in sys.path:
        sys.path.insert(0, p)

from oak import wire  # noqa: E402

log = logging.getLogger("oak-server")
MOCK_ATTEST = os.environ.get("OAK_MOCK_ATTEST") == "1"
MAA_URL = os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net")
TARGET = os.environ.get("OAK_TARGET", "127.0.0.1:8080")
_VCEK_CACHE: dict = {"pem": None}
# Connections are served concurrently (as the RA+TLS / HTTPA/2 baseline
# servers do); the vTPM serialises the quotes itself.  OAK_SERIAL_EVIDENCE=1
# additionally serialises the whole evidence build (measured: lower throughput
# on a 2-vCPU CVM, since the non-TPM parts then cannot overlap).
_EVIDENCE_LOCK = threading.Lock() if os.environ.get("OAK_SERIAL_EVIDENCE") == "1" else contextlib.nullcontext()


def build_evidence(client_nonce: bytes) -> tuple[dict, ec.EllipticCurvePrivateKey, dict]:
    """Fresh binding key + evidence bound to it + MAA JWT.  Returns
    (evidence message, binding private key, timing dict)."""
    t: dict = {}
    t0 = time.perf_counter()
    binding_key = ec.generate_private_key(ec.SECP256R1())
    pub_der = binding_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    t["keygen_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    if MOCK_ATTEST:
        bundle, jwt = wire.mock_bundle(pub_der, client_nonce), "mock.jwt"
        t["quote_ms"] = (time.perf_counter() - t0) * 1000
        t["maa_ms"] = 0.0
    else:
        from janus.common.snp_attestation import (build_snp_evidence_bundle,
                                                  parse_snp_evidence_bundle,
                                                  submit_to_maa, _split_hcl)
        # The client's nonce forces the fresh quote (as the RA+TLS and HTTPA/2
        # clients force theirs); the quote carries SHA256(nonce || binding key),
        # which the client recomputes.
        bundle = build_snp_evidence_bundle(nonce=client_nonce,
                                           pubkey_spki_der=pub_der,
                                           vcek_chain_cache=_VCEK_CACHE["pem"])
        ev = parse_snp_evidence_bundle(bundle)
        if _VCEK_CACHE["pem"] is None:
            _VCEK_CACHE["pem"] = ev.pem_chain
        t["quote_ms"] = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        snp_report, runtime_claims = _split_hcl(ev.hcl_report)
        jwt = submit_to_maa(snp_report, ev.pem_chain, runtime_claims, maa_url=MAA_URL)
        t["maa_ms"] = (time.perf_counter() - t0) * 1000
    # The VCEK chain went to the attestation service; the client verifies the
    # AS token and the quote and never reads the chain, so it stays off the wire
    # (with it, the reply exceeded the initial congestion window: +1 RTT).
    msg = {"binding_pub_der_b64": base64.b64encode(pub_der).decode(),
           "bundle_b64": base64.b64encode(wire.strip_chain(bundle)).decode(),
           "jwt": jwt,
           "server_ms": {k: round(v, 3) for k, v in t.items()}}
    return msg, binding_key, t


def _close_session(conn, app, upstream_thread):
    """Unblock both directions and join the reader before releasing descriptors.

    Closing the TLS socket while the upstream thread is inside SSL_read can
    let that operation outlive the descriptor. A subsequent application socket
    can reuse its number and receive the old TLS connection's close-notify.
    Keep both descriptors alive until no relay thread can use either one.
    """
    for sock in (conn, app):
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except (OSError, ValueError):
                pass
    if upstream_thread is not None and upstream_thread.ident is not None:
        upstream_thread.join()
    for sock in (app, conn):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def handle(conn: ssl.SSLSocket, peer):
    app = None
    th = None
    try:
        conn.do_handshake()          # outer TLS, in this thread (never in the accept loop)
        # 1. ATTESTATION: "ATTEST" || 32-byte client nonce
        req = wire.recv_frame(conn)
        if len(req) != 6 + wire.NONCE_LEN or req[:6] != b"ATTEST":
            return
        with _EVIDENCE_LOCK:
            msg, binding_key, t = build_evidence(req[6:])
        wire.send_frame(conn, json.dumps(msg).encode())
        # 2. HANDSHAKE (Noise NN, responder)
        noise = NoiseConnection.from_name(wire.NOISE_PROTOCOL)
        noise.set_as_responder()
        noise.start_handshake()
        noise.read_message(wire.recv_frame(conn))
        m2 = noise.write_message()
        sig = binding_key.sign(noise.get_handshake_hash(), ec.ECDSA(hashes.SHA256()))
        wire.send_frame(conn, struct.pack(">H", len(m2)) + m2 + sig)
        assert noise.handshake_finished
        # 3. OPEN: relay to the app
        host, port = TARGET.rsplit(":", 1)
        app = socket.create_connection((host, int(port)))
        app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def upstream():
            try:
                while True:
                    ct = wire.recv_frame(conn)
                    if not ct:
                        break
                    app.sendall(noise.decrypt(ct))
            except Exception:
                pass
            finally:
                try:
                    app.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        th = threading.Thread(target=upstream, daemon=True)
        th.start()
        while True:
            data = app.recv(16384)
            if not data:
                break
            wire.send_frame(conn, noise.encrypt(data))
        wire.send_frame(conn, b"")
        log.info(f"{peer} served; keygen {t['keygen_ms']:.1f} quote {t['quote_ms']:.1f} "
                 f"maa {t['maa_ms']:.1f} ms")
    except Exception as exc:
        log.warning(f"{peer}: {exc}")
    finally:
        _close_session(conn, app, th)


def _ensure_selfsigned(cert: str, key: str):
    if os.path.isfile(cert) and os.path.isfile(key):
        return
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-keyout", key, "-out", cert, "-days", "30",
                    "-nodes", "-subj", "/CN=oak-server"], check=True, capture_output=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8543)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--cert", default="oak-cert.pem")
    p.add_argument("--key", default="oak-key.pem")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    _ensure_selfsigned(a.cert, a.key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(a.cert, a.key)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ls.bind((a.bind, a.port))
    ls.listen(128)
    log.info(f"Oak attested-session server on {a.bind}:{a.port} -> {TARGET} "
             f"(mock={MOCK_ATTEST}, fresh evidence per connection)")
    while True:
        c, peer = ls.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sc = ctx.wrap_socket(c, server_side=True, do_handshake_on_connect=False)
        except ssl.SSLError as exc:
            log.warning(f"TLS from {peer}: {exc}")
            c.close()
            continue
        threading.Thread(target=handle, args=(sc, peer), daemon=True).start()


if __name__ == "__main__":
    main()
