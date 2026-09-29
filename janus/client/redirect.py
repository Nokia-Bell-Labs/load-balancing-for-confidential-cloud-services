# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Janus redirection-mode reference client (paper §4.4, redirection mode).

Two-connection flow:

  Control connection (to the frontend):
    TCP + TLS-1.3, then the client validates the frontend's attested identity:
      (i)   PKI path validation of the frontend chain -- NOT done by this
            measurement client (it connects by IP to a certificate from the
            testbed's Pebble CA).  Firefox and
            nss_dc_helper validate the chain natively.
      (ii)  extract the MAA JWT, verify its RS256 signature with the cached,
            issuer-pinned AS key (attest.check_as_trust / get_maa_public_key)
      (iii) REPORTDATA == SHA-256(frontend public key)
      (iv)  measurement policy (MRENCLAVE/MRSIGNER/SVN) -- not applied here
            (the browser extension has an optional one)
    and obtains a backend address from ``GET /route``.

  Data connection (to a backend):
    TCP + TLS-1.3 where the backend's Certificate message carries the frontend's
    chain plus an RFC 9345 Delegated Credential. Step (v): the DC signature is
    verified against the frontend cert and the server's CertificateVerify is
    checked with the DC key — performed *in-band* by NSS via ``nss_dc_helper``
    (``native/``); Python ssl / BoringSSL clients cannot do this.

Binding: the data-connection leaf certificate (the DC's delegating cert) must be
byte-for-byte the attested frontend cert from the control connection — otherwise
a host adversary could pair a valid attestation with an unrelated DC.

This module is the protocol only. The DC handshake is performed by a helper
object passed to ``data_connect`` (duck-typed: ``request(host, port, path,
timeout) -> dict``); the measurement scripts supply a pooled ``nss_dc_helper`` and
times the steps. Per-step latencies are recorded into caller-provided dicts.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from janus.client import attest
from janus.client._timing import phase


class RedirectClient:
    def __init__(
        self,
        *,
        frontend_host: str,
        frontend_port: int,
        routing_path: str,
        timeout_s: float,
        maa_issuer: str,
    ):
        self.frontend_host = frontend_host
        self.frontend_port = int(frontend_port)
        self.routing_path = routing_path
        self.timeout_s = float(timeout_s)
        self.maa_issuer = maa_issuer

        # PAPER: §4.4 Check 1 — disabled in this measurement client: it connects by
        # IP to a certificate issued by the testbed's Pebble CA, so chain and
        # hostname validation are off. Firefox and
        # nss_dc_helper perform Check 1 natively.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx = ctx

    # PAPER: §4.4 Redirection mode — the same 4 checks on the frontend, then /route for the backend address.
    def attest_frontend(self, jwks_cache, *, want_pool: bool = False,
                        timing: dict | None = None,
                        breakdown: dict | None = None) -> tuple:
        """Control connection: steps (i)-(iv); return (frontend cert fp, routed).

        ``routed`` is the backend the frontend steers this client to: a single
        ``(host, port)`` from ``GET /route``, or a list of them from
        ``GET /route?pool=1`` when ``want_pool`` is set.

        If ``timing`` is given, per-phase times are accumulated into it
        (``tcp_ms``/``tls_ms``/``attest_ms``, and ``_jwks_cold``). The
        ``attest_ms`` phase is additionally split, when ``breakdown`` is given,
        into ``validate_ms`` (client-side crypto, steps i-iv) and ``route_ms``
        (the one routing round trip), kept separate so the latency breakdown
        attributes the control-plane routing cost honestly rather than as
        validation.
        """
        fe_sock = fe_ssock = None
        t = timing if timing is not None else {}
        bd = breakdown if breakdown is not None else {}
        routed = None
        try:
            with phase(t, "tcp_ms"):
                fe_sock = socket.create_connection(
                    (self.frontend_host, self.frontend_port),
                    timeout=self.timeout_s)
                fe_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with phase(t, "tls_ms"):
                fe_ssock = self.ctx.wrap_socket(
                    fe_sock, server_hostname=self.frontend_host)
            fe_der = fe_ssock.getpeercert(binary_form=True)
            fe_cert = x509.load_der_x509_certificate(fe_der, default_backend())
            fp = hashlib.sha256(fe_der).hexdigest()
            with phase(t, "attest_ms"):
                # Steps (i)-(iv): client-side crypto validation only.
                with phase(bd, "validate_ms"):
                    jwt_token = attest.extract_jwt(fe_cert)
                    header, payload, _sig = attest.parse_jwt(jwt_token)
                    issuer = payload.get("iss") or self.maa_issuer
                    kid = header.get("kid", "")
                    jku = header.get("jku") or f"{self.maa_issuer}/certs"
                    jwks = attest.get_maa_public_key(
                        issuer, kid, jku, jwks_cache, self.timeout_s,
                        trusted_issuer=self.maa_issuer)
                    try:
                        attest.verify_jwt_rs256(jwt_token, jwks.public_key)
                    except Exception:
                        if jwks.cold:
                            raise
                        # Design §4.4: a failed check against a *cached* AS
                        # key triggers a passive key refresh, then one retry.
                        jwks = attest.get_maa_public_key(
                            issuer, kid, jku, jwks_cache, self.timeout_s,
                            trusted_issuer=self.maa_issuer, force_refresh=True)
                        attest.verify_jwt_rs256(jwt_token, jwks.public_key)
                    if timing is not None:
                        timing["_jwks_cold"] = jwks.cold
                    attest.verify_jwt_validity(payload)
                    attest.verify_reportdata_ctls(fe_cert, payload)
                # Control-plane routing: one round trip to the frontend, which
                # returns the backend(s) to connect to (select_backend()).
                # Handled off the data path and amortized in steady state --
                # NOT client-side validation.
                with phase(bd, "route_ms"):
                    path = "/route?pool=1" if want_pool else self.routing_path
                    fe_ssock.sendall(_http_routing(self.frontend_host, path))
                    routed = _parse_route_response(
                        _recv_http_body(fe_ssock), want_pool)
            return fp, routed
        finally:
            for s in (fe_ssock, fe_sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

    def data_connect(self, helper, host: str, port: int, path: str,
                     timeout: float) -> dict:
        """Step (v): open the data connection to the backend and validate the
        RFC 9345 DC in-band via ``helper`` (the NSS handshaker). Returns the
        helper's field dict (tcp_ms/tls_ms/http_ms/dc/status/leaf_sha256)."""
        return helper.request(host, port, path, timeout=timeout)

    @staticmethod
    # PAPER: §4.4 Redirection mode — the backend's DC must be delegated from the attested frontend certificate (NSS verifies the DC in-band).
    def check_binding(fields: dict, frontend_fp: str) -> tuple[bool, str]:
        """Verify the data connection authenticated with a DC whose delegating
        leaf is the attested frontend cert, and that the request succeeded.
        Returns (ok, reason)."""
        dc_used = int(fields.get("dc", "0"))
        leaf_fp = fields.get("leaf_sha256", "na")
        status = int(fields.get("status", "0"))
        if dc_used != 1:
            return False, "no_delegated_credential"
        if leaf_fp != frontend_fp:
            return False, "dc_cert_not_attested_frontend"
        if status == 0 or status >= 400:
            return False, f"http_status={status}"
        return True, ""


def _http_routing(host: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: janus-client/1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    ).encode("ascii")


def _recv_http_body(ssock) -> bytes:
    """Read a full HTTP/1.1 response (server sends Connection: close) and return
    the body bytes."""
    chunks = []
    while True:
        try:
            d = ssock.recv(4096)
        except Exception:
            break
        if not d:
            break
        chunks.append(d)
    raw = b"".join(chunks)
    i = raw.find(b"\r\n\r\n")
    return raw[i + 4:] if i >= 0 else b""


def _parse_route_response(body: bytes, want_pool: bool):
    """Parse the frontend's /route reply. Returns a (host, port) tuple for a
    single pick, or a list of them for ?pool=1. Returns None / [] on a 503 or
    unparseable body so the caller can fall back to configured backends."""
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return [] if want_pool else None
    if want_pool:
        return [(b["backend_host"], int(b["backend_port"]))
                for b in obj.get("backends", [])]
    if "backend_host" in obj:
        return (obj["backend_host"], int(obj["backend_port"]))
    return None
