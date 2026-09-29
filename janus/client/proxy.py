# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Janus proxy-mode reference client (paper §4.4, proxy mode).

The frontend terminates client TLS and forwards to a backend over its
TEE-bound channel; the client never sees a backend identity. The client opens
TLS-1.3 to the frontend, validates its attested identity (extract the MAA JWT,
verify its RS256 signature against the cached AS key, check REPORTDATA), then
makes an ordinary HTTP request that the frontend relays.  This measurement client does not apply Check 1 (PKI chain) or
Check 4 (measurement policy).

This module is the protocol only; per-step latencies are recorded into
caller-provided dicts (the measurement scripts package them into their result schema).
HTTP time-to-first-byte is the ``http_ms`` phase.
"""
from __future__ import annotations

import re
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from janus.client import attest
from janus.client._timing import phase

_STATUS_RE = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})")


class ProxyClient:
    def __init__(
        self,
        *,
        frontend_host: str,
        frontend_port: int,
        timeout_s: float,
        maa_issuer: str,
    ):
        self.frontend_host = frontend_host
        self.frontend_port = int(frontend_port)
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

    # PAPER: §4.4 Proxy mode — Checks 2-3 (AS JWT signature with the pinned AS key, REPORTDATA binding), abort on any failure; Check 1 disabled and Check 4 not applied in this measurement client.
    def connect_validate_request(self, jwks_cache, http_template: str,
                                 payload_path: str, *,
                                 timing: dict | None = None,
                                 breakdown: dict | None = None) -> tuple:
        """Run the full proxy-mode pipeline; return (ok, status, jwks_cold).

        Records ``tcp_ms``/``tls_ms``/``attest_ms``/``http_ms`` into ``timing``
        and the attestation sub-phases (``jwks_fetch_ms``/``jwt_sig_ms``/
        ``reportdata_ms``) into ``breakdown`` when given.
        """
        t = timing if timing is not None else {}
        bd = breakdown if breakdown is not None else {}
        ok, status, jwks_cold = True, None, False
        sock = ssock = None
        try:
            with phase(t, "tcp_ms"):
                sock = socket.create_connection(
                    (self.frontend_host, self.frontend_port),
                    timeout=self.timeout_s)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with phase(t, "tls_ms"):
                ssock = self.ctx.wrap_socket(
                    sock, server_hostname=self.frontend_host)

            der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der, default_backend())

            with phase(t, "attest_ms"):
                jwt_token = attest.extract_jwt(cert)
                header, payload, _sig = attest.parse_jwt(jwt_token)
                issuer = payload.get("iss") or self.maa_issuer
                kid = header.get("kid", "")
                jku = header.get("jku") or f"{self.maa_issuer}/certs"
                with phase(bd, "jwks_fetch_ms"):
                    jwks = attest.get_maa_public_key(
                        issuer, kid, jku, jwks_cache, self.timeout_s,
                        trusted_issuer=self.maa_issuer)
                jwks_cold = jwks.cold
                with phase(bd, "jwt_sig_ms"):
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
                        jwks_cold = True
                        attest.verify_jwt_rs256(jwt_token, jwks.public_key)
                attest.verify_jwt_validity(payload)
                with phase(bd, "reportdata_ms"):
                    attest.verify_reportdata_ctls(cert, payload)

            request = _build_http_get(http_template, self.frontend_host,
                                      payload_path)
            with phase(t, "http_ms"):
                ssock.sendall(request)
                first = _recv_first_byte(ssock)
            body = _drain_response(ssock, first, max_bytes=8192)
            status = _parse_status_code(body)
            if status is None or status >= 400:
                ok = False
        finally:
            for s in (ssock, sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        return ok, status, jwks_cold


def _build_http_get(template: str, host: str, path: str) -> bytes:
    body = template.format(host=host, path=path)
    body = body.replace("\r\n", "\n").replace("\n", "\r\n")
    if not body.endswith("\r\n\r\n"):
        body = body.rstrip("\r\n") + "\r\n\r\n"
    return body.encode("ascii")


def _recv_first_byte(sock) -> bytes:
    b = sock.recv(1)
    if not b:
        raise ConnectionError("peer closed before any response byte")
    return b


def _drain_response(sock, first_byte: bytes, max_bytes: int = 65536) -> bytes:
    out = bytearray(first_byte)
    while len(out) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(out)))
        except Exception:
            break
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def _parse_status_code(resp_bytes: bytes) -> int | None:
    m = _STATUS_RE.match(resp_bytes)
    return int(m.group(1)) if m else None
