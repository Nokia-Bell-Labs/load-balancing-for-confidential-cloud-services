# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Tests for the Janus reference client (``janus.client``).

Pure-logic unit tests (route parsing, DC binding check, request formatting) plus
a localhost-TLS integration test for the proxy flow and the redirect control
leg. Attestation is stubbed: ``attest.py`` is unchanged by the protocol refactor,
so these tests exercise the relocated connection orchestration (sockets, TLS,
HTTP, /route, the helper handoff, result wiring).

Run from the repo root:
    python3 -m unittest janus.client.test_client
"""
import datetime
import socket
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from janus.client import redirect as R
from janus.client.proxy import ProxyClient
from janus.client.redirect import RedirectClient


# --------------------------------------------------------------------------- #
# Pure-logic unit tests (no I/O)
# --------------------------------------------------------------------------- #
class TestRouteParsing(unittest.TestCase):
    def test_single(self):
        body = b'{"backend_host":"be.local","backend_port":8443}'
        self.assertEqual(R._parse_route_response(body, False), ("be.local", 8443))

    def test_pool(self):
        body = (b'{"backends":[{"backend_host":"a","backend_port":1},'
                b'{"backend_host":"b","backend_port":2}]}')
        self.assertEqual(R._parse_route_response(body, True), [("a", 1), ("b", 2)])

    def test_503_or_empty(self):
        self.assertIsNone(R._parse_route_response(b"", False))
        self.assertEqual(R._parse_route_response(b"", True), [])

    def test_garbage(self):
        self.assertIsNone(R._parse_route_response(b"not json", False))
        self.assertEqual(R._parse_route_response(b"not json", True), [])


class TestBindingCheck(unittest.TestCase):
    FP = "a" * 64

    def test_ok(self):
        ok, why = RedirectClient.check_binding(
            {"dc": "1", "leaf_sha256": self.FP, "status": "200"}, self.FP)
        self.assertTrue(ok)
        self.assertEqual(why, "")

    def test_no_dc(self):
        ok, why = RedirectClient.check_binding(
            {"dc": "0", "leaf_sha256": self.FP, "status": "200"}, self.FP)
        self.assertFalse(ok)
        self.assertEqual(why, "no_delegated_credential")

    def test_wrong_leaf(self):
        ok, why = RedirectClient.check_binding(
            {"dc": "1", "leaf_sha256": "deadbeef", "status": "200"}, self.FP)
        self.assertFalse(ok)
        self.assertEqual(why, "dc_cert_not_attested_frontend")

    def test_bad_status(self):
        ok, why = RedirectClient.check_binding(
            {"dc": "1", "leaf_sha256": self.FP, "status": "503"}, self.FP)
        self.assertFalse(ok)
        self.assertTrue(why.startswith("http_status="))


class TestHttpRouting(unittest.TestCase):
    def test_format(self):
        raw = R._http_routing("fe.local", "/route?pool=1").decode("ascii")
        self.assertTrue(raw.startswith("GET /route?pool=1 HTTP/1.1\r\n"))
        self.assertIn("Host: fe.local\r\n", raw)
        self.assertIn("Connection: close\r\n", raw)
        self.assertTrue(raw.endswith("\r\n\r\n"))


# --------------------------------------------------------------------------- #
# Localhost-TLS integration test
# --------------------------------------------------------------------------- #
def _self_signed(certfile, keyfile):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


def _http_resp(body: bytes) -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


@contextmanager
def stub_tls_server(responder):
    """A one-shot-per-connection threaded TLS server. ``responder(path)`` returns
    raw HTTP response bytes."""
    tmp = tempfile.mkdtemp()
    cf, kf = tmp + "/c.pem", tmp + "/k.pem"
    _self_signed(cf, kf)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cf, kf)
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    host, port = lsock.getsockname()
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                lsock.settimeout(0.5)
                conn, _ = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                s = sctx.wrap_socket(conn, server_side=True)
                req = s.recv(4096).decode("latin1", "replace")
                path = req.split(" ")[1] if " " in req else "/"
                s.sendall(responder(path))
                s.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        yield host, port
    finally:
        stop.set()
        try:
            lsock.close()
        except Exception:
            pass
        th.join(timeout=2)


_FAKE_JWKS = type("J", (), {"public_key": None, "cold": False})
_ATTEST_STUBS = {
    "extract_jwt": lambda cert: "h.p.s",
    "parse_jwt": lambda tok: ({}, {}, b""),
    "get_maa_public_key": lambda *a, **k: _FAKE_JWKS(),
    "verify_jwt_rs256": lambda *a, **k: None,
    "verify_jwt_validity": lambda *a, **k: None,
    "verify_reportdata_ctls": lambda *a, **k: None,
}


@contextmanager
def _stub_attest():
    with mock.patch.multiple("janus.client.attest", **_ATTEST_STUBS):
        yield


class TestProxyFlow(unittest.TestCase):
    def test_round_trip(self):
        with _stub_attest(), stub_tls_server(lambda p: _http_resp(b"ok")) as (h, p):
            c = ProxyClient(frontend_host=h, frontend_port=p,
                            timeout_s=5, maa_issuer="https://maa")
            timing, bd = {}, {}
            ok, status, cold = c.connect_validate_request(
                object(), "GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n", "/x",
                timing=timing, breakdown=bd)
            self.assertTrue(ok)
            self.assertEqual(status, 200)
            for k in ("tcp_ms", "tls_ms", "attest_ms", "http_ms"):
                self.assertIn(k, timing)


class TestRedirectControlLeg(unittest.TestCase):
    def test_route(self):
        body = b'{"backend_host":"be.local","backend_port":8443}'
        with _stub_attest(), stub_tls_server(lambda p: _http_resp(body)) as (h, p):
            c = RedirectClient(frontend_host=h, frontend_port=p,
                               routing_path="/route", timeout_s=5,
                               maa_issuer="https://maa")
            timing, bd = {}, {}
            fp, routed = c.attest_frontend(object(), timing=timing, breakdown=bd)
            self.assertEqual(routed, ("be.local", 8443))
            self.assertIsInstance(fp, str)
            self.assertEqual(len(fp), 64)  # sha256 hex of the frontend cert
            for k in ("tcp_ms", "tls_ms", "attest_ms"):
                self.assertIn(k, timing)
            for k in ("validate_ms", "route_ms"):
                self.assertIn(k, bd)


class TestRedirectDataLeg(unittest.TestCase):
    def test_data_connect_and_binding(self):
        class FakeHelper:
            def request(self, host, port, path, timeout=30.0):
                return {"tcp_ms": "1.0", "tls_ms": "2.0", "http_ms": "3.0",
                        "dc": "1", "status": "200", "leaf_sha256": "FP"}

        c = RedirectClient(frontend_host="x", frontend_port=1,
                           routing_path="/route", timeout_s=5, maa_issuer="m")
        fields = c.data_connect(FakeHelper(), "be", 8443, "/health", 5)
        self.assertEqual(fields["dc"], "1")
        ok, why = c.check_binding(fields, "FP")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
