#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Tests for the design-fidelity fixes (run: python3 -m janus.tests.test_ae_fixes).

Plain asserts, no pytest dependency.  Everything runs offline in direct/mock
mode; nothing here touches a TEE, MAA, or the network.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from janus.common import dc as dcmod                      # noqa: E402
from janus.client import attest                           # noqa: E402

LOG = logging.getLogger("test")
logging.basicConfig(level=logging.WARNING)


def _selfsigned(key, cn="fe"):
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256(), default_backend()))


def _csr(key, ip="127.0.0.1"):
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .sign(key, hashes.SHA256(), default_backend())
            .public_bytes(serialization.Encoding.PEM))


# ── RFC 9345 DC: sign / parse / verify, and the certificate-binding property ──
def test_dc_roundtrip_and_cert_binding():
    fe_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    be_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cert_a = _selfsigned(fe_key, "a")
    cert_b = _selfsigned(fe_key, "b")          # same key, re-issued certificate
    der_a = cert_a.public_bytes(serialization.Encoding.DER)

    dc = dcmod.sign_dc(der_a, fe_key, be_key.public_key(), 86400)
    parsed = dcmod.verify_dc(dc, cert_a, be_key.public_key())
    assert parsed.valid_seconds == 86400
    assert parsed.dc_cert_verify_alg == dcmod.SIG_ECDSA_P256_SHA256

    # wrong holder key
    other = ec.generate_private_key(ec.SECP256R1(), default_backend())
    try:
        dcmod.verify_dc(dc, cert_a, other.public_key()); assert False
    except ValueError as e:
        assert "not for this holder" in str(e)

    # tampered signature
    bad = bytearray(dc); bad[-1] ^= 0x01
    try:
        dcmod.verify_dc(bytes(bad), cert_a); assert False
    except ValueError:
        pass

    # The property behind design §4.2/§4.3: a DC is bound to the certificate
    # DER, so a re-issued certificate (same key!) voids it.
    try:
        dcmod.verify_dc(dc, cert_b); assert False
    except ValueError:
        pass

    # over the RFC's 7-day cap
    try:
        dcmod.sign_dc(der_a, fe_key, be_key.public_key(), 8 * 86400); assert False
    except ValueError:
        pass
    print("ok  dc roundtrip + certificate binding")


# ── client check 2: AS issuer / JWKS origin pinning ──────────────────────────
def test_check_as_trust():
    good = "https://sharedweu.weu.attest.azure.net"
    attest.check_as_trust(good, good + "/certs", good)
    attest.check_as_trust(good + "/", good + "/certs", good)   # trailing slash ok
    for iss, jku in [("https://evil.example", good + "/certs"),
                     (good, "https://evil.example/certs"),
                     (good, "http://sharedweu.weu.attest.azure.net/certs")]:
        try:
            attest.check_as_trust(iss, jku, good); assert False, (iss, jku)
        except ValueError:
            pass

    # get_maa_public_key rejects before any cache/network access
    class NoCache:
        def get(self, *a): raise AssertionError("cache must not be consulted")
        def put(self, *a): raise AssertionError
    try:
        attest.get_maa_public_key("https://evil.example", "k", "https://evil.example/certs",
                                  NoCache(), trusted_issuer=good); assert False
    except ValueError:
        pass
    print("ok  AS issuer pinning")


# ── JWKS cache: rotation-window TTL and eviction ─────────────────────────────
def test_jwks_cache_ttl():
    from clients._base import JwksCache
    d = tempfile.mkdtemp()
    c = JwksCache(Path(d), "warm")
    c.put("iss", "kid", {"n": "AQ", "e": "AQAB"})
    assert c.get("iss", "kid") == {"n": "AQ", "e": "AQAB"}
    c.max_age_s = 0.0
    time.sleep(0.01)
    assert c.get("iss", "kid") is None            # window lapsed → miss
    c.max_age_s = 3600
    c.put("iss", "kid", {"n": "AQ", "e": "AQAB"})
    c.evict("iss", "kid")
    assert c.get("iss", "kid") is None
    print("ok  JWKS cache TTL + evict")


# ── frontend: nonce policy, fail-closed evidence, pinning data, restart check ─
def test_frontend_admission_policy():
    sealed = tempfile.mkdtemp()
    os.environ["JANUS_SEALED_DIR"] = sealed
    os.environ["ISSUE_DC"] = "1"
    from janus.frontend import frontend_server as fs
    fe = fs.FrontendServer("direct", LOG)      # Pebble absent → self-signed fallback

    be_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    csr = _csr(be_key)
    be_cert_pem = _selfsigned(be_key, "127.0.0.1").public_bytes(serialization.Encoding.PEM).decode()

    r = fe.register_backend(csr, b"", "", "snp", "127.0.0.1", 8443)
    assert not r["success"] and "Missing challenge nonce" in r["error"], r

    r = fe.register_backend(csr, b"", "deadbeef", "snp", "127.0.0.1", 8443)
    assert not r["success"] and r["error"] == "Unknown nonce", r

    fe.register_nonce("old", "127.0.0.1", "snp")
    fe._pending_nonces["old"]["timestamp"] = time.time() - fs.NONCE_TTL_S - 1
    r = fe.register_backend(csr, b"", "old", "snp", "127.0.0.1", 8443)
    assert not r["success"] and r["error"] == "Nonce expired", r

    # valid nonce but empty evidence and mock not enabled → fail closed
    fe.register_nonce("n1", "127.0.0.1", "snp")
    fs.ALLOW_MOCK_ATTESTATION = False
    r = fe.register_backend(csr, b"", "n1", "snp", "127.0.0.1", 8443)
    assert not r["success"] and "Empty attestation evidence" in r["error"], r

    # mock explicitly allowed (direct mode) → admitted, pinning data recorded
    fs.ALLOW_MOCK_ATTESTATION = True
    fe.register_nonce("n2", "127.0.0.1", "snp")
    r = fe.register_backend(csr, b"", "n2", "snp", "127.0.0.1", 8443, be_cert_pem)
    assert r["success"], r
    row = fe._key_store.get_backend(r["cvm_id"])
    assert row["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert len(row["cert_fp"]) == 64
    assert r["dc_b64"], "DC must be issued when ISSUE_DC=1"

    # replay of a consumed nonce
    r = fe.register_backend(csr, b"", "n2", "snp", "127.0.0.1", 8443)
    assert not r["success"] and "already used" in r["error"], r

    # certificate whose key is not the CSR key → rejected
    fe.register_nonce("n3", "127.0.0.1", "snp")
    other_cert = _selfsigned(ec.generate_private_key(ec.SECP256R1(), default_backend()), "x")
    r = fe.register_backend(csr, b"", "n3", "snp", "127.0.0.1", 8443,
                            other_cert.public_bytes(serialization.Encoding.PEM).decode())
    assert not r["success"] and "does not match the CSR key" in r["error"], r

    # upstream hop refuses to run unpinned
    os.environ.pop("JANUS_ALLOW_UNPINNED_UPSTREAM", None)
    try:
        fe.get_backend_session("127.0.0.1", 8443, ""); assert False
    except RuntimeError:
        pass
    assert fe.get_backend_session("127.0.0.1", 8443, row["cert_fp"]) is not None

    # restart check: the helper answers without crashing; with a plain
    # self-signed fallback there is no JWT so it reports "not usable"
    rem = fe._certificate_remaining_s()
    assert isinstance(rem, float)

    # DC issued by the frontend verifies under its certificate with the
    # shared module (frontend.sign_dc and common.dc agree on the format)
    with open(fe._tls_cert_file, "rb") as f:
        fe_cert = x509.load_pem_x509_certificate(f.read())
    pub_pem = be_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    dcmod.verify_dc(fe.sign_dc(pub_pem), fe_cert, be_key.public_key())
    print("ok  frontend admission policy, pinning data, DC format")


# ── backend: fresh key at rest, proxy-hop certificate, renewed-DC validation ─
def test_backend_key_and_renewal():
    home = tempfile.mkdtemp()
    os.environ["APP_HOME"] = home
    from janus.backend import backend_server as bs
    be = bs.BackendServer("https://127.0.0.1:1", "gramine", "direct", LOG)
    be._init_keypair()
    st = os.stat(be._private_key_file)
    assert (st.st_mode & 0o777) == 0o600, oct(st.st_mode)
    first_pub = be._public_key_pem()
    be._init_keypair()                                    # a restart → fresh key
    assert be._public_key_pem() != first_pub

    pem = be._write_self_signed_cert("127.0.0.1")
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == be._public_key_pem()

    # renewed DC: accepted only under the pinned frontend key, for our key
    fe_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    fe_cert1 = _selfsigned(fe_key, "fe1")
    be._frontend_public_key = fe_key.public_key()
    fe_cert2 = _selfsigned(fe_key, "fe2")                 # the renewed certificate
    dc2 = dcmod.sign_dc(fe_cert2.public_bytes(serialization.Encoding.DER),
                        fe_key, be._public_key, 3600)
    be.install_renewed_dc(dc2, fe_cert2.public_bytes(serialization.Encoding.PEM).decode())
    assert open(be._dc_file, "rb").read() == dc2
    # a DC signed under a *different* key's certificate is refused
    rogue = ec.generate_private_key(ec.SECP256R1(), default_backend())
    rc = _selfsigned(rogue, "rogue")
    dcr = dcmod.sign_dc(rc.public_bytes(serialization.Encoding.DER), rogue, be._public_key, 3600)
    try:
        be.install_renewed_dc(dcr, rc.public_bytes(serialization.Encoding.PEM).decode()); assert False
    except ValueError as e:
        assert "pinned frontend key" in str(e)
    # right chain, DC for someone else's key → refused
    dcx = dcmod.sign_dc(fe_cert2.public_bytes(serialization.Encoding.DER), fe_key,
                        rogue.public_key(), 3600)
    try:
        be.install_renewed_dc(dcx, fe_cert2.public_bytes(serialization.Encoding.PEM).decode()); assert False
    except ValueError as e:
        assert "holder" in str(e)
    # every dc_proxy instance is signalled; a pidfile of an exited one is removed
    for name, pid in (("dc_proxy.8443.pid", 424242), ("dc_proxy.8543.pid", 424243), ("dc_proxy.pid", 424244)):
        open(os.path.join(be._sealed_dir, name), "w").write(f"{pid}\n")
    signalled = []
    def fake_kill(pid, sig):
        if pid == 424244:
            raise ProcessLookupError
        signalled.append((pid, sig))
    real_kill = bs.os.kill; bs.os.kill = fake_kill
    try:
        be._notify_dc_proxy()
    finally:
        bs.os.kill = real_kill
    assert sorted(signalled) == [(424242, bs.signal.SIGHUP), (424243, bs.signal.SIGHUP)], signalled
    assert not os.path.exists(os.path.join(be._sealed_dir, "dc_proxy.pid"))
    print("ok  backend fresh key (0600), proxy-hop cert, renewed-DC validation, dc_proxy reload fan-out")


def _cert_with_jwt(key, iss: str, exp_offset_s: int, cn="fe"):
    """Self-signed cert carrying a (mock) AS JWT in the Janus extension."""
    import base64, json
    now = int(time.time())
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = f"{b64({'alg': 'RS256', 'kid': 'k'})}.{b64({'iss': iss, 'iat': now, 'exp': now + exp_offset_s})}.sig"
    n = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(n - dt.timedelta(minutes=1))
            .not_valid_after(n + dt.timedelta(days=30))
            .add_extension(x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1"), token.encode()), critical=False)
            .sign(key, hashes.SHA256(), default_backend()))


# ── frontend restart: unseal-and-skip (design §4.2) ──────────────────────────
def test_frontend_restart_skips_issuance():
    sealed = tempfile.mkdtemp()
    os.environ["JANUS_SEALED_DIR"] = sealed
    from janus.frontend import frontend_server as fs
    fe = fs.FrontendServer("direct", LOG)
    # Replace the plain fallback cert with one carrying an unexpired JWT,
    # issued for the *sealed* key, as a real (or Pebble-issued) cert would be.
    good = _cert_with_jwt(fe._server_private_key, "mock", 6 * 3600)
    with open(fe._tls_cert_file, "wb") as f:
        f.write(good.public_bytes(serialization.Encoding.PEM))
    assert fe._certificate_remaining_s() > fs.RENEW_MARGIN_S
    assert fe._sealed_certificate_valid()
    before = open(fe._tls_cert_file, "rb").read()

    fe2 = fs.FrontendServer("direct", LOG)      # "restart": same sealed dir
    after = open(fe2._tls_cert_file, "rb").read()
    assert after == before, "restart must unseal, not re-issue"
    assert fe2._server_public_key_pem() == fe._server_public_key_pem()

    # JWT expired (or inside the renewal margin) → not usable → re-issued
    stale = _cert_with_jwt(fe._server_private_key, "mock", 60)
    with open(fe._tls_cert_file, "wb") as f:
        f.write(stale.public_bytes(serialization.Encoding.PEM))
    assert not fe._sealed_certificate_valid()
    fe3 = fs.FrontendServer("direct", LOG)
    assert open(fe3._tls_cert_file, "rb").read() != stale.public_bytes(serialization.Encoding.PEM)

    # An enclave requires the real AS issuer: a mock-JWT cert never counts.
    with open(fe._tls_cert_file, "wb") as f:
        f.write(good.public_bytes(serialization.Encoding.PEM))
    assert fe._sealed_certificate_valid(require_issuer="")            # direct: fine
    assert not fe._sealed_certificate_valid(require_issuer=fs.ATTESTATION_URL)

    # A cert for a *different* key is never usable (sealed key mismatch)
    other = _cert_with_jwt(ec.generate_private_key(ec.SECP256R1(), default_backend()), "mock", 6 * 3600)
    with open(fe._tls_cert_file, "wb") as f:
        f.write(other.public_bytes(serialization.Encoding.PEM))
    assert fe._certificate_remaining_s() < 0
    print("ok  frontend restart unseals and skips; expired / foreign / mock-in-enclave re-issue")


# ── frontend renewal: re-sign every in-service DC and push it (design §4.3) ─
def test_frontend_resign_and_push():
    sealed = tempfile.mkdtemp()
    os.environ["JANUS_SEALED_DIR"] = sealed
    os.environ["ISSUE_DC"] = "1"
    from janus.frontend import frontend_server as fs
    fe = fs.FrontendServer("direct", LOG)
    be_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_pem = be_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fe._key_store.add_backend("cvm1", "10.0.0.9", 8443, public_key_pem=pub_pem, cert_fp="ab" * 32)
    fe._key_store.set_cvm_mode("cvm1", "in-service")
    fe._key_store.add_backend("cvm2", "10.0.0.10", 8443)           # legacy row: no key
    fe._key_store.set_cvm_mode("cvm2", "in-service")

    posts = []
    class FakeResp:
        status_code = 200; text = "ok"
    class FakeSess:
        def post(self, url, json=None, timeout=None, **kw):
            posts.append((url, json)); return FakeResp()
    fe.get_backend_session = lambda ip, port, fp="": FakeSess()

    # simulate a renewal: new certificate under the same key, then re-sign
    fe._reissue_certificate()
    fe._resign_and_push_dcs()
    assert len(posts) == 1 and posts[0][0] == "https://10.0.0.9:8443/renew_dc", posts
    import base64
    with open(fe._tls_cert_file, "rb") as f:
        cur = x509.load_pem_x509_certificate(f.read())
    dcmod.verify_dc(base64.b64decode(posts[0][1]["dc_b64"]), cur, be_key.public_key())
    assert posts[0][1]["frontend_cert_chain_pem"].startswith("-----BEGIN CERTIFICATE-----")

    # the reloadable server context accepts a renewed chain
    ctx = fe.ssl_context()
    fe._reload_ssl_context()
    assert fe.ssl_context() is ctx
    print("ok  renewal re-signs in-service DCs under the new cert and pushes them")


def test_as_key_lookup_positive_path():
    """get_maa_public_key returns a usable key on a cache hit and on a fetch (the
    functions every client and bench call before verifying an AS JWT)."""
    from janus.client import attest
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    nums = priv.public_key().public_numbers()
    import base64
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    jwk = {"kty": "RSA", "kid": "k1", "n": b64(nums.n), "e": b64(nums.e)}

    class Cache:
        def __init__(self, hit): self.hit = hit; self.stored = None
        def get(self, issuer, kid): return {"n": jwk["n"], "e": jwk["e"]} if self.hit else None
        def put(self, issuer, kid, entry): self.stored = (issuer, kid, entry)

    r = attest.get_maa_public_key("https://as.example", "k1", "https://as.example/certs", Cache(True))
    assert r.public_key.public_numbers() == nums and r.cold is False and r.fetch_ms == 0.0

    class Resp:
        def raise_for_status(self): pass
        def json(self): return {"keys": [jwk]}
    real_get = attest.requests.get; attest.requests.get = lambda *a, **k: Resp()
    try:
        c = Cache(False)
        r = attest.get_maa_public_key("https://as.example", "k1", "https://as.example/certs", c)
        assert r.public_key.public_numbers() == nums and r.cold is True and c.stored[1] == "k1"
    finally:
        attest.requests.get = real_get
    print("ok  AS key lookup returns the key on cache hit and on fetch")


if __name__ == "__main__":
    test_dc_roundtrip_and_cert_binding()
    test_check_as_trust()
    test_jwks_cache_ttl()
    test_as_key_lookup_positive_path()
    test_frontend_admission_policy()
    test_backend_key_and_renewal()
    test_frontend_restart_skips_issuance()
    test_frontend_resign_and_push()
    print("ALL OK")
