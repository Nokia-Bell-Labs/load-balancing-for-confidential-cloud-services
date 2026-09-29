# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Attestation checks used by the Janus clients and the measurement scripts
(paper §4.4, Checks 2-3), and by the RA+TLS / HTTPA/2 measurement clients.

Pure functions where possible; the JWKS fetch is the one I/O helper and
respects the :class:`JwksCache` policy that the caller passes in.

The Janus frontend writes ``REPORTDATA = SHA-256(PEM SubjectPublicKeyInfo of
its TLS key)`` (paper §4.2 Step 2); the AS-signed JWT is carried in the
certificate extension OID 1.3.6.1.4.1.99999.3.1.  (Backends bind
``SHA-256(nonce || SPKI DER)`` instead; see janus/common/snp_attestation.py.)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# OIDs assigned by the Janus frontend (SGX_JWT_OID in janus/frontend/frontend_server.py).
SGX_JWT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1")


def b64url_decode(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_jwt(token: str) -> tuple[dict, dict, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    return (
        json.loads(b64url_decode(parts[0])),
        json.loads(b64url_decode(parts[1])),
        b64url_decode(parts[2]),
    )


def extract_cert_ext(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bytes:
    for ext in cert.extensions:
        if ext.oid == oid:
            return ext.value.value
    raise ValueError(f"certificate missing extension {oid.dotted_string}")


def extract_jwt(cert: x509.Certificate) -> str:
    return extract_cert_ext(cert, SGX_JWT_OID).decode("utf-8")


def check_as_trust(issuer: str, jku: str, trusted_issuer: str) -> None:
    """Design §4.4, check 2: the JWT must come from the *configured* AS.

    A token names its own issuer (``iss``) and key-set URL (``jku``); a
    signature that verifies under a key fetched from an attacker-chosen
    ``jku`` proves nothing.  So both must match the AS the client was
    configured with: ``iss`` equal to it (modulo a trailing slash) and
    ``jku`` an https URL on the same host.  Raises ValueError otherwise.
    """
    from urllib.parse import urlparse
    want = urlparse(trusted_issuer.rstrip("/"))
    got_iss = (issuer or "").rstrip("/")
    if got_iss != trusted_issuer.rstrip("/"):
        raise ValueError(f"untrusted AS issuer {issuer!r} (configured {trusted_issuer!r})")
    j = urlparse(jku or "")
    if j.scheme != "https" or j.netloc.lower() != want.netloc.lower():
        raise ValueError(f"JWKS URL {jku!r} is not on the configured AS {trusted_issuer!r}")


@dataclass
class JwksResult:
    public_key: Any
    cold: bool
    fetch_ms: float


def get_maa_public_key(
    issuer: str,
    kid: str,
    jku: str,
    jwks_cache,
    timeout_s: float = 10.0,
    trusted_issuer: str | None = None,
    force_refresh: bool = False,
) -> JwksResult:
    """Return the RSA public key for ``(issuer, kid)``.

    On cache hit, no network I/O happens and ``cold`` is False.  On miss
    we fetch ``jku``, parse the JWK with the requested ``kid``, store
    only ``(n, e)`` (the entire ``x5c`` envelope is intentionally not
    cached — Azure MAA re-issues that envelope frequently without
    rotating the underlying key, and caching it would force spurious
    invalidations).  See evaluation §AS key stability.

    ``trusted_issuer`` pins the AS (see ``check_as_trust``); the Janus
    clients always pass it.  ``force_refresh`` bypasses the cache — the
    passive refresh the design describes when a JWT check fails with a
    cached key (design §4.4, "Caching AS Signing Key").
    """
    if trusted_issuer:
        check_as_trust(issuer, jku, trusted_issuer)
    entry = None if force_refresh else jwks_cache.get(issuer, kid)
    if entry is not None:
        n_int = int.from_bytes(b64url_decode(entry["n"]), "big")
        e_int = int.from_bytes(b64url_decode(entry["e"]), "big")
        pub = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
        return JwksResult(public_key=pub, cold=False, fetch_ms=0.0)

    t0 = time.perf_counter()
    resp = requests.get(jku, timeout=timeout_s, verify=True)
    resp.raise_for_status()
    body = resp.json()
    fetch_ms = (time.perf_counter() - t0) * 1000.0

    keys = {
        k["kid"]: k
        for k in body.get("keys", [])
        if k.get("kty") == "RSA" and "kid" in k
    }
    if kid not in keys:
        raise ValueError(f"kid {kid!r} not present in JWKS at {jku}")

    k = keys[kid]
    n_int = int.from_bytes(b64url_decode(k["n"]), "big")
    e_int = int.from_bytes(b64url_decode(k["e"]), "big")
    pub = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
    jwks_cache.put(issuer, kid, {"n": k["n"], "e": k["e"]})
    return JwksResult(public_key=pub, cold=True, fetch_ms=fetch_ms)


def verify_jwt_rs256(token: str, public_key) -> None:
    """Raise on signature mismatch.  Mirrors RFC 7518 RS256."""
    parts = token.split(".")
    msg = (parts[0] + "." + parts[1]).encode()
    sig = b64url_decode(parts[2])
    public_key.verify(sig, msg, padding.PKCS1v15(), crypto_hashes.SHA256())


def verify_jwt_validity(payload: dict, now: float | None = None) -> None:
    now = now or time.time()
    nbf = payload.get("nbf", 0)
    exp = payload.get("exp", 0)
    if exp and now > exp:
        raise ValueError(f"JWT expired (exp={exp}, now={now:.0f})")
    if nbf and now < nbf:
        raise ValueError(f"JWT not yet valid (nbf={nbf}, now={now:.0f})")


def verify_reportdata_ctls(
    server_cert: x509.Certificate,
    payload: dict,
) -> None:
    """Check that the JWT's REPORTDATA claim binds the TLS public key.

    The Janus frontend writes ``REPORTDATA = SHA256(pk_srv_pem)``
    where pk_srv_pem is the SubjectPublicKeyInfo PEM of the leaf cert's
    public key.  Azure MAA carries the original runtime data (the PEM
    bytes themselves) in ``x-ms-sgx-ehd`` and the 32-byte hash in
    ``x-ms-sgx-report-data``.

    We accept either form:
      * ``x-ms-sgx-ehd`` is the PEM (>32 bytes): hash it and compare.
      * ``x-ms-sgx-ehd`` is the 32-byte hash itself (mock path).
    The bare ``x-ms-sgx-report-data`` claim is a third equivalent check.
    """
    pk_srv = server_cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = hashlib.sha256(pk_srv).digest()

    ehd_b64 = payload.get("x-ms-sgx-ehd", "")
    if not ehd_b64:
        raise ValueError("JWT missing x-ms-sgx-ehd")
    ehd = b64url_decode(ehd_b64)

    if len(ehd) > 32:
        if hashlib.sha256(ehd).digest() != expected:
            raise ValueError("REPORTDATA mismatch (runtime-data path)")
    else:
        if ehd[:32] != expected[:32]:
            raise ValueError("REPORTDATA mismatch (hash path)")
