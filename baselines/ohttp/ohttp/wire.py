# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Oblivious HTTP (RFC 9458) primitives for the OHTTP+KMS baseline.

This is the proof-of-concept wire layer shared by the KMS role in the
frontend, the gateway (``ohttp/gateway.py``) and the client
(``ohttp/client.py``).  It follows RFC 9458 for everything that affects
cost -- the key configuration, request encapsulation with a fresh HPKE
context per request (RFC 9458 s6.1), the response key schedule (s4.4), and the
``enc``-window replay check (s6.5) -- and simplifies only the inner HTTP
message encoding, where RFC 9292 binary HTTP is replaced by a compact
length-prefixed encoding (see ``encode_inner_request``).  That encoding is a
serialization detail with no cryptographic or round-trip consequence.

Cipher suite: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, a standard
RFC 9180 suite (RFC 9458 does not mandate one; its Appendix A example uses X25519).  The HPKE implementation is
``pyhpke``, which is backed by the same ``cryptography`` package the rest of
Janus (and the HTTPA/2 baseline's inner channel) uses.
"""
from __future__ import annotations

import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterator, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

# RFC 9180 identifiers for the suite above.
KEM_ID = 0x0010   # DHKEM(P-256, HKDF-SHA256)
KDF_ID = 0x0001   # HKDF-SHA256
AEAD_ID = 0x0001  # AES-128-GCM
AEAD_KEY_LEN = 16
AEAD_NONCE_LEN = 12

SUITE = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256,
                        AEADId.AES128_GCM)

REQUEST_INFO_LABEL = b"message/bhttp request"    # RFC 9458 s4.3
RESPONSE_EXPORT_LABEL = b"message/bhttp response"  # RFC 9458 s4.4

# Media types (RFC 9458 s10 / chunked-OHTTP draft).
MT_REQUEST = "message/ohttp-req"
MT_RESPONSE = "message/ohttp-res"
MT_CHUNKED_RESPONSE = "message/ohttp-chunked-res"


# ── key configuration (RFC 9458 s3) ─────────────────────────────────────────

@dataclass
class KeyConfig:
    key_id: int
    public_key: bytes  # uncompressed SEC1 point for P-256 (65 bytes)

    def encode(self) -> bytes:
        """RFC 9458 s3: key_id(1) kem_id(2) pk(Npk) cipher_suites<...>."""
        suites = struct.pack(">HH", KDF_ID, AEAD_ID)
        return (struct.pack(">BH", self.key_id, KEM_ID) + self.public_key
                + struct.pack(">H", len(suites)) + suites)

    @classmethod
    def decode(cls, data: bytes) -> "KeyConfig":
        key_id, kem_id = struct.unpack(">BH", data[:3])
        if kem_id != KEM_ID:
            raise ValueError(f"unsupported KEM 0x{kem_id:04x}")
        pk = data[3:3 + 65]
        (suites_len,) = struct.unpack(">H", data[68:70])
        suites = data[70:70 + suites_len]
        if struct.pack(">HH", KDF_ID, AEAD_ID) not in [suites[i:i + 4]
                                                      for i in range(0, len(suites), 4)]:
            raise ValueError("required cipher suite not offered")
        return cls(key_id=key_id, public_key=pk)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key_bytes, private_key_bytes) for a fresh P-256 KEM key."""
    kp = SUITE.kem.derive_key_pair(os.urandom(32))
    return kp.public_key.to_public_bytes(), kp.private_key.to_private_bytes()


def load_public_key(pk_bytes: bytes):
    return SUITE.kem.deserialize_public_key(pk_bytes)


def load_private_key(sk_bytes: bytes):
    return SUITE.kem.deserialize_private_key(sk_bytes)


# ── inner HTTP message encoding (simplified stand-in for RFC 9292 BHTTP) ────

def encode_inner_request(method: str, path: str, headers: dict[str, str],
                         body: bytes) -> bytes:
    """Compact length-prefixed encoding of (method, path, headers, body).

    RFC 9458 carries an RFC 9292 binary HTTP message here; we use a simpler
    encoding with identical information content.  A ``Date`` header is added
    if absent, which the gateway uses for its replay window (RFC 9458 s6.5).
    """
    hdrs = dict(headers)
    hdrs.setdefault("date", time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()))
    out = bytearray()
    for part in (method.encode(), path.encode()):
        out += struct.pack(">H", len(part)) + part
    out += struct.pack(">H", len(hdrs))
    for k, v in hdrs.items():
        kb, vb = k.lower().encode(), v.encode()
        out += struct.pack(">H", len(kb)) + kb + struct.pack(">I", len(vb)) + vb
    out += struct.pack(">I", len(body)) + body
    return bytes(out)


def decode_inner_request(data: bytes) -> tuple[str, str, dict[str, str], bytes]:
    off = 0

    def take(n):
        nonlocal off
        v = data[off:off + n]
        off += n
        return v

    def take_s(fmt):
        (n,) = struct.unpack(fmt, take(struct.calcsize(fmt)))
        return take(n)

    method = take_s(">H").decode()
    path = take_s(">H").decode()
    (n_hdrs,) = struct.unpack(">H", take(2))
    headers = {}
    for _ in range(n_hdrs):
        k = take_s(">H").decode()
        v = take_s(">I").decode()
        headers[k] = v
    body = take_s(">I")
    return method, path, headers, body


# ── request encapsulation (RFC 9458 s4.3) ───────────────────────────────────

def _hdr(key_id: int) -> bytes:
    return struct.pack(">BHHH", key_id, KEM_ID, KDF_ID, AEAD_ID)


class SenderContext:
    """Client side: one HPKE context per request (RFC 9458 s6.1)."""

    def __init__(self, cfg: KeyConfig):
        self.key_id = cfg.key_id
        pkR = load_public_key(cfg.public_key)
        hdr = _hdr(cfg.key_id)
        self.enc, self._ctx = SUITE.create_sender_context(
            pkR, info=REQUEST_INFO_LABEL + b"\x00" + hdr)
        self._hdr = hdr

    def seal(self, inner_request: bytes) -> bytes:
        ct = self._ctx.seal(inner_request, aad=b"")
        return self._hdr + self.enc + ct

    def response_opener(self) -> "ResponseOpener":
        secret = self._ctx.export(RESPONSE_EXPORT_LABEL, AEAD_KEY_LEN)
        return ResponseOpener(secret, self.enc)


class RecipientContext:
    """Gateway side: decapsulate one request and seal its response."""

    def __init__(self, sk_bytes: bytes, encapsulated: bytes):
        key_id, kem_id, kdf_id, aead_id = struct.unpack(">BHHH", encapsulated[:7])
        if (kem_id, kdf_id, aead_id) != (KEM_ID, KDF_ID, AEAD_ID):
            raise ValueError("unsupported HPKE suite in request")
        self.key_id = key_id
        self.enc = encapsulated[7:7 + 65]
        ct = encapsulated[7 + 65:]
        skR = load_private_key(sk_bytes)
        self._ctx = SUITE.create_recipient_context(
            self.enc, skR, info=REQUEST_INFO_LABEL + b"\x00" + _hdr(key_id))
        self.inner_request = self._ctx.open(ct, aad=b"")

    def response_sealer(self) -> "ResponseSealer":
        secret = self._ctx.export(RESPONSE_EXPORT_LABEL, AEAD_KEY_LEN)
        return ResponseSealer(secret, self.enc)


def peek_key_id(encapsulated: bytes) -> int:
    return encapsulated[0]


# ── response encapsulation (RFC 9458 s4.4, chunked per record) ──────────────
#
# RFC 9458 s4.4: secret = context.Export("message/bhttp response", Nk);
# salt = enc || response_nonce; prk = Extract(salt, secret);
# aead_key = Expand(prk, "key", Nk); aead_nonce = Expand(prk, "nonce", Nn).
# For streaming (LLM tokens) we frame the response into AEAD records with a
# per-record counter XORed into the nonce, as the chunked-OHTTP draft does; a
# zero-length record terminates the stream.

def _response_keys(secret: bytes, enc: bytes, response_nonce: bytes) -> tuple[bytes, bytes]:
    prk = _hkdf_extract(enc + response_nonce, secret)
    key = HKDFExpand(algorithm=hashes.SHA256(), length=AEAD_KEY_LEN, info=b"key").derive(prk)
    nonce = HKDFExpand(algorithm=hashes.SHA256(), length=AEAD_NONCE_LEN, info=b"nonce").derive(prk)
    return key, nonce


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    import hashlib
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _xor_counter(base_nonce: bytes, counter: int) -> bytes:
    return bytes(b ^ c for b, c in zip(base_nonce, counter.to_bytes(AEAD_NONCE_LEN, "big")))


class ResponseSealer:
    def __init__(self, secret: bytes, enc: bytes):
        self.response_nonce = os.urandom(AEAD_KEY_LEN)
        key, self._base_nonce = _response_keys(secret, enc, self.response_nonce)
        self._aead = AESGCM(key)
        self._ctr = 0

    def header(self) -> bytes:
        """First bytes on the wire: the response_nonce (RFC 9458 s4.4)."""
        return self.response_nonce

    def seal_record(self, chunk: bytes) -> bytes:
        ct = self._aead.encrypt(_xor_counter(self._base_nonce, self._ctr), chunk, b"")
        self._ctr += 1
        return struct.pack(">I", len(ct)) + ct

    def final(self) -> bytes:
        return self.seal_record(b"")

    def seal_stream(self, chunks: Iterator[bytes]) -> Iterator[bytes]:
        yield self.header()
        for c in chunks:
            if c:
                yield self.seal_record(c)
        yield self.final()


class ResponseOpener:
    def __init__(self, secret: bytes, enc: bytes):
        self._secret, self._enc = secret, enc
        self._aead = None
        self._base_nonce = b""
        self._ctr = 0
        self._buf = bytearray()
        self.done = False

    def feed(self, data: bytes) -> Iterator[bytes]:
        """Feed wire bytes; yield decrypted chunks as records complete."""
        self._buf += data
        if self._aead is None:
            if len(self._buf) < AEAD_KEY_LEN:
                return
            response_nonce = bytes(self._buf[:AEAD_KEY_LEN])
            del self._buf[:AEAD_KEY_LEN]
            key, self._base_nonce = _response_keys(self._secret, self._enc, response_nonce)
            self._aead = AESGCM(key)
        while len(self._buf) >= 4 and not self.done:
            (n,) = struct.unpack(">I", self._buf[:4])
            if len(self._buf) < 4 + n:
                return
            ct = bytes(self._buf[4:4 + n])
            del self._buf[:4 + n]
            pt = self._aead.decrypt(_xor_counter(self._base_nonce, self._ctr), ct, b"")
            self._ctr += 1
            if not pt:
                self.done = True
                return
            yield pt


# ── replay window (RFC 9458 s6.5) ───────────────────────────────────────────

class ReplayWindow:
    """Remember ``enc`` values seen within ``window_s``; reject duplicates.

    RFC 9458 s6.5: "Storing just the enc field of a request, which should be
    unique to each request, is sufficient."  Requests whose inner ``Date`` is
    outside the window are rejected outright, bounding the set size.
    """

    def __init__(self, window_s: int = 60):
        self.window_s = window_s
        self._seen: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def check(self, enc: bytes, date_header: Optional[str]) -> bool:
        now = time.time()
        if date_header:
            try:
                ts = time.mktime(time.strptime(date_header, "%a, %d %b %Y %H:%M:%S GMT")) - time.timezone
            except ValueError:
                return False
            if abs(now - ts) > self.window_s:
                return False
        with self._lock:
            cutoff = now - self.window_s
            if len(self._seen) > 10000:
                for k in [k for k, t in self._seen.items() if t < cutoff]:
                    del self._seen[k]
            if enc in self._seen and self._seen[enc] >= cutoff:
                return False
            self._seen[enc] = now
            return True


# ── private-key wrapping for release to an attested gateway ─────────────────
#
# The KMS releases the epoch private key wrapped under the gateway's
# registration public key (the P-256 key in its CSR, whose hash is bound into
# the gateway's TPM quote).  HPKE to that key plays the role of Azure's
# "wrapped under the attested vTPM key".

WRAP_INFO = b"janus-ohttp-kms key release"


def wrap_private_key(sk_bytes: bytes, gateway_pub_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(gateway_pub_pem)
    pkR = KEMKey.from_pyca_cryptography_key(pub)
    enc, ctx = SUITE.create_sender_context(pkR, info=WRAP_INFO)
    return enc + ctx.seal(sk_bytes, aad=b"")


def unwrap_private_key(wrapped: bytes, gateway_priv) -> bytes:
    skR = KEMKey.from_pyca_cryptography_key(gateway_priv)
    enc, ct = wrapped[:65], wrapped[65:]
    ctx = SUITE.create_recipient_context(enc, skR, info=WRAP_INFO)
    return ctx.open(ct, aad=b"")
