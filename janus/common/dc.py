# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
RFC 9345 Delegated Credential helpers shared by the frontend (issuer), the
backend (holder, which re-validates a renewed DC before installing it) and
the tests.

Wire format (RFC 9345 §4):

    struct {
        uint32 valid_time;                 // seconds from the delegating
                                           //   certificate's notBefore
        SignatureScheme dc_cert_verify_algorithm;
        opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
    } Credential;

    struct {
        Credential cred;
        SignatureScheme algorithm;         // scheme used for `signature`
        opaque signature<0..2^16-1>;
    } DelegatedCredential;

The signature covers (RFC 9345 §4.1.2):

    64 x 0x20 || "TLS, server delegated credentials" || 0x00
        || DER(delegating end-entity certificate) || Credential || algorithm

Because the delegating certificate's DER is part of the signed input, a DC is
only valid together with the exact certificate it was issued under: re-issuing
the frontend certificate invalidates every outstanding DC, which is why the
frontend re-signs and pushes them on renewal (design §4.3, "Handling Backend
Irregularities").
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SIG_ECDSA_P256_SHA256 = 0x0403
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
MAX_VALID_SECONDS = 7 * 24 * 3600          # RFC 9345 §4.1.3

_CONTEXT = b"\x20" * 64 + b"TLS, server delegated credentials\x00"


@dataclass
class ParsedDC:
    valid_seconds: int
    dc_cert_verify_alg: int
    spki_der: bytes
    algorithm: int
    signature: bytes
    credential: bytes          # the raw Credential bytes (needed to re-verify)


def build_credential(spki_der: bytes, valid_seconds: int,
                     dc_cert_verify_alg: int) -> bytes:
    if not 0 < valid_seconds <= MAX_VALID_SECONDS:
        raise ValueError(f"DC valid_time must be in (0, {MAX_VALID_SECONDS}] s")
    return (struct.pack(">I", valid_seconds)
            + struct.pack(">H", dc_cert_verify_alg)
            + struct.pack(">I", len(spki_der))[1:]
            + spki_der)


def sign_input(cert_der: bytes, credential: bytes, algorithm: int) -> bytes:
    # NSS (Bug 2018200) places `algorithm` after the Credential bytes; the
    # frontend has always signed this layout and NSS/BoringSSL accept it.
    return _CONTEXT + cert_der + credential + struct.pack(">H", algorithm)


def sign_dc(delegating_cert_der: bytes, frontend_private_key,
            holder_public_key, valid_seconds: int) -> bytes:
    """Issue a DC for `holder_public_key` under `delegating_cert_der`."""
    spki_der = holder_public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    dc_alg = (SIG_ECDSA_P256_SHA256 if isinstance(holder_public_key, ec.EllipticCurvePublicKey)
              else SIG_RSA_PSS_RSAE_SHA256)
    credential = build_credential(spki_der, valid_seconds, dc_alg)
    algorithm = SIG_ECDSA_P256_SHA256
    signature = frontend_private_key.sign(
        sign_input(delegating_cert_der, credential, algorithm), ec.ECDSA(hashes.SHA256()))
    return credential + struct.pack(">H", algorithm) + struct.pack(">H", len(signature)) + signature


def parse_dc(dc: bytes) -> ParsedDC:
    if len(dc) < 4 + 2 + 3:
        raise ValueError("DC too short")
    valid_seconds = struct.unpack(">I", dc[:4])[0]
    dc_alg = struct.unpack(">H", dc[4:6])[0]
    spki_len = int.from_bytes(dc[6:9], "big")
    p = 9 + spki_len
    if len(dc) < p + 4:
        raise ValueError("DC truncated after SPKI")
    spki_der = dc[9:p]
    algorithm = struct.unpack(">H", dc[p:p + 2])[0]
    sig_len = struct.unpack(">H", dc[p + 2:p + 4])[0]
    signature = dc[p + 4:p + 4 + sig_len]
    if len(signature) != sig_len:
        raise ValueError("DC truncated in signature")
    return ParsedDC(valid_seconds, dc_alg, spki_der, algorithm, signature, dc[:p])


def verify_dc(dc: bytes, delegating_cert: x509.Certificate,
              expected_holder_public_key=None) -> ParsedDC:
    """Verify `dc` against the certificate it claims to be delegated from.

    Checks the signature with the certificate's public key and, if given,
    that the DC's SPKI equals `expected_holder_public_key`.  Raises
    ValueError on any failure.
    """
    parsed = parse_dc(dc)
    if parsed.algorithm != SIG_ECDSA_P256_SHA256:
        raise ValueError(f"unsupported DC signature scheme 0x{parsed.algorithm:04x}")
    if not 0 < parsed.valid_seconds <= MAX_VALID_SECONDS:
        raise ValueError("DC valid_time out of range")
    pub = delegating_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("delegating certificate key is not EC")
    cert_der = delegating_cert.public_bytes(serialization.Encoding.DER)
    try:
        pub.verify(parsed.signature,
                   sign_input(cert_der, parsed.credential, parsed.algorithm),
                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("DC signature does not verify under the delegating certificate")
    if expected_holder_public_key is not None:
        want = expected_holder_public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if want != parsed.spki_der:
            raise ValueError("DC is not for this holder key")
    return parsed
