# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Oak baseline -- shared wire helpers (framing, mock evidence, verification).

Framing inside the outer TLS stream is a 4-byte length prefix per message;
an empty frame closes the session.  The Noise suite is the one Oak's
session library uses by default: Noise_NN_25519_ChaChaPoly_SHA256.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

NOISE_PROTOCOL = b"Noise_NN_25519_ChaChaPoly_SHA256"
NONCE_LEN = 32          # client challenge in the ATTEST message

_CODEBASE = Path(__file__).resolve().parents[3]
if str(_CODEBASE) not in sys.path:
    sys.path.insert(0, str(_CODEBASE))


def send_frame(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n) if n else b""


# ── mock evidence (no TEE) ──────────────────────────────────────────────────

def strip_chain(bundle: bytes) -> bytes:
    """The same bundle without the VCEK/ASK/ARK PEM chain (~6.5 KB).  The client
    verifies the AS-signed JWT and the TPM quote; the chain was consumed by the
    attestation service on the server side and the client never reads it.
    Keeping it made the ATTEST reply exceed the initial congestion window."""
    p = 0
    fields = []
    for _ in range(4):
        (n,) = struct.unpack(">I", bundle[p:p + 4])
        fields.append(bundle[p + 4:p + 4 + n])
        p += 4 + n
    fields[1] = b""
    return b"".join(struct.pack(">I", len(x)) + x for x in fields)


def qualifying_data(nonce: bytes, pub_der: bytes) -> bytes:
    """TPM quote qualifyingData = SHA256(client nonce || binding public key), the same
    binding the Janus registration uses (snp_attestation.registration_reportdata)."""
    return hashlib.sha256(nonce + pub_der).digest()


def mock_bundle(pub_der: bytes, nonce: bytes) -> bytes:
    """Stub bundle in the same layout as build_snp_evidence_bundle:
    [hcl_len | hcl][chain_len | chain][qmsg_len | qmsg][qsig_len | qsig],
    with SHA256(nonce || pub_der) where the TPM quote's qualifyingData would be."""
    hcl = b"\x00" * 32 + b"\x00" * 0x50 + qualifying_data(nonce, pub_der) + b"\x00" * (1184 - 0x50 - 32)
    chain = b""
    qmsg = b"MOCKQUOTE" + qualifying_data(nonce, pub_der)
    qsig = b""
    return b"".join(struct.pack(">I", len(x)) + x for x in (hcl, chain, qmsg, qsig))


# ── client-side verification ────────────────────────────────────────────────

def verify_evidence(bundle: bytes, jwt: str, pub_der: bytes, nonce: bytes, *, jwks_cache,
                    maa_issuer: str, timeout_s: float,
                    expected_measurement: str | None = None) -> dict:
    """Verify per-instance evidence the way the Janus frontend verifies a
    backend bundle, but against the server-supplied MAA JWT instead of a
    fresh attestation-service call (Oak's client verifies locally):

      1. JWT signature with the cached AS key (issuer pinned), validity
         (janus.client.attest)
      2. measurement policy on the JWT claims
      3. the bundle's runtime claims are the ones the AS attested: their vTPM
         attestation key equals the one in the JWT's x-ms-runtime claim
      4. TPM quote: AK signature under that key and
         qualifyingData == SHA256(client nonce || binding public key)
         (janus.common.snp_attestation._verify_tpm_quote)

    Returns the JWT claims plus ``jwks_cold``.
    """
    from janus.client import attest
    from janus.common.snp_attestation import (_split_hcl, _verify_tpm_quote,
                                              parse_snp_evidence_bundle)
    header, payload, _ = attest.parse_jwt(jwt)
    issuer = payload.get("iss") or maa_issuer
    jwks = attest.get_maa_public_key(issuer, header.get("kid", ""),
                                     header.get("jku") or f"{maa_issuer}/certs",
                                     jwks_cache, timeout_s, trusted_issuer=maa_issuer)
    attest.verify_jwt_rs256(jwt, jwks.public_key)
    attest.verify_jwt_validity(payload)
    measured = payload.get("x-ms-sevsnpvm-launchmeasurement", "")
    if expected_measurement and expected_measurement.lower() != measured.lower():
        raise ValueError("launch measurement does not match policy")
    ev = parse_snp_evidence_bundle(bundle)
    _snp_report, runtime_claims = _split_hcl(ev.hcl_report)
    _check_runtime_claims_attested(runtime_claims, payload)
    _verify_tpm_quote(ev.tpm_quote_msg, ev.tpm_quote_sig, runtime_claims,
                      nonce, pub_der)
    return {"claims": payload, "jwks_cold": jwks.cold}


def _check_runtime_claims_attested(runtime_claims_json: bytes, jwt_payload: dict) -> None:
    """Bind the server-supplied runtime claims to the AS-signed token: the vTPM AK
    (kid HCLAkPub) in the bundle must be the AK the AS put in x-ms-runtime, which
    it derived from the report it validated.  Without this, any valid token for
    any CVM plus an attacker-chosen AK would pass the quote check."""
    import json
    bundle_keys = {k.get("kid"): k for k in json.loads(runtime_claims_json).get("keys", [])}
    token_keys = {k.get("kid"): k for k in (jwt_payload.get("x-ms-runtime") or {}).get("keys", [])}
    a, b = bundle_keys.get("HCLAkPub"), token_keys.get("HCLAkPub")
    if not a or not b:
        raise ValueError("attestation key missing from the runtime claims or the AS token")
    if (a.get("n"), a.get("e")) != (b.get("n"), b.get("e")):
        raise ValueError("runtime claims are not the ones the AS attested (AK mismatch)")


def mock_verify_evidence(bundle: bytes, pub_der: bytes, nonce: bytes) -> None:
    """Mock check: the stub quote carries SHA256(nonce || binding public key)."""
    (hlen,) = struct.unpack(">I", bundle[:4])
    off = 4 + hlen
    (clen,) = struct.unpack(">I", bundle[off:off + 4])
    off += 4 + clen
    (qlen,) = struct.unpack(">I", bundle[off:off + 4])
    qmsg = bundle[off + 4:off + 4 + qlen]
    if qmsg[-32:] != qualifying_data(nonce, pub_der):
        raise ValueError("mock quote not bound to the client nonce and binding key")
