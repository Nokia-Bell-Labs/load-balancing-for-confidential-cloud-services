#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Microbenchmark of the frontend's Delegated-Credential signing operation
(the per-backend step in registration that replaces a per-worker CA cert).

This replicates ctls/frontend/frontend_server.py:sign_dc faithfully: build the
RFC-9345 Credential (backend SPKI + validity), assemble the signing input
(label + frontend cert DER + credential), and time the single ECDSA-P256-SHA256
signature with the frontend's key. It is a CPU-local crypto op (no CA, no
network), so a host-side measurement faithfully represents its cost; we report
it as the per-backend DC-issuance signing latency.
"""
import struct
import time
import statistics
import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

ITERS = 5000
SIG_ECDSA_P256_SHA256 = 0x0403

# Frontend key + a realistic frontend certificate (DER) to match sign_dc input.
fe_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
now = datetime.datetime.now(datetime.timezone.utc)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "frontend.ctls")])
fe_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
           .public_key(fe_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("frontend.ctls")]), False)
           .sign(fe_key, hashes.SHA256(), default_backend()))
cert_der = fe_cert.public_bytes(serialization.Encoding.DER)

# Backend key SPKI (P-256), as carried in the DC Credential.
be_pub = ec.generate_private_key(ec.SECP256R1(), default_backend()).public_key()
spki_der = be_pub.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)

valid_seconds = 86400
credential = (struct.pack(">I", valid_seconds)
              + struct.pack(">H", SIG_ECDSA_P256_SHA256)
              + struct.pack(">I", len(spki_der))[1:]
              + spki_der)
sign_input = (b"\x20" * 64
              + b"TLS, server delegated credentials\x00"
              + cert_der + credential + struct.pack(">H", SIG_ECDSA_P256_SHA256))

# warmup
for _ in range(200):
    fe_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))

samples = []
for _ in range(ITERS):
    t0 = time.perf_counter()
    fe_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
    samples.append((time.perf_counter() - t0) * 1000.0)

samples.sort()
p = lambda q: samples[int(q * (len(samples) - 1))]
print(f"sign_input={len(sign_input)} B  cert_der={len(cert_der)} B  spki={len(spki_der)} B")
print(f"DC sign (ECDSA-P256-SHA256), N={ITERS}:")
print(f"  mean   {statistics.mean(samples):.4f} ms")
print(f"  median {p(0.50):.4f} ms")
print(f"  p95    {p(0.95):.4f} ms")
print(f"  min    {samples[0]:.4f} ms")
with open("dc_sign_microbench.csv", "w") as f:
    f.write("metric,ms\n")
    f.write(f"mean,{statistics.mean(samples):.4f}\nmedian,{p(0.50):.4f}\np95,{p(0.95):.4f}\nmin,{samples[0]:.4f}\n")
