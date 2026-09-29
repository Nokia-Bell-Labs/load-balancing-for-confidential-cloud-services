#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Table 3: bandwidth overhead of Janus over TLS, measured live.
#
# Janus adds two static items per connection. One is the AS JWT inside the frontend
# certificate (an X.509 extension). The other is the RFC 9345 DC in the handshake.
# This script measures the certificate side on the live testbed. It gets the vanilla leaf
# from the plain terminator of the backend. It gets the attested leaf from the frontend,
# and the size of the JWT extension in it. It computes the DC size by
# serializing DCs with the encoder of the artifact. A non-DC client cannot see the DC,
# Seconds to run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
cd "$ROOT"
python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" "$BACKEND_HOST" "$VANILLA_PORT" <<'PY'
import sys, ssl, socket
sys.path.insert(0, ".")
from cryptography import x509
from cryptography.hazmat.primitives import serialization
def leaf(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
        return x509.load_der_x509_certificate(ss.getpeercert(True))
fe, va = leaf(sys.argv[1], sys.argv[2]), leaf(sys.argv[3], sys.argv[4])
fe_der = len(fe.public_bytes(serialization.Encoding.DER)); va_der = len(va.public_bytes(serialization.Encoding.DER))
jwt = len(fe.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1")).value.value)
print(f"vanilla leaf certificate (DER)        {va_der:6d} B")
print(f"frontend attested leaf (DER)          {fe_der:6d} B")
print(f"  of which the AS-JWT extension       {jwt:6d} B   (what Janus adds to the certificate)")
import sys, os; sys.path.insert(0, os.environ.get("ROOT", "."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from janus.common import dc as _dc
_k = ec.generate_private_key(ec.SECP256R1()); _hold = ec.generate_private_key(ec.SECP256R1())
_sizes = [len(_dc.sign_dc(fe.public_bytes(serialization.Encoding.DER), _k, _hold.public_key(), 86400)) for _ in range(20)]
print(f"RFC 9345 Delegated Credential      {min(_sizes)}-{max(_sizes)} B   (computed: 20 DCs serialized by janus/common/dc.py for this frontend certificate. The ECDSA signature length varies by 1-2 B)")
PY
echo "The DC is the only addition of Janus to the TLS 1.3 handshake."
