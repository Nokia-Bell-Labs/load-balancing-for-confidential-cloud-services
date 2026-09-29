# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""HTTP helpers for the bench.

We measure time to first byte (TTFB) as the ``http_ms`` phase: from
``sendall(request)`` to the moment ``recv()`` returns the first response
byte to user space.  Draining the rest of the response is for validation
only and is intentionally not timed — the metric we publish describes
connection establishment + attestation, not throughput.
"""

from __future__ import annotations

import re


def build_http_get(template: str, host: str, path: str) -> bytes:
    """Render the GET request from the YAML template.

    The YAML block-string carries Unix line endings; we normalise to CRLF
    and guarantee the trailing blank line so the request is wire-correct
    regardless of how the template was authored.
    """
    body = template.format(host=host, path=path)
    body = body.replace("\r\n", "\n").replace("\n", "\r\n")
    if not body.endswith("\r\n\r\n"):
        body = body.rstrip("\r\n") + "\r\n\r\n"
    return body.encode("ascii")


def recv_first_byte(sock) -> bytes:
    """Block until the first response byte arrives; return it."""
    b = sock.recv(1)
    if not b:
        raise ConnectionError("peer closed before any response byte")
    return b


def drain_response(sock, first_byte: bytes, max_bytes: int = 65536) -> bytes:
    """Read the rest of the response up to ``max_bytes``; not timed.

    Used to validate that the server actually returned a response (we
    check for an HTTP/1.x status line in the caller).  Errors here are
    swallowed: a peer that closes mid-body still produced a measurable
    first-byte time, which is what the metric needs.
    """
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


_STATUS_RE = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})")


def parse_status_code(resp_bytes: bytes) -> int | None:
    m = _STATUS_RE.match(resp_bytes)
    return int(m.group(1)) if m else None
