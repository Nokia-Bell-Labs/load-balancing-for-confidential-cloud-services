# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Untrusted OHTTP relay with persistent upstream connections and streaming.

Gateway URLs are deployment configuration, not client-controlled destinations.
This module is separate from the unchanged Janus frontend implementation.
"""
import itertools
import os
import threading

import requests
from flask import Flask, Response, request, stream_with_context

app = Flask(__name__)
_gateways = tuple(url.rstrip('/') for url in os.environ.get('OHTTP_GATEWAYS', '').split(',') if url)
_sequence = itertools.cycle(_gateways)
_selection_lock = threading.Lock()
_local = threading.local()
_hop = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length'}


@app.get('/health')
def health():
    return {'gateways': len(_gateways)}, 200 if _gateways else 503


@app.post('/forward/ohttp')
def forward():
    if not _gateways:
        return Response('No configured gateway', status=503)
    with _selection_lock:
        target = next(_sequence)
    if not hasattr(_local, 'session'):
        _local.session = requests.Session()
        # Keep a pool for every configured gateway. The requests default
        # caches only ten pools, causing avoidable TLS reconnects at N=32.
        for scheme in ('http://', 'https://'):
            _local.session.mount(scheme, requests.adapters.HTTPAdapter(
                pool_connections=len(_gateways), pool_maxsize=1, pool_block=True))
    excluded = _hop | {'host'}
    # Connection may nominate additional hop-by-hop fields.
    excluded |= {x.strip().lower() for x in request.headers.get('Connection', '').split(',')}
    headers = {k: v for k, v in request.headers if k.lower() not in excluded}
    headers['Accept-Encoding'] = 'identity'
    try:
        upstream = _local.session.post(target + '/ohttp', data=request.get_data(),
                                       headers=headers, stream=True, timeout=(10, 300),
                                       verify=False, allow_redirects=False)
    except requests.RequestException:
        app.logger.exception('OHTTP upstream request failed')
        return Response('Gateway unavailable', status=502)
    response_excluded = _hop | {x.strip().lower() for x in upstream.headers.get('Connection', '').split(',')}
    output_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in response_excluded}

    def chunks():
        try:
            # The gateway's encrypted body is opaque. HTTP framing is decoded
            # by requests and supplied afresh by the downstream WSGI server.
            for chunk in upstream.iter_content(chunk_size=None):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return Response(stream_with_context(chunks()), status=upstream.status_code,
                    headers=output_headers)
