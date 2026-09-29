<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Janus client

The client sets up a Janus-attested channel and speaks **ordinary HTTP** over it. It
is **application-agnostic**: the "application" is just whatever HTTP server runs behind
the backend's `dc_proxy`, so targeting a different app means sending a different
request, not changing this code. The `eval/benches/` drivers are worked examples.

## Files

| File | Role |
|---|---|
| `proxy.py` | Proxy mode: one TLS connection to the frontend (verifies its attestation), which relays to a backend. |
| `redirect.py` | Redirection mode: control leg to the frontend, then a direct DC-validated data leg to a backend. |
| `attest.py` | Attestation helpers (MAA JWT, JWKS, REPORTDATA), shared with the baselines. |
| `native/nss_dc_helper.c` | The real DC handshake over NSS (Firefox's stack); Python `ssl` can't validate DCs. See `native/README.md`. |
| `browser_extension/` | Firefox WebExtension — the browser client. See its README. |
| `_timing.py`, `test_client.py` | Phase timer; tests. |

## Topology

```
proxy mode:        client ──TLS──► frontend ──(/forward)──► backend dc_proxy ──► app
redirection mode:  client ──TLS+DC──► backend dc_proxy ──► app     (after a /route 302)
```

Only redirection presents a **DC to the client**: it validates the frontend's cert
chain plus the backend's RFC 9345 DC. Proxy mode is plain TLS to the frontend's
attested cert — no client-side DC. Either way the backend's `dc_proxy` (in the TEE)
terminates the public TLS and forwards plain HTTP to the app on loopback; target the
app by `(host, port, path[, body])`.

## Driving it

- **Redirection** (programmatic): write `"<host> <port> <path>"` (GET) or
  `"POST <host> <port> <path> <json-body>"` to `nss_dc_helper` (it replies
  `OK …status=… dc=1 …`). `redirect.py` does the control leg, then `data_connect()`.
- **Proxy**: `ProxyClient(...).connect_validate_request(jwks, http_template, path)`.
- **Browser**: stock Firefox + `browser_extension/`, navigated to the frontend URL.

| App | Driver | Client use | Metric |
|---|---|---|---|
| Browser web app | `eval/benches/browser_plt_bench.py` | Firefox + extension (native NSS DC) | page-load time |
| LLM | `eval/benches/llm_ttft_bench.py` | helper, `POST /generate` (streamed) | time-to-first-token |
| Microservice | `eval/benches/microservice_bench.py` | helper, `GET /reservation` | end-to-end latency |


## Same client the evaluation ran

The eval infra code drives this code, it does not reimplement it: `eval/clients/ctls_proxy.py`
and `ctls_redirect.py` import `ProxyClient`/`RedirectClient` from here (adding only
pooling and timing), and every redirection DC handshake — eval clients and app benches
alike — uses the one `native/nss_dc_helper` binary. App benches also share
`attest.py`/`snp_attestation`; only their app-specific request shaping is inline. So the
security-critical paths (attestation + the DC handshake) are shared everywhere — there is
no second client implementation.

## A new application

Run it behind `dc_proxy` and send its HTTP request via the client (the helper line,
`http_template`, or a browser navigation). No client code changes.
