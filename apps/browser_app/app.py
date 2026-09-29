#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Confidential web application (the browser-benchmark target).

A small self-contained Flask site — an HTML page plus a CSS and a JS
sub-resource and an inline SVG — served from inside the SEV-SNP backend.
It is intentionally free of external (CDN) resources so page-load time is
deterministic and reflects only the Janus establishment + transfer cost,
not third-party network latency.

The same app is fronted three ways for the PLT comparison (all relay here):
  * Janus redirect : dc_proxy(DC)      :8543 -> :5001   (attested leaf cert)
  * vanilla TLS    : dc_proxy(--x509)  :8544 -> :5001   (trusted localhost cert)
  * Janus proxy    : frontend          :6037 /forward.. -> backend

Run:  python3 app.py --port 5001
"""
import argparse
from flask import Flask, Response

app = Flask(__name__)

INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Confidential Dashboard</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header>
    <svg width="40" height="40" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#1e8e3e" d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/>
      <path fill="#fff" d="M10.5 14.2 8 11.7l1.2-1.2 1.3 1.3 3.3-3.3 1.2 1.2z"/>
    </svg>
    <h1>Confidential Dashboard</h1>
  </header>
  <main>
    <section class="card">
      <h2>Account summary</h2>
      <p>This page is served from inside an AMD SEV-SNP confidential VM and
         delivered over a Janus channel whose attestation your browser verified
         before rendering.</p>
      <table>
        <tr><th>Tenant</th><td>acme-corp</td></tr>
        <tr><th>Region</th><td>west-europe</td></tr>
        <tr><th>TEE</th><td id="tee">verifying…</td></tr>
      </table>
    </section>
    <section class="card">
      <h2>Recent activity</h2>
      <ul id="log"><li>Loading…</li></ul>
    </section>
  </main>
  <footer>Janus demo &middot; Flask</footer>
  <script src="/app.js"></script>
</body>
</html>"""

STYLE = """:root{--bg:#f1f3f4;--fg:#202124;--accent:#1e8e3e}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:12px;padding:18px 28px;background:#fff;
box-shadow:0 1px 4px rgba(0,0,0,.1)}header h1{font-size:20px;margin:0}
main{max-width:860px;margin:24px auto;padding:0 16px;display:grid;gap:18px;
grid-template-columns:1fr 1fr}
.card{background:#fff;border-radius:10px;padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card h2{margin:0 0 10px;font-size:16px;color:var(--accent)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 4px;
border-bottom:1px solid #eee;font-size:14px}th{color:#5f6368;font-weight:600;width:40%}
ul{margin:0;padding-left:18px;font-size:14px;line-height:1.7}
footer{text-align:center;color:#80868b;font-size:12px;padding:20px}
@media(max-width:680px){main{grid-template-columns:1fr}}"""

APPJS = """// Tiny client script: render some "activity" and reflect the attested TEE
// the Janus extension recorded on <html data-ctls-tee>.
(function(){
  var items=["Signed in from 10.0.0.7","Viewed billing report",
             "Rotated API key","Exported audit log","Updated 2FA device"];
  var ul=document.getElementById("log"); ul.innerHTML="";
  items.forEach(function(t){var li=document.createElement("li");li.textContent=t;ul.appendChild(li);});
  var tee=document.documentElement.getAttribute("data-ctls-tee");
  document.getElementById("tee").textContent = tee ? (tee.toUpperCase()+" (attested)") : "unverified";
})();"""


@app.route("/")
def index():
    return Response(INDEX, mimetype="text/html")


@app.route("/style.css")
def style():
    return Response(STYLE, mimetype="text/css")


@app.route("/app.js")
def appjs():
    return Response(APPJS, mimetype="application/javascript")


@app.route("/healthz")
def healthz():
    return "ok\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--bind", default="127.0.0.1")
    a = ap.parse_args()
    # Plain HTTP behind the TLS-terminating dc_proxy fronts.
    app.run(host=a.bind, port=a.port, threaded=True, load_dotenv=False)


if __name__ == "__main__":
    main()
