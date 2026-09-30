#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Browser application benchmark: page-load time (PLT) of a confidential Flask
web app fronted by Janus vs vanilla TLS, measured with a real headless Firefox
and the Janus WebExtension.

Topologies (all relay to the SAME Flask app on the backend CVM, so the delta is
purely the protocol's establishment + client-side validation cost):

  vanilla        : Firefox (no extension) -> backend :8544 (dc_proxy --x509) -> webapp
  Janus redirect : Firefox + Janus ext -> frontend :6037 /route --(302)--> backend
                   :8543 (dc_proxy DC) -> webapp.  Firefox follows the 302 itself.
  Janus proxy    : Firefox + Janus ext -> frontend :6037 /forward/ (relayed inside the enclave) -> webapp

This is the genuine browser-driven path, identical in mechanism to
``browser_compat_proof.py``: a stock Firefox is given only the service entry URL
and is steered to a backend by the frontend's 302, with the frontend's
CA-issued cert (SAN covering the backend host via JANUS_EXTRA_SANS) + an RFC 9345
Delegated Credential validated natively. There is NO socat relay and NO
localhost — the addresses are the real SAN hostnames, reached over the network.

For redirection the browser performs BOTH legs in a single navigation (control
connection to the frontend for the 302, then the data connection to the
backend), so the navigation's loadEventEnd — measured from navigationStart — is
the full two-connection e2e. We additionally record a wall-clock e2e and the
nav-timing redirect span as cross-checks (the cross-origin redirect span may be
masked to 0 without Timing-Allow-Origin; the wall-clock then confirms the total).

Prerequisites (testbed), same as browser_compat_proof.py:
  - Frontend cert SAN covers the frontend + backend hostnames (JANUS_EXTRA_SANS).
  - The (mock-public, per paper) CA root is trusted by Firefox via the enterprise
    policy in firefox/distribution/policies.json.
  - /etc/hosts (or DNS) maps the hostnames to the frontend/backend IPs.

Delegated Credentials are enabled in the profile
(security.tls.enable_delegated_credentials) so Firefox does real chain/SAN/DC
validation.

PLT = PerformanceNavigationTiming.loadEventEnd (ms from navigationStart): the
time from request initiation until the page and all sub-resources are received
and the load event fires.  We launch a FRESH Firefox per protocol and force a
fresh TLS/DC connection per measured load (idle gap > keep-alive timeout), while
the warm JWKS stays cached in the extension's in-memory key cache.

Usage (on the load-gen client):
  python3 browser_plt_bench.py --n 30 --warmup 3 \
      --frontend janus-fe.local --backend janus-be.local \
      --xpi /home/janus/browser_bench/ctls-ext.xpi \
      --firefox /home/janus/firefox/firefox --geckodriver /home/janus/geckodriver \
      --out /home/janus/browser_bench/plt.csv
"""
import os
import argparse, csv, time, sys
from urllib.parse import urlsplit

# protocol -> (uses_extension, expects a cross-origin 302 to the backend)
PROTOS = {
    "vanilla":       (False, False),
    "ctls_redirect": (True,  True),
    "ctls_proxy":    (True,  False),
}


def pct(xs, p):
    s = sorted(xs); k = (len(s)-1)*p/100; f = int(k); c = min(f+1, len(s)-1)
    return s[f] if f == c else s[f]+(s[c]-s[f])*(k-f)


def make_driver(firefox, geckodriver, use_ext, xpi):
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    o = Options()
    o.add_argument("--headless")
    o.binary_location = firefox
    o.set_preference("security.tls.enable_delegated_credentials", True)
    # keep-alive ON so a page's sub-resources reuse one connection (realistic),
    # but expire idle connections fast so the NEXT navigation (after the
    # inter-iteration gap) opens a FRESH TLS/DC connection — i.e. every measured
    # load pays a full establishment, while the warm JWKS stays cached in the
    # background page's in-memory key cache (steady-state attestation).
    o.set_preference("network.http.keep-alive", True)
    o.set_preference("network.http.persistent-connection-timeout", 1)
    # disk cache OFF so the page + sub-resources are always re-fetched (the JWKS
    # is cached by the extension in memory, not by the HTTP cache).
    o.set_preference("browser.cache.disk.enable", False)
    o.set_preference("browser.cache.memory.enable", False)
    o.set_preference("toolkit.telemetry.enabled", False)
    o.set_preference("network.captive-portal-service.enabled", False)
    o.set_preference("datareporting.healthreport.uploadEnabled", False)
    svc = Service(executable_path=geckodriver, log_output=f"/tmp/gecko.{os.getuid()}.log")
    d = webdriver.Firefox(service=svc, options=o)
    if use_ext:
        d.install_addon(xpi, temporary=True)
        time.sleep(1.5)  # let the background page register its webRequest hook
    d.set_page_load_timeout(60)
    return d


NAV_JS = """
var t = performance.getEntriesByType('navigation')[0];
if (!t) return null;
return {
  plt: t.loadEventEnd, dcl: t.domContentLoadedEventEnd,
  ttfb: t.responseStart, respEnd: t.responseEnd,
  connectStart: t.connectStart, connectEnd: t.connectEnd,
  secureStart: t.secureConnectionStart, requestStart: t.requestStart,
  redirectStart: t.redirectStart, redirectEnd: t.redirectEnd,
  fetchStart: t.fetchStart
};
"""


def read_verdict(d):
    g = "return document.documentElement.getAttribute(arguments[0]);"
    ok = None
    for _ in range(40):
        ok = d.execute_script(g, "data-ctls-ok")
        if ok is not None and ok != "":
            break
        time.sleep(0.05)
    return {
        "ok": ok,
        "reason": d.execute_script(g, "data-ctls-reason"),
        "verify_ms": d.execute_script(g, "data-ctls-ms"),
        "tee": d.execute_script(g, "data-ctls-tee"),
    }


def measure(name, url, use_ext, expect_redirect, xpi, firefox, geckodriver, n, warmup):
    """One persistent Firefox per protocol: warmup navigations prime the
    extension's JWKS cache; a short idle gap between iterations forces a fresh
    TLS/DC connection each measured load.

    For redirect, the browser is pointed at the frontend's /route URL and
    follows the 302 to the backend itself — so a single navigation covers both
    the control (frontend) and data (backend) connections, and loadEventEnd is
    the full two-connection e2e."""
    rows = []
    entry_host = urlsplit(url).hostname
    d = None
    try:
        d = make_driver(firefox, geckodriver, use_ext, xpi)
        for i in range(n + warmup):
            try:
                # settle + let the previous idle connection expire (timeout=1s)
                d.get("about:blank")
                time.sleep(1.3)
                t0 = time.perf_counter()
                d.get(url)                         # follows the 302 natively
                wall = (time.perf_counter() - t0) * 1000
                nav = d.execute_script(NAV_JS)
                final = d.current_url
                v = (read_verdict(d) if use_ext
                     else {"ok": "n/a", "reason": "", "verify_ms": "", "tee": ""})
                if nav and nav.get("plt"):
                    tls = (nav["connectEnd"] - nav["secureStart"]) if nav.get("secureStart") else 0
                    redir = ((nav["redirectEnd"] - nav["redirectStart"])
                             if nav.get("redirectEnd") else 0)
                    redirected = urlsplit(final).hostname != entry_host
                    row = {
                        "protocol": name, "iter": i, "warmup": int(i < warmup),
                        "plt_ms": round(nav["plt"], 2),        # nav-timing full e2e
                        "e2e_wall_ms": round(wall, 2),         # wall-clock cross-check
                        "redirect_ms": round(redir, 2),        # 0 if cross-origin masked
                        "dcl_ms": round(nav["dcl"], 2),
                        "ttfb_ms": round(nav["ttfb"], 2),
                        "tls_ms": round(tls, 2),
                        "final_url": final,
                        "ctls_ok": v["ok"], "ctls_reason": v["reason"],
                        "verify_ms": v["verify_ms"], "tee": v["tee"],
                    }
                    # reject a sample that didn't attest, or (redirect mode) that
                    # never left the frontend origin — i.e. the 302 wasn't followed.
                    if use_ext and v["ok"] != "1":
                        row["rejected"] = 1
                    if expect_redirect and not redirected:
                        row["rejected"] = 1
                    rows.append(row)
            except Exception as e:
                print(f"  [{name} iter {i}] ERROR: {repr(e)[:160]}", file=sys.stderr)
    finally:
        if d:
            try: d.quit()
            except Exception: pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--frontend", default="janus-fe.local",
                    help="frontend SAN hostname (redirect /route + proxy)")
    ap.add_argument("--backend", default="janus-be.local",
                    help="backend SAN hostname (vanilla endpoint)")
    ap.add_argument("--route-port", type=int, default=6037,
                    help="frontend /route port (redirect entry)")
    ap.add_argument("--vanilla-port", type=int, default=8544,
                    help="backend dc_proxy --x509 port (vanilla)")
    # explicit per-protocol entry URLs override the host/port defaults
    ap.add_argument("--vanilla-url", default="")
    ap.add_argument("--redirect-url", default="")
    ap.add_argument("--proxy-url", default="")
    ap.add_argument("--xpi", default=os.path.expanduser("~/browser_bench/ctls-ext.xpi"))
    ap.add_argument("--firefox", default=os.path.expanduser("~/firefox/firefox"))
    ap.add_argument("--geckodriver", default=os.path.expanduser("~/geckodriver"))
    ap.add_argument("--out", default=os.path.expanduser("~/browser_bench/plt.csv"))
    ap.add_argument("--only", default="", help="comma list: vanilla,ctls_redirect,ctls_proxy")
    a = ap.parse_args()

    urls = {
        "vanilla":       a.vanilla_url  or f"https://{a.backend}:{a.vanilla_port}/",
        "ctls_redirect": a.redirect_url or f"https://{a.frontend}:{a.route_port}/route",
        "ctls_proxy":    a.proxy_url    or f"https://{a.frontend}:{a.route_port}/forward/",   # relayed inside the enclave
    }
    sel = set(a.only.split(",")) if a.only else set(urls)

    no_data = []
    all_rows = []
    for name in ["vanilla", "ctls_redirect", "ctls_proxy"]:
        if name not in sel:
            continue
        url = urls[name]
        use_ext, expect_redirect = PROTOS[name]
        print(f"== {name} ({url}, ext={use_ext}, redirect={expect_redirect}) "
              f"n={a.n}+{a.warmup}w ==")
        rows = measure(name, url, use_ext, expect_redirect, a.xpi, a.firefox,
                       a.geckodriver, a.n, a.warmup)
        good = [r for r in rows if not r.get("warmup") and not r.get("rejected")]
        plts = [r["plt_ms"] for r in good]
        if plts:
            print(f"   n={len(plts)} PLT p50={pct(plts,50):.1f} "
                  f"p95={pct(plts,95):.1f} p99={pct(plts,99):.1f} ms "
                  f"(min={min(plts):.1f})")
        else:
            print("   NO DATA"); no_data.append(name)
        if plts and len(plts) < 0.9 * a.n:
            print(f"   INCOMPLETE: {len(plts)} of {a.n} loads succeeded (rejected/failed: {a.n - len(plts)})"); no_data.append(name)
        all_rows += rows

    if all_rows:
        keys = ["protocol","iter","warmup","plt_ms","e2e_wall_ms","redirect_ms",
                "dcl_ms","ttfb_ms","tls_ms","final_url",
                "ctls_ok","ctls_reason","verify_ms","tee","rejected"]
        with open(a.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            for r in all_rows:
                w.writerow(r)
        print(f"wrote {len(all_rows)} rows -> {a.out}")
    if no_data:
        print(f"FAILED: no successful page load for {', '.join(no_data)}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
