#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Browser-compatibility proof for Janus redirection mode.

Demonstrates the paper's claim that Janus works with *unmodified* browsers: a
stock headless Firefox, given only the service entry URL, is steered to a
backend by the frontend and validates the attested channel — with no browser
patch and no test-infrastructure trickery (no socat, no localhost SAN).

Flow exercised (all real, on the testbed):
  1. Firefox navigates to the frontend service URL  https://<fe>:<p>/route
  2. The frontend answers GET /route (Accept: text/html) with a 302 to a
     backend it selected (select_backend()); Firefox follows it natively.
  3. Firefox opens TLS 1.3 to the backend, which presents the frontend's
     CA-issued certificate + an RFC 9345 Delegated Credential. Firefox
     validates the chain (trusted CA), the SAN (matches the backend host),
     and the DC — all natively (security.tls.enable_delegated_credentials).
  4. The Janus extension validates the attestation JWT for the backend origin.

PASS criteria: the final URL is the backend, the page loads, and the extension
verdict is ok with tee != none.

Prerequisites (testbed):
  - Frontend cert SAN covers the frontend + backend hostnames (JANUS_EXTRA_SANS).
  - The (mock-public, per paper) CA root is trusted by Firefox — here via the
    enterprise policy in firefox/distribution/policies.json.
  - /etc/hosts (or DNS) maps the hostnames to the frontend/backend IPs.

Usage:
  python3 browser_compat_proof.py \
      --entry https://janus-fe.local:6037/route \
      --expect-backend https://janus-be.local:8543/ \
      --firefox /home/janus/firefox/firefox --geckodriver /home/janus/geckodriver \
      --xpi /home/janus/browser_bench/ctls-ext.xpi
"""
import os
import argparse
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry", required=True, help="frontend service URL the browser opens")
    ap.add_argument("--expect-backend", required=True,
                    help="URL prefix the browser must be redirected to")
    ap.add_argument("--firefox", default=os.path.expanduser("~/firefox/firefox"))
    ap.add_argument("--geckodriver", default=os.path.expanduser("~/geckodriver"))
    ap.add_argument("--xpi", default=os.path.expanduser("~/browser_bench/ctls-ext.xpi"))
    a = ap.parse_args()

    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service

    o = Options()
    o.add_argument("--headless")
    o.binary_location = a.firefox
    o.set_preference("security.tls.enable_delegated_credentials", True)
    o.set_preference("browser.cache.disk.enable", False)
    svc = Service(executable_path=a.geckodriver, log_output="/tmp/gecko_compat.log")
    d = webdriver.Firefox(service=svc, options=o)
    d.install_addon(a.xpi, temporary=True)
    time.sleep(1.5)  # let the extension register its webRequest hook
    d.set_page_load_timeout(60)
    try:
        d.get(a.entry)
        time.sleep(2.5)
        final = d.current_url
        title = d.title
        g = "return document.documentElement.getAttribute(arguments[0]);"
        verdict = {k: d.execute_script(g, "data-ctls-" + k)
                   for k in ("ok", "reason", "ms", "tee")}
    finally:
        try:
            d.quit()
        except Exception:
            pass

    redirected = final.startswith(a.expect_backend)
    attested = verdict.get("ok") == "1" and (verdict.get("tee") or "none") != "none"
    print(f"entry            : {a.entry}")
    print(f"final URL        : {final}")
    print(f"page title       : {title}")
    print(f"extension verdict: {verdict}")
    print(f"redirected->backend: {redirected}")
    print(f"attested         : {attested}")
    ok = redirected and attested
    print("RESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
