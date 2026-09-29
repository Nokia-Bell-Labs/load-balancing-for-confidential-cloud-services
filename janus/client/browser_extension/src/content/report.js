// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Content script: surface the background's attestation verdict for this origin
 * onto the DOM so an automated client (the page-load bench) and tests can read it.
 *
 * Runs at document_idle (after load), so it does NOT affect page-load timing.
 * It reads the verdict the background page already stored under "v:<origin>".
 */
(async () => {
  try {
    const origin = location.hostname + ":" +
      (location.port || (location.protocol === "https:" ? "443" : "80"));
    const key = "v:" + origin;
    // Background may write slightly after onHeadersReceived; poll briefly.
    let v = null;
    for (let i = 0; i < 20 && !v; i++) {
      const got = await browser.storage.local.get(key);
      v = got[key];
      if (!v) await new Promise(r => setTimeout(r, 25));
    }
    const root = document.documentElement;
    if (v) {
      root.setAttribute("data-ctls-ok", v.ok ? "1" : "0");
      root.setAttribute("data-ctls-reason", v.reason || "");
      root.setAttribute("data-ctls-ms", v.ms != null ? String(v.ms) : "");
      root.setAttribute("data-ctls-tee", (v.claims && v.claims.tee) || "");
    } else {
      root.setAttribute("data-ctls-ok", "");
      root.setAttribute("data-ctls-reason", "no verdict");
    }
  } catch (e) {
    try { document.documentElement.setAttribute("data-ctls-reason", "cs-error:" + e.message); }
    catch (_) {}
  }
})();
