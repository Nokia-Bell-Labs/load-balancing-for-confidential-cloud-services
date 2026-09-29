// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Janus background page — client-side attestation gate.
 *
 * For every HTTPS response we pull the negotiated leaf certificate via
 * webRequest.getSecurityInfo and run JanusValidator.validate on it.  The
 * attestation verdict is cached per origin (host:port) so only the *first*
 * request to a site pays the validation cost; sub-resources reuse the verdict.
 * This matches the measured "page load time" model: attestation is a one-off
 * per-origin establishment cost, not a per-request tax.
 *
 * Two operating modes (JanusStore settings):
 *   - monitor  (enforcedHosts empty): always allow; badge shows the verdict.
 *   - enforce  (origin in enforcedHosts): a missing/invalid attestation
 *     cancels the request and the tab is sent to blocked.html.
 *
 * Timing: each validation records performance.now() deltas and is exposed on
 * window.__ctls_timings (read by the page-load bench) and via runtime messaging.
 */

const TIMINGS = [];                       // ring of recent validations (for the page-load bench)
const MAA_HOSTS = new Set();              // issuer hosts we must NOT intercept (avoid recursion)

function noteMaaHost(settings) {
  for (const iss of settings.allowedIssuers || []) {
    try { MAA_HOSTS.add(new URL(iss).hostname); } catch (e) {}
  }
  try { MAA_HOSTS.add(new URL(settings.maaDefault).hostname); } catch (e) {}
}

function isEnforced(settings, hostport) {
  return (settings.enforcedHosts || []).some(h => {
    if (h.includes(":")) return h === hostport;
    return h === hostport.split(":")[0];           // host-only entry matches any port
  });
}

async function setBadge(tabId, verdict) {
  if (tabId < 0) return;
  const ok = verdict && verdict.ok;
  try {
    await browser.pageAction.show(tabId);
    await browser.pageAction.setTitle({
      tabId,
      title: ok ? "Janus: attested TEE (" + (verdict.claims.tee || "tee") + ")"
                : "Janus: " + (verdict ? verdict.reason : "no attestation"),
    });
  } catch (e) { /* pageAction unavailable for this tab */ }
}

// PAPER: §4.4 — the browser aborts the navigation if any check fails (evaluated on the response headers).
async function handleHeaders(details) {
  let settings;
  try { settings = await JanusStore.getSettings(); } catch (e) { return {}; }
  noteMaaHost(settings);

  const url = new URL(details.url);
  if (url.protocol !== "https:") return {};
  if (MAA_HOSTS.has(url.hostname)) return {};          // never gate the AS itself

  const hostport = JanusStore.originKey(details.url);
  const enforced = isEnforced(settings, hostport);

  // Cached verdict for this origin → no re-validation.
  let verdict = JanusStore.getVerdict(details.url);
  if (!verdict) {
    const t0 = performance.now();
    let info;
    try {
      info = await browser.webRequest.getSecurityInfo(
        details.requestId, { certificateChain: true, rawDER: true });
    } catch (e) {
      verdict = { ok: false, reason: "getSecurityInfo failed: " + e.message, claims: {} };
    }
    if (!verdict) {
      if (info.state !== "secure" || !info.certificates || !info.certificates.length) {
        verdict = { ok: false, reason: "connection not secure", claims: {} };
      } else {
        const leaf = Uint8Array.from(info.certificates[0].rawDER);
        verdict = await JanusValidator.validate(leaf, {
          allowedIssuers: settings.allowedIssuers,
          maaDefault: settings.maaDefault,
          expectedMrenclave: settings.expectedMrenclave,
          expectedMrsigner: settings.expectedMrsigner,
        });
      }
    }
    verdict.ms = performance.now() - t0;
    verdict.ts = Date.now();
    JanusStore.setVerdict(details.url, verdict);
    // Mirror to storage so the content-script reporter (and tests) can read it.
    try {
      browser.storage.local.set({ ["v:" + hostport]: {
        ok: verdict.ok, reason: verdict.reason, ms: verdict.ms,
        claims: verdict.claims, ts: verdict.ts, cold: !!verdict.coldJwks } });
    } catch (e) { /* storage unavailable */ }
    TIMINGS.push({ origin: hostport, ms: verdict.ms, ok: verdict.ok,
                   cold: !!verdict.coldJwks, reason: verdict.reason });
    if (TIMINGS.length > 200) TIMINGS.shift();
  }

  setBadge(details.tabId, verdict);

  if (enforced && !verdict.ok) {
    if (details.type === "main_frame") {
      const frag = encodeURIComponent(JSON.stringify(
        { host: hostport, error: verdict.reason }));
      browser.tabs.update(details.tabId, {
        url: browser.runtime.getURL("blocked.html") + "#" + frag,
      });
    }
    return { cancel: true };
  }
  return {};
}

// Gate at document granularity only: attestation binds the *origin*, so once a
// document's origin is verified its same-origin sub-resources inherit trust.
// Intercepting every sub-resource with a blocking round-trip would add needless
// per-request latency without changing the security decision.
browser.webRequest.onHeadersReceived.addListener(
  handleHeaders,
  { urls: ["https://*/*"], types: ["main_frame", "sub_frame"] },
  ["blocking", "responseHeaders"]);

// New navigation to an origin re-checks freshness: drop its cached verdict so
// the next request re-validates (the JWT/quote is per-connection fresh).
browser.webNavigation.onBeforeNavigate.addListener(d => {
  if (d.frameId === 0) {
    try { JanusStore.setVerdict(d.url, undefined); JanusStore._verdicts.delete(JanusStore.originKey(d.url)); }
    catch (e) {}
  }
});

// Expose verdicts/timings to the popup and the page-load bench.
browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "ctls-get-timings")
    return Promise.resolve({ timings: TIMINGS.slice() });
  if (msg && msg.type === "ctls-get-verdict")
    return Promise.resolve({ verdict: JanusStore._verdicts.get(msg.origin) || null });
  if (msg && msg.type === "ctls-clear")
    { JanusStore.clearVerdicts(); TIMINGS.length = 0; return Promise.resolve({ ok: true }); }
});
