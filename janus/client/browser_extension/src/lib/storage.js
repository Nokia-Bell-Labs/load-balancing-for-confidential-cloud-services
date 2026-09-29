// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Persistent settings + the per-origin verdict cache.
 *
 * Settings (browser.storage.local):
 *   enforcedHosts   : ["host[:port]", ...] origins where attestation is REQUIRED
 *                     (a plain or failed-attestation TLS connection is blocked).
 *                     Empty ⇒ "monitor mode": validate + badge, never block.
 *   allowedIssuers  : trusted MAA issuer prefixes.
 *   expectedMrenclave / expectedMrsigner : optional measurement policy.
 *   maaDefault      : fallback issuer if a JWT omits `iss`.
 */

const JanusStore = (() => {
  const DEFAULTS = {
    enforcedHosts: [],
    allowedIssuers: ["https://sharedweu.weu.attest.azure.net",
                     "https://sharedeus.eus.attest.azure.net"],
    expectedMrenclave: "",
    expectedMrsigner: "",
    maaDefault: "https://sharedweu.weu.attest.azure.net",
  };

  async function getSettings() {
    const got = await browser.storage.local.get(Object.keys(DEFAULTS));
    return Object.assign({}, DEFAULTS, got);
  }
  async function setSettings(patch) {
    await browser.storage.local.set(patch);
  }

  // Verdict cache lives in memory only (cleared on browser restart): a map
  // "host:port" -> { ok, reason, claims, ts, leafSha }.
  const verdicts = new Map();
  function originKey(url) {
    const u = new URL(url);
    return u.hostname + ":" + (u.port || (u.protocol === "https:" ? "443" : "80"));
  }
  function getVerdict(url) { return verdicts.get(originKey(url)); }
  function setVerdict(url, v) { verdicts.set(originKey(url), v); }
  function clearVerdicts() { verdicts.clear(); }

  return { DEFAULTS, getSettings, setSettings, originKey,
           getVerdict, setVerdict, clearVerdicts, _verdicts: verdicts };
})();

if (typeof module !== "undefined") module.exports = JanusStore;
