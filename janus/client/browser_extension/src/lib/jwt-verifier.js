// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* JWT (RS256) verification against an Azure MAA JWKS endpoint.
 *
 * Mirrors janus/client/attest.py: parse the compact JWT, fetch the
 * issuer's JWKS (cached by (issuer,kid) — the underlying RSA key is stable even
 * though MAA re-wraps the x5c envelope frequently), import the (n,e) key into
 * WebCrypto and verify RSASSA-PKCS1-v1_5 / SHA-256 over `header.payload`.
 */

const JanusJwt = (() => {
  // (issuer|kid) -> CryptoKey ; survives for the life of the background page.
  const keyCache = new Map();

  function parse(token) {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("malformed JWT");
    const header = JSON.parse(JanusUtil.b64urlToStr(parts[0]));
    const payload = JSON.parse(JanusUtil.b64urlToStr(parts[1]));
    return { header, payload, parts };
  }

  async function importJwkKey(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false, ["verify"]);
  }

  // Return a verify-capable CryptoKey for (issuer,kid), fetching JWKS on miss.
  async function getKey(issuer, kid, jku) {
    const ck = issuer + "|" + kid;
    if (keyCache.has(ck)) return { key: keyCache.get(ck), cold: false };
    const url = jku || (issuer.replace(/\/$/, "") + "/certs");
    const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
    if (!resp.ok) throw new Error("JWKS fetch failed: HTTP " + resp.status);
    const body = await resp.json();
    const jwk = (body.keys || []).find(k => k.kty === "RSA" && k.kid === kid);
    if (!jwk) throw new Error("kid not present in JWKS: " + kid);
    const key = await importJwkKey(jwk);
    keyCache.set(ck, key);
    return { key, cold: true };
  }

  async function verifySignature(parts, key) {
    const data = JanusUtil.strToBytes(parts[0] + "." + parts[1]);
    const sig = JanusUtil.b64urlToBytes(parts[2]);
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", key, sig, data);
    if (!ok) throw new Error("JWT signature verification failed");
  }

  function checkValidity(payload, skewSec = 60) {
    const now = Date.now() / 1000;
    if (payload.exp && now > payload.exp + skewSec)
      throw new Error("JWT expired");
    if (payload.nbf && now < payload.nbf - skewSec)
      throw new Error("JWT not yet valid");
  }

  return { parse, getKey, verifySignature, checkValidity, _keyCache: keyCache };
})();

if (typeof module !== "undefined") module.exports = JanusJwt;
