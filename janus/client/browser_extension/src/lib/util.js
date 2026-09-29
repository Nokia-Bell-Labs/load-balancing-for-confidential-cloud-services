// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Janus extension — low-level encoding/crypto helpers.
 *
 * Everything here is pure (no DOM, no browser.* API) so the same code runs
 * unchanged in the background page and could be unit-tested in a worker.
 * Crypto is the platform WebCrypto (crypto.subtle); we deliberately avoid
 * shipping a JS bigint/RSA implementation.
 */

const JanusUtil = (() => {
  function strToBytes(s) {
    return new TextEncoder().encode(s);
  }
  function bytesToStr(b) {
    return new TextDecoder().decode(b instanceof Uint8Array ? b : new Uint8Array(b));
  }

  // Standard base64 -> Uint8Array
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64(bytes) {
    let s = "";
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  // base64url (RFC 7515) -> bytes, tolerant of missing padding
  function b64urlToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return b64ToBytes(s);
  }
  function b64urlToStr(s) {
    return bytesToStr(b64urlToBytes(s));
  }

  function bytesToHex(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = "";
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return s;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  async function sha256(bytes) {
    const buf = await crypto.subtle.digest(
      "SHA-256", bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    return new Uint8Array(buf);
  }

  // DER SubjectPublicKeyInfo bytes -> OpenSSL/`cryptography`-style PEM string,
  // byte-for-byte: 64-col base64, "\n" separators, trailing newline. The Janus
  // frontend commits SHA256 of exactly this string in REPORTDATA.
  function spkiDerToPem(der) {
    const b64 = bytesToB64(der);
    const lines = b64.match(/.{1,64}/g) || [""];
    return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") +
           "\n-----END PUBLIC KEY-----\n";
  }

  return { strToBytes, bytesToStr, b64ToBytes, bytesToB64, b64urlToBytes,
           b64urlToStr, bytesToHex, bytesEqual, sha256, spkiDerToPem };
})();

if (typeof module !== "undefined") module.exports = JanusUtil;
