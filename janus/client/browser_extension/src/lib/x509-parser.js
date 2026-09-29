// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* Minimal DER / X.509 reader for the Janus extension.
 *
 * We only need two things out of the leaf certificate and we extract them
 * without pulling in a full ASN.1 library:
 *   1. the value of a custom extension identified by its OID
 *      (the AS-issued attestation JWT, OID 1.3.6.1.4.1.99999.3.1), and
 *   2. the SubjectPublicKeyInfo DER, used to recompute the REPORTDATA binding.
 *
 * The parser is a small TLV walker.  It handles definite-length, multi-byte
 * length encodings and constructed types, which is all an X.509 cert uses.
 */

const JanusX509 = (() => {
  // OID 1.3.6.1.4.1.99999.3.1 (Janus AS-JWT), DER *content* (no tag/len).
  const SGX_JWT_OID = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x03, 0x01];

  // Read one TLV starting at offset `off`. Returns {tag, hdr, len, start, end}
  // where [start,end) is the content and [off,end) is the whole element.
  function readTLV(buf, off) {
    const tag = buf[off];
    let i = off + 1;
    let len = buf[i++];
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
    }
    return { tag, hdr: i - off, len, start: i, end: i + len };
  }

  // Return the list of child TLVs of a constructed element body [start,end).
  function children(buf, start, end) {
    const out = [];
    let off = start;
    while (off < end) {
      const t = readTLV(buf, off);
      out.push(t);
      off = t.end;
    }
    return out;
  }

  function oidMatches(buf, t, oidContent) {
    if (t.tag !== 0x06 || t.len !== oidContent.length) return false;
    for (let k = 0; k < oidContent.length; k++) {
      if (buf[t.start + k] !== oidContent[k]) return false;
    }
    return true;
  }

  // Parse the cert and return {spkiDer: Uint8Array, extensions: [{oid TLV, value bytes}]}.
  function parse(der) {
    const buf = der instanceof Uint8Array ? der : new Uint8Array(der);
    const cert = readTLV(buf, 0);                       // Certificate SEQUENCE
    const tbs = readTLV(buf, cert.start);               // TBSCertificate SEQUENCE
    const top = children(buf, tbs.start, tbs.end);

    // Extensions live in the [3] context element (tag 0xA3), itself wrapping a
    // SEQUENCE OF Extension.
    const exts = [];
    const ctx3 = top.find(t => t.tag === 0xa3);
    if (ctx3) {
      const seq = readTLV(buf, ctx3.start);             // SEQUENCE OF Extension
      for (const ext of children(buf, seq.start, seq.end)) {
        const parts = children(buf, ext.start, ext.end); // OID [crit] OCTETSTRING
        const oid = parts[0];
        const octet = parts.find(p => p.tag === 0x04);
        if (oid && octet) {
          exts.push({ oid, valueStart: octet.start, valueEnd: octet.end });
        }
      }
    }
    return { buf, exts };
  }

  // High level: pull the AS JWT (string) out of the leaf cert.
  function extractJwt(der) {
    const p = parse(der);
    const e = p.exts.find(x => oidMatches(p.buf, x.oid, SGX_JWT_OID));
    if (!e) throw new Error("leaf certificate missing Janus AS-JWT extension");
    return JanusUtil.bytesToStr(p.buf.slice(e.valueStart, e.valueEnd));
  }

  // High level: SubjectPublicKeyInfo DER of the leaf cert.
  function extractSpkiDer(der) {
    const buf = der instanceof Uint8Array ? der : new Uint8Array(der);
    const cert = readTLV(buf, 0);
    const tbs = readTLV(buf, cert.start);
    const top = children(buf, tbs.start, tbs.end);
    const i = (top.length && top[0].tag === 0xa0) ? 1 : 0;
    const spki = top[i + 5];
    return buf.slice(spki.start - spki.hdr, spki.end); // include tag+len header
  }

  return { extractJwt, extractSpkiDer, SGX_JWT_OID };
})();

if (typeof module !== "undefined") module.exports = JanusX509;
