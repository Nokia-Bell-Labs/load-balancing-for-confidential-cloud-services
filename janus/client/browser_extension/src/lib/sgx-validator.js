// © 2026 Nokia
// Licensed under the BSD 3-Clause Clear License
// SPDX-License-Identifier: BSD-3-Clause-Clear

/* End-to-end client-side Janus attestation validation.
 *
 * Given the leaf certificate's raw DER (from webRequest.getSecurityInfo) this
 * runs the full check the Janus client performs, mirroring
 * janus/client/attest.py::verify_reportdata_ctls:
 *
 *   1. extract the AS-issued JWT from the leaf cert (OID 1.3.6.1.4.1.99999.3.1)
 *   2. verify the MAA RS256 signature over the JWT (key from issuer JWKS)
 *   3. check the JWT validity window (nbf/exp)
 *   4. REPORTDATA binding: the attested runtime data (x-ms-sgx-ehd) must commit
 *      to the leaf certificate's public key — i.e. ehd decodes to the SPKI PEM
 *      of *this* cert.  We compare SHA256(ehd) == SHA256(leaf-SPKI-PEM), the
 *      same equality the Python client checks.
 *   5. (optional) enforce a measurement policy: expected MRENCLAVE / MRSIGNER.
 *
 * Returns { ok, reason, claims:{tee,mrenclave,mrsigner,iss,exp}, coldJwks }.
 */

const JanusValidator = (() => {
  // PAPER: §4.4 Checks 2–4 in the browser — AS JWT signature (WebCrypto), REPORTDATA binding, measurement policy.
  async function validate(leafDer, opts = {}) {
    const claims = {};
    try {
      const jwt = JanusX509.extractJwt(leafDer);
      const { header, payload, parts } = JanusJwt.parse(jwt);

      const iss = payload.iss || opts.maaDefault;
      const jku = header.jku || (iss && iss.replace(/\/$/, "") + "/certs");
      claims.iss = iss;
      claims.tee = payload.tee || payload["x-ms-attestation-type"];
      claims.mrenclave = payload["x-ms-sgx-mrenclave"] || payload["sgx-mrenclave"];
      claims.mrsigner = payload["x-ms-sgx-mrsigner"] || payload["sgx-mrsigner"];
      claims.exp = payload.exp;

      // Trust anchor: the JWT must come from an allowed MAA issuer.
      if (opts.allowedIssuers && opts.allowedIssuers.length &&
          !opts.allowedIssuers.some(a => (iss || "").startsWith(a)))
        return { ok: false, reason: "untrusted AS issuer: " + iss, claims };

      const { key, cold } = await JanusJwt.getKey(iss, header.kid, jku);
      await JanusJwt.verifySignature(parts, key);
      JanusJwt.checkValidity(payload);

      // REPORTDATA binding to the leaf cert's public key.
      const ehdB64 = payload["x-ms-sgx-ehd"];
      if (!ehdB64) return { ok: false, reason: "JWT missing x-ms-sgx-ehd", claims };
      const ehd = JanusUtil.b64urlToBytes(ehdB64);
      const spkiDer = JanusX509.extractSpkiDer(leafDer);
      const spkiPem = JanusUtil.strToBytes(JanusUtil.spkiDerToPem(spkiDer));
      const lhs = await JanusUtil.sha256(ehd);
      const rhs = await JanusUtil.sha256(spkiPem);
      // ehd carries the runtime PEM (>32 B): SHA256(ehd) must equal
      // SHA256(leaf SPKI PEM).  (Hash-only ehd path kept for the mock server.)
      const bound = ehd.length > 32
        ? JanusUtil.bytesEqual(lhs, rhs)
        : JanusUtil.bytesEqual(ehd.subarray(0, 32), rhs.subarray(0, 32));
      if (!bound) return { ok: false, reason: "REPORTDATA does not bind TLS key", claims };

      // Optional measurement policy.
      if (opts.expectedMrenclave &&
          (claims.mrenclave || "").toLowerCase() !== opts.expectedMrenclave.toLowerCase())
        return { ok: false, reason: "MRENCLAVE mismatch", claims };
      if (opts.expectedMrsigner &&
          (claims.mrsigner || "").toLowerCase() !== opts.expectedMrsigner.toLowerCase())
        return { ok: false, reason: "MRSIGNER mismatch", claims };

      return { ok: true, reason: "attested", claims, coldJwks: cold };
    } catch (e) {
      return { ok: false, reason: String(e && e.message || e), claims };
    }
  }

  return { validate };
})();

if (typeof module !== "undefined") module.exports = JanusValidator;
