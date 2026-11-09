# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
SEV-SNP attestation helpers for Azure CVMs.

Architecturally aligns with Janus's design (and faithful to the ATC paper's
"server gen, client verify" split): the CVM produces *raw* attestation
evidence; the verifier (Janus frontend, or HTTPA/2 / RATLS client) submits
that evidence to Azure MAA's /attest/SevSnpVm REST endpoint and verifies
the returned JWT.

Wire format produced by the CVM (length-prefixed binary, network byte order):

    bundle = hcl_len:4    | hcl_bytes      (HCL report, NV index 0x01400001)
           | chain_len:4  | pem_chain      (VCEK leaf || ASK || ARK, PEM)
           | qmsg_len:4   | tpm_quote_msg  (0 if no per-conn binding)
           | qsig_len:4   | tpm_quote_sig  (0 if no per-conn binding)

The chain is per-VM stable (chip ID + TCB version) and ships in-bundle so
the verifier needs no separate AMD KDS round trip. Caller may cache it
across connections via the `vcek_chain_cache` parameter to avoid the ~1 s
`snpguest fetch` cost on every handshake.

The verifier extracts the SEV-SNP report payload (offset 32, 1184 bytes) and
the boot-time runtime claims (offset 1216 + 20-byte runtime-data header,
length = ClaimSize) from the HCL report, then POSTs to:

    POST {maa_url}/attest/SevSnpVm?api-version=2022-08-01

with body:

    {
      "report": base64url(JSON_TEXT),
      "runtimeData": {"data": base64url(runtime_claims_json),
                      "dataType": "JSON"}
    }

where JSON_TEXT is:

    \\n        {
            "SnpReport" : "<base64url(snp_report_bytes)>",
            "VcekCertChain" : "<base64url(pem_chain_string)>"
        }


(whitespace formatting matches Microsoft's official sample request body).
The endpoint replies with an MAA-signed JWT whose claims include the
verified SEV-SNP fields (`x-ms-sevsnpvm-launchmeasurement`,
`x-ms-sevsnpvm-reportdata`, `x-ms-sevsnpvm-guestsvn`, ...).

Per-connection binding rides on the optional TPM2 quote
(qualifyingData = SHA256(nonce ‖ backend TLS public key)), which is verified
locally against the AK pub embedded in the runtime claims. The MAA endpoint
itself only verifies the SEV-SNP→AMD signature chain.

References:
  - Azure REST API: learn.microsoft.com/en-us/rest/api/attestation/
        attestation/attest-sev-snp-vm
  - Azure CVM Guest Attestation design:
        learn.microsoft.com/en-us/azure/confidential-computing/
        guest-attestation-confidential-virtual-machines-design
"""

from __future__ import annotations

import base64
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple

import requests

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DEFAULT_MAA_URL = os.environ.get(
    "MAA_URL", "https://sharedweu.weu.attest.azure.net"
)
MAA_API_VERSION = "2022-08-01"

# Azure-reserved TPM NV indexes (from Microsoft's design doc)
NV_HCL_REPORT  = "0x01400001"   # Azure-defined HCL report (SNP + runtime data)
NV_VTPM_AK_CERT = "0x01C101D0"  # AK certificate
PERSISTENT_AK_HANDLE = "0x81000003"  # vTPM AK persistent handle

# HCL report layout
HCL_HEADER_LEN = 32
SNP_REPORT_LEN = 1184      # AMD SEV-SNP report payload size
RUNTIME_HDR_LEN = 20       # DataSize|Version|ReportType|HashType|ClaimSize

# Backend code measurement: once per boot the Backend extends SHA-256 PCR 15
# with the Janus measurement, then the application measurement, and quotes
# only that PCR at registration.  The SNP launch measurement covers Azure's
# HCL/paravisor, not the guest: it is the CVM's launch measurement, compared only with an
# explicit expected value.
CODE_PCR = 15
CODE_PCR_SELECTION = f"sha256:{CODE_PCR}"
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B
_ZERO_PCR = bytes(32)
_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Third-party checkouts that the setup fetches into the janus package; their
# scripts are not Backend code (BoringSSL is measured as part of dc_proxy).
_MEASURE_SKIP_DIRS = frozenset({"__pycache__", "boringssl", "snpguest"})
_ABSENT_DIGEST = hashlib.sha256(b"absent").hexdigest()
# Janus scripts that set up and start the Backend, relative to the repository root.
_JANUS_SCRIPTS = ("deploy/backend_setup.sh", "janus/backend/*.sh")
# What Azure Attestation must state about the CVM; the guest has no expected value on Azure.
PLATFORM_CLAIMS = {
    "x-ms-attestation-type": "sevsnpvm",
    "x-ms-compliance-status": "azure-compliant-cvm",
    "x-ms-sevsnpvm-is-debuggable": False,
}


# -----------------------------------------------------------------------------
# Server-side: produce evidence
# -----------------------------------------------------------------------------

@dataclass
class SnpEvidence:
    """Raw evidence the CVM produces and ships to the verifier."""
    hcl_report:    bytes        # 2600 bytes from NV 0x01400001
    pem_chain:     bytes        # VCEK leaf || ASK || ARK, PEM concatenation
    tpm_quote_msg: bytes = b""  # for per-connection nonce binding
    tpm_quote_sig: bytes = b""  # signature over quote_msg by vTPM AK
    code_digest:   bytes = b""  # the two PCR 15 events, Janus || application (64 B); optional 5th field


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, **kw)


def read_hcl_report() -> bytes:
    """Read the HCL report from vTPM NV index 0x01400001 (~24 ms on Azure)."""
    # tpm2_nvread runs under `sudo` (because /dev/tpm0 is root-only), so any
    # file it writes ends up owned by root.  We pre-create an empty file as
    # the user, then sudo redirects its output there — the file's existing
    # ownership is preserved.
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "hcl.bin")
        open(out_path, "wb").close()  # touch as user
        _run(["sudo", "tpm2_nvread", NV_HCL_REPORT, "-C", "o", "-o", out_path])
        # If sudo reset ownership we can't read it; chmod for safety.
        try:
            _run(["sudo", "chmod", "644", out_path])
        except subprocess.CalledProcessError:
            pass
        with open(out_path, "rb") as fr:
            return fr.read()


def _detect_processor(default: str = "milan") -> str:
    """Map the host AMD EPYC generation to snpguest's --processor name so the
    fetched ASK/ARK matches the VCEK's signing key.  Mismatching this (e.g.
    fetching Milan CA for a Genoa VCEK) makes MAA reject the chain with
    "unable to get local issuer certificate".  Azure CC SKUs: 7xx3 -> Milan,
    9Vxx/9xx4 -> Genoa (e.g. the H100 NCC-ads box is EPYC 9V84)."""
    try:
        for line in open("/proc/cpuinfo"):
            if "model name" in line and "EPYC" in line:
                tok = line.split("EPYC", 1)[1].strip().split()[0]
                if tok[:1] == "9":
                    return "genoa"
                if tok[:1] == "7":
                    return "milan"
                break
    except Exception:
        pass
    return default


def fetch_vcek_chain(snp_report_path: str, processor: Optional[str] = None,
                      out_dir: Optional[str] = None,
                      snpguest_bin: str = "snpguest") -> bytes:
    """Fetch VCEK + ASK + ARK certificates from AMD KDS and return them
    concatenated as a single PEM bytestring (leaf-first ordering).

    Cacheable per VM lifetime — chain depends only on chip ID + TCB version.
    """
    if processor is None:
        processor = _detect_processor()
    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="snp_certs_")
    else:
        os.makedirs(out_dir, exist_ok=True)

    _run(["sudo", snpguest_bin, "fetch", "vcek", "pem", out_dir, snp_report_path])
    _run(["sudo", snpguest_bin, "fetch", "ca",   "pem", out_dir, processor])
    # Files end up root-owned; fix permissions so the user can read.
    try:
        _run(["sudo", "chmod", "-R", "a+r", out_dir])
    except subprocess.CalledProcessError:
        pass

    with open(os.path.join(out_dir, "vcek.pem"), "rb") as f: vcek = f.read()
    with open(os.path.join(out_dir, "ask.pem"),  "rb") as f: ask  = f.read()
    with open(os.path.join(out_dir, "ark.pem"),  "rb") as f: ark  = f.read()
    return vcek + ask + ark


# PAPER: §4.3 Step 3 — the binding value SHA-256(nonce ‖ backend TLS public key).
def registration_reportdata(nonce: Optional[bytes],
                            pubkey_spki_der: Optional[bytes] = None) -> bytes:
    """Backend-registration attestation binding (design.tex sec:design-backend,
    Steps 3/5): the TPM2_Quote qualifyingData (SNP) / REPORTDATA (SGX) =
    SHA256(nonce || backend TLS public key in SubjectPublicKeyInfo DER). This
    binds the quote to BOTH the frontend's challenge (freshness) AND this
    backend's TLS identity, so a fresh-but-substituted key cannot be admitted.

    The producer (backend, generating the quote) and the verifier (frontend, at
    registration) MUST call this with identical inputs — the same nonce bytes
    and the same SPKI DER — or the binding check fails. Returns the 32-byte
    digest. ``pubkey_spki_der=None`` reduces to SHA256(nonce) (freshness only),
    which is the legacy behaviour other callers (baselines, CLI) still use.
    """
    h = hashlib.sha256()
    h.update(nonce or b"")
    if pubkey_spki_der:
        h.update(pubkey_spki_der)
    return h.digest()


def make_tpm_quote(nonce: bytes,
                   pubkey_spki_der: Optional[bytes] = None,
                   ak_handle: str = PERSISTENT_AK_HANDLE,
                   pcrs: str = "sha256:0,1,2,3,4,5,6,7") -> Tuple[bytes, bytes]:
    """Generate a fresh TPM2_Quote signing PCR values + qualifyingData
    (= SHA256(nonce || backend_pub); see registration_reportdata) with the
    vTPM AK. Returns (quote_msg, quote_sig)."""
    qd = registration_reportdata(nonce, pubkey_spki_der).hex()
    with tempfile.TemporaryDirectory() as td:
        msg = os.path.join(td, "quote.msg")
        sig = os.path.join(td, "quote.sig")
        # touch outputs as user so sudo'd tpm2_quote writes into pre-owned files
        open(msg, "wb").close()
        open(sig, "wb").close()
        _run(["sudo", "tpm2_quote", "-c", ak_handle,
              "-l", pcrs, "-q", qd, "-m", msg, "-s", sig])
        try:
            _run(["sudo", "chmod", "644", msg, sig])
        except subprocess.CalledProcessError:
            pass
        with open(msg, "rb") as f: m = f.read()
        with open(sig, "rb") as f: s = f.read()
    return m, s


def _extend(pcr: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(pcr + digest).digest()


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _env_list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def _python_dist_entries(requirements_file: str) -> list[tuple[str, str]]:
    """The files of the installed distributions named in ``requirements_file``
    and of their dependencies (markers evaluated for this interpreter, no
    extras), labelled by distribution, version and path inside site-packages."""
    import importlib.metadata as md
    try:
        from packaging.requirements import Requirement
    except ImportError:
        from pip._vendor.packaging.requirements import Requirement

    def norm(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    todo = []
    with open(requirements_file) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                todo.append(Requirement(line).name)
    seen, entries = set(), []
    while todo:
        name = norm(todo.pop())
        if name in seen:
            continue
        seen.add(name)
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            entries.append((f"pydist:{name}:absent", _ABSENT_DIGEST))
            continue
        tag = f"pydist:{name}=={dist.version}"
        if dist.files is not None:
            rels = [str(f).replace(os.sep, "/") for f in dist.files]
        else:
            # A distro package without a RECORD: walk its top-level packages.
            site = str(dist.locate_file(""))
            rels = []
            for top_name in (dist.read_text("top_level.txt") or "").split():
                base = os.path.join(site, top_name)
                if os.path.isfile(base + ".py"):
                    rels.append(top_name + ".py")
                for top, dirs, names in os.walk(base):
                    dirs[:] = [d for d in dirs if d != "__pycache__"]
                    rels += [os.path.relpath(os.path.join(top, n), site).replace(os.sep, "/")
                             for n in names]
        for rel in rels:
            parts = rel.split("/")
            if (rel.startswith("..") or "__pycache__" in parts
                    or parts[0].endswith((".dist-info", ".egg-info"))):
                continue          # scripts outside site-packages, bytecode, install metadata
            path = str(dist.locate_file(rel))
            if os.path.isfile(path):
                entries.append((f"{tag}:{rel}", _file_sha256(path)))
        for req in dist.requires or []:
            r = Requirement(req)
            if r.marker is None or r.marker.evaluate({"extra": ""}):
                todo.append(r.name)
    return entries


def _app_entries(app_paths: list[str], root: str) -> list[tuple[str, str]]:
    """Every file of the configured application paths (files or directories,
    relative to the repository root or absolute).  A missing path is an error."""
    entries = []
    for p in app_paths:
        full = p if os.path.isabs(p) else os.path.join(root, p)
        if os.path.isfile(full):
            entries.append((f"app:{p}", _file_sha256(full)))
        elif os.path.isdir(full):
            for top, dirs, names in os.walk(full):
                dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
                for n in names:
                    path = os.path.join(top, n)
                    if os.path.isfile(path):
                        rel = os.path.relpath(path, full).replace(os.sep, "/")
                        entries.append((f"app:{p.rstrip('/')}/{rel}", _file_sha256(path)))
        else:
            raise FileNotFoundError(f"application path to measure not found: {p}")
    return entries


def _image_entries(images: list[str]) -> list[tuple[str, str]]:
    """The image ID (content digest) of every configured container image."""
    entries = []
    for ref in images:
        image_id = _run(["sudo", "docker", "image", "inspect", "--format", "{{.Id}}", ref],
                        text=True).stdout.strip()
        if not image_id.startswith("sha256:"):
            raise RuntimeError(f"no image ID for container image {ref}: {image_id!r}")
        entries.append((f"image:{ref}", image_id[len("sha256:"):]))
    return entries


def janus_measurement_entries(package_dir: str = _PACKAGE_DIR,
                              snpguest: Optional[str] = None
                              ) -> list[tuple[str, str]]:
    """Everything the Janus measurement covers, as sorted ``(label,
    sha256-hex)`` pairs:

    - ``janus:``  every ``.py`` file of the ``janus`` package, except the
      third-party checkouts that the setup fetches into it (BoringSSL for
      dc_proxy, snpguest): their scripts never run in the Backend;
    - ``bin:``    the dc_proxy binary (with BoringSSL linked in) and the
      snpguest binary (``snpguest``, default: the one on ``PATH``), if present;
    - ``script:`` the Janus scripts that set up and start the Backend;
    - ``pydist:`` the files of the Python distributions in
      ``backend/requirements.txt`` and of their dependencies.
    """
    root = os.path.dirname(package_dir)
    entries = []
    for top, dirs, names in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d not in _MEASURE_SKIP_DIRS]
        for name in names:
            if name.endswith(".py"):
                path = os.path.join(top, name)
                rel = os.path.relpath(path, package_dir).replace(os.sep, "/")
                entries.append((f"janus:{rel}", _file_sha256(path)))
    dc_proxy = os.path.join(package_dir, "backend", "dc_proxy", "dc_proxy")
    if os.path.isfile(dc_proxy):
        entries.append(("bin:dc_proxy", _file_sha256(dc_proxy)))
    snpguest = snpguest if snpguest is not None else shutil.which("snpguest")
    if snpguest and os.path.isfile(snpguest):
        entries.append(("bin:snpguest", _file_sha256(snpguest)))
    for pattern in _JANUS_SCRIPTS:
        for path in sorted(glob.glob(os.path.join(root, pattern))):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append((f"script:{rel}", _file_sha256(path)))
    requirements = os.path.join(package_dir, "backend", "requirements.txt")
    if os.path.isfile(requirements):
        entries += _python_dist_entries(requirements)
    return sorted(entries)


def app_measurement_entries(app_paths: Optional[list[str]] = None,
                            app_images: Optional[list[str]] = None,
                            root: str = os.path.dirname(_PACKAGE_DIR)
                            ) -> list[tuple[str, str]]:
    """Everything the application measurement covers, as sorted ``(label,
    sha256-hex)`` pairs:

    - ``app:``    the files of the application paths (``JANUS_APP_MEASURE``),
      relative to ``root`` (the repository root) or absolute;
    - ``image:``  the image IDs of the application containers
      (``JANUS_APP_IMAGES``).

    ``app_paths``/``app_images`` default to these comma-separated variables.
    """
    if app_paths is None:
        app_paths = _env_list("JANUS_APP_MEASURE")
    if app_images is None:
        app_images = _env_list("JANUS_APP_IMAGES")
    return sorted(_app_entries(app_paths, root) + _image_entries(app_images))


def measurement_digest(entries: list[tuple[str, str]]) -> bytes:
    """SHA-256 over the ``(label, sha256-hex)`` pairs, in the given order."""
    h = hashlib.sha256()
    for label, hexdigest in entries:
        h.update(label.encode("utf-8") + b"\0" + bytes.fromhex(hexdigest))
    return h.digest()


def summarize_measurement(entries: list[tuple[str, str]]) -> str:
    """One line: how many items of each kind a measurement covers."""
    kinds = [label.split(":", 1)[0] for label, _ in entries]
    dists = {label.split(":")[1] for label, _ in entries if label.startswith("pydist:")}
    bins = [label.split(":", 1)[1] for label, _ in entries if label.startswith("bin:")]
    parts = []
    if kinds.count("janus") or bins or kinds.count("script") or dists:
        parts += [f"{kinds.count('janus')} Janus files",
                  f"binaries: {', '.join(bins) or 'none'}",
                  f"{kinds.count('script')} setup scripts",
                  f"{len(dists)} Python distributions ({kinds.count('pydist')} files)"]
    if kinds.count("app") or kinds.count("image"):
        parts += [f"{kinds.count('app')} application files",
                  f"{kinds.count('image')} container images"]
    return ", ".join(parts) or "nothing"


def code_pcr_value(janus_digest: bytes, app_digest: bytes) -> bytes:
    """PCR 15 after the two events of a boot: Janus, then the application."""
    return _extend(_extend(_ZERO_PCR, janus_digest), app_digest)


def extend_code_pcr(janus_digest: bytes, app_digest: bytes) -> None:
    """Record the Janus and application measurements as the two PCR 15 events
    of this boot, in that order.  A restart on the same code finds them
    already there; other code needs a reboot."""
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "pcr.bin")
        open(out, "wb").close()
        _run(["sudo", "tpm2_pcrread", CODE_PCR_SELECTION, "-o", out])
        with open(out, "rb") as f:
            current = f.read()
    if current == code_pcr_value(janus_digest, app_digest):
        return
    if current != _ZERO_PCR:
        raise RuntimeError(f"PCR {CODE_PCR} already records other code; "
                           "reboot the CVM to measure this code")
    for digest in (janus_digest, app_digest):
        _run(["sudo", "tpm2_pcrextend", f"{CODE_PCR}:sha256={digest.hex()}"])


# PAPER: §4.3 Step 3 — SEV-SNP evidence: HCL report + VCEK chain + vTPM quote whose qualifyingData carries the binding.
def build_snp_evidence_bundle(nonce: Optional[bytes] = None,
                              pubkey_spki_der: Optional[bytes] = None,
                              vcek_chain_cache: Optional[bytes] = None,
                              processor: Optional[str] = None,
                              code_digests: Optional[Tuple[bytes, bytes]] = None) -> bytes:
    """Produce the wire-format evidence bundle.

    Wire format:
        hcl_len:4   | hcl_report (~2600 B)
        | chain_len:4 | pem_chain (VCEK || ASK || ARK, ~6.5 KB)
        | qmsg_len:4  | tpm_quote_msg (~0.4 KB if nonce given, else 0)
        | qsig_len:4  | tpm_quote_sig
        [| code_len:4 | janus_digest || app_digest (64 B)]   only with code_digests

    Args:
        nonce: per-connection bytes; SHA256(nonce ‖ pubkey_spki_der) becomes the
            TPM2_Quote's qualifyingData.  If None or empty, no quote is generated
            and the bundle has empty TPM quote fields.
        pubkey_spki_der: the backend's TLS public key (SubjectPublicKeyInfo DER)
            folded into the qualifyingData alongside the nonce, binding the quote
            to this backend's TLS identity (see registration_reportdata).
        vcek_chain_cache: pass a previously-fetched chain (e.g. from a
            previous connection's bundle) to skip the ~1 s `snpguest fetch`
            on every call.  Per-VM stable, so caching across the lifetime
            of the CVM is safe.
        processor: "milan" (default), "genoa", "bergamo", "siena", "turin"
        code_digests: the (Janus, application) measurements already extended
            into PCR 15 by extend_code_pcr(); the quote then covers PCR 15
            only and both digests are appended as a fifth field.  Needs a nonce.
    """
    if code_digests is not None and not nonce:
        raise ValueError("a code measurement needs a nonce-bound quote")
    hcl = read_hcl_report()

    if vcek_chain_cache is not None:
        chain = vcek_chain_cache
    else:
        with tempfile.TemporaryDirectory() as td:
            rep_path = os.path.join(td, "snp_report.bin")
            # snpguest fetch reads the SNP report from a file to learn TCB
            # version; the report is the first 1184 bytes of the SNP payload
            # inside the HCL report.
            snp_payload = hcl[HCL_HEADER_LEN:HCL_HEADER_LEN + SNP_REPORT_LEN]
            with open(rep_path, "wb") as f:
                f.write(snp_payload)
            chain = fetch_vcek_chain(rep_path, processor=processor, out_dir=td)

    if code_digests is not None:
        qmsg, qsig = make_tpm_quote(nonce, pubkey_spki_der, pcrs=CODE_PCR_SELECTION)
    elif nonce:
        qmsg, qsig = make_tpm_quote(nonce, pubkey_spki_der)
    else:
        qmsg, qsig = b"", b""

    bundle = (struct.pack(">I", len(hcl))   + hcl
            + struct.pack(">I", len(chain)) + chain
            + struct.pack(">I", len(qmsg))  + qmsg
            + struct.pack(">I", len(qsig))  + qsig)
    if code_digests is not None:
        code = b"".join(code_digests)
        bundle += struct.pack(">I", len(code)) + code
    return bundle


def parse_snp_evidence_bundle(bundle: bytes) -> SnpEvidence:
    """Inverse of build_snp_evidence_bundle()."""
    p = 0
    def read_lp() -> bytes:
        nonlocal p
        if p + 4 > len(bundle):
            raise ValueError("bundle truncated")
        n = struct.unpack(">I", bundle[p:p+4])[0]
        p += 4
        if p + n > len(bundle):
            raise ValueError(f"bundle truncated at length-prefixed field of {n}")
        b = bundle[p:p+n]
        p += n
        return b
    hcl   = read_lp()
    chain = read_lp()
    qmsg  = read_lp()
    qsig  = read_lp()
    # Legacy readers ignore trailing bytes; only an exact length-prefixed field is the code digest.
    code = b""
    if p + 4 <= len(bundle) and p + 4 + struct.unpack(">I", bundle[p:p+4])[0] == len(bundle):
        code = read_lp()
    return SnpEvidence(hcl_report=hcl, pem_chain=chain,
                       tpm_quote_msg=qmsg, tpm_quote_sig=qsig, code_digest=code)


# -----------------------------------------------------------------------------
# Verifier-side: validate via MAA REST + (optional) local TPM quote check
# -----------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    if isinstance(b, str): b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _split_hcl(hcl: bytes) -> Tuple[bytes, bytes]:
    """Return (snp_report_bytes, runtime_claims_json_bytes)."""
    if len(hcl) < HCL_HEADER_LEN + SNP_REPORT_LEN + RUNTIME_HDR_LEN:
        raise ValueError("HCL report too short")
    snp = hcl[HCL_HEADER_LEN:HCL_HEADER_LEN + SNP_REPORT_LEN]
    rt  = hcl[HCL_HEADER_LEN + SNP_REPORT_LEN:]
    # runtime header is little-endian, 5 x uint32
    _, _, _, _, claim_size = struct.unpack("<IIIII", rt[:RUNTIME_HDR_LEN])
    claims = rt[RUNTIME_HDR_LEN:RUNTIME_HDR_LEN + claim_size]
    return snp, claims


def _build_maa_request(snp_report: bytes, pem_chain: bytes,
                       runtime_claims: bytes) -> dict:
    """Construct the MAA /attest/SevSnpVm request body.
    Format matches Microsoft's official sample (whitespace-formatted inner JSON,
    base64url throughout)."""
    inner = (
        "\n        {\n"
        f'            "SnpReport" : "{_b64url(snp_report)}",\n'
        f'            "VcekCertChain" : "{_b64url(pem_chain)}"\n'
        "        }\n"
        "        "
    )
    return {
        "report": _b64url(inner.encode()),
        "runtimeData": {
            "data": _b64url(runtime_claims),
            "dataType": "JSON",
        },
    }


# A relying party that verifies many connections keeps ONE keep-alive TLS
# connection to the attestation service rather than re-doing DNS+TCP+TLS on every
# verification (that setup, ~180 ms at 40 ms RTT, otherwise dominates the
# per-connection cost).  Pooling here models that optimized verifier.
_MAA_SESSION: Optional[requests.Session] = None


def _maa_session() -> requests.Session:
    global _MAA_SESSION
    if _MAA_SESSION is None:
        _MAA_SESSION = requests.Session()
    return _MAA_SESSION


def submit_to_maa(snp_report: bytes, pem_chain: bytes, runtime_claims: bytes,
                  maa_url: str = DEFAULT_MAA_URL,
                  api_version: str = MAA_API_VERSION,
                  timeout: int = 20) -> str:
    """POST evidence to MAA /attest/SevSnpVm; return the verified JWT string."""
    url = f"{maa_url.rstrip('/')}/attest/SevSnpVm?api-version={api_version}"
    body = _build_maa_request(snp_report, pem_chain, runtime_claims)
    # MAA_NO_POOL=1 forces a fresh, un-pooled HTTPS connection per verification
    # (full DNS+TCP+TLS each call) -> models a cold one-shot verifier. Default
    # uses the keep-alive session -> models an optimized repeat verifier.
    if os.environ.get("MAA_NO_POOL") == "1":
        r = requests.post(url, json=body, timeout=timeout)
    else:
        r = _maa_session().post(url, json=body, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"MAA returned HTTP {r.status_code}: {r.text[:300]}")
    tok = r.json().get("token", "")
    if not tok:
        raise RuntimeError("MAA response missing token")
    return tok


def parse_jwt_claims(jwt_token: str) -> dict:
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError(f"malformed JWT ({len(parts)} parts)")
    return json.loads(_b64url_decode(parts[1]))


# PAPER: §4.3 Steps 5–6 — frontend-side verification: AS (MAA) validates the report; the vTPM quote binds nonce + key.
def verify_snp_bundle(bundle: bytes,
                      expected_nonce: Optional[bytes] = None,
                      expected_pubkey_spki_der: Optional[bytes] = None,
                      expected_measurement: Optional[str] = None,
                      maa_url: str = DEFAULT_MAA_URL,
                      logger: Optional[logging.Logger] = None,
                      verify_tpm_quote: bool = True,
                      require_code_measurement: bool = False,
                      expected_janus_measurement: Optional[str] = None,
                      expected_app_measurement: Optional[str] = None,
                      expected_cvm_measurement: Optional[str] = None
                      ) -> Tuple[bool, dict]:
    """Verify an SEV-SNP evidence bundle produced by build_snp_evidence_bundle.

    Returns (verified, info_dict). On failure, info_dict["error"] holds a
    human-readable reason; on success, info_dict contains the MAA-verified
    claims plus a nonce-binding decision.

    Steps:
      1. Parse the bundle.
      2. Submit (SnpReport, VcekCertChain) to MAA /attest/SevSnpVm with
         runtime claims as runtimeData; receive an MAA-signed JWT.
      3. Optional: enforce policy (expected_measurement).
      4. Optional: verify TPM2 quote signature against AK pub from the JWT
         claims, and check qualifyingData == SHA256(expected_nonce ‖ expected
         backend TLS public key).

    With ``require_code_measurement`` (Backend admission) the MAA claims must
    meet PLATFORM_CLAIMS, and the Backend identity is three values: the CVM's
    launch measurement, and the Janus and application
    measurements, proven by the quote over PCR 15 (two extends from zero, in
    that order).  Each is compared with its ``expected_*`` value when set
    ("sha256:<hex>" or "<hex>"); ``expected_measurement`` is then unused.
    """
    log = logger or logging.getLogger("snp_attestation")

    try:
        ev = parse_snp_evidence_bundle(bundle)
        snp_report, runtime_claims = _split_hcl(ev.hcl_report)
    except Exception as exc:
        return False, {"error": f"bundle parse failed: {exc}"}

    try:
        jwt_token = submit_to_maa(snp_report, ev.pem_chain, runtime_claims,
                                   maa_url=maa_url)
        claims = parse_jwt_claims(jwt_token)
    except Exception as exc:
        return False, {"error": f"MAA verification failed: {exc}"}

    launch = claims.get("x-ms-sevsnpvm-launchmeasurement", "")
    if require_code_measurement:
        failed = platform_claim_failures(claims)
        if failed:
            return False, {"error": "the CVM is not a compliant, non-debuggable SEV-SNP VM: "
                                    + ", ".join(failed), "claims": claims}
        if not ev.tpm_quote_msg or expected_nonce is None or len(ev.code_digest) != 64:
            return False, {"error": "evidence carries no nonce-bound code measurement",
                           "claims": claims}
        janus_digest, app_digest = ev.code_digest[:32], ev.code_digest[32:]
        measured = {"cvm": launch,
                    "janus": "sha256:" + janus_digest.hex(),
                    "app": "sha256:" + app_digest.hex()}
        for kind, wanted, got in (("CVM", expected_cvm_measurement, launch),
                                  ("JANUS", expected_janus_measurement, janus_digest.hex()),
                                  ("APP", expected_app_measurement, app_digest.hex())):
            if wanted and _strip_sha256(wanted) != got.lower():
                return False, {"error": f"{kind} MEASUREMENT mismatch",
                               "expected": wanted, "got": got, "claims": claims}
    else:
        measured = launch
        # Policy: measurement match (if requested)
        if expected_measurement and expected_measurement.lower() != measured.lower():
            return False, {"error": "MEASUREMENT mismatch",
                           "expected": expected_measurement, "got": measured,
                           "claims": claims}

    # NOTE: MAA's `reportdata` claim is the *static* boot-time value
    # (= SHA256(AK pub hash || boot config)) — not a per-connection nonce.
    # Per-connection freshness rides on the TPM2 quote below, if present.

    info = {"verified": True, "token": jwt_token, "claims": claims,
            "measurement": measured,
            "launch_measurement": launch,
            "guestsvn":     claims.get("x-ms-sevsnpvm-guestsvn"),
            "is_debuggable": claims.get("x-ms-sevsnpvm-is-debuggable")}

    if (verify_tpm_quote or require_code_measurement) and \
            (ev.tpm_quote_msg or expected_nonce is not None):
        info["tpm_quote_supplied"] = bool(ev.tpm_quote_msg)
        if expected_nonce is not None and not ev.tpm_quote_msg:
            return False, {"error": "expected_nonce set but no TPM quote in "
                           "bundle — cannot verify per-connection freshness",
                           "claims": claims}
        # MAA has already bound the runtime claims (which carry the vTPM AK
        # public key) to the genuine SNP hardware via report_data, so the AK
        # pub is trustworthy.  Verify the TPM2_Quote signature with that AK
        # and check qualifyingData == SHA256(nonce ‖ backend public key) to
        # complete the per-connection freshness + backend-identity binding.
        try:
            _verify_tpm_quote(ev.tpm_quote_msg, ev.tpm_quote_sig,
                              runtime_claims, expected_nonce,
                              expected_pubkey_spki_der)
            info["tpm_quote_verified"] = True
        except Exception as exc:
            return False, {"error": f"TPM quote verification failed: {exc}",
                           "claims": claims}

    if require_code_measurement:
        try:
            _verify_code_pcr(ev.tpm_quote_msg, janus_digest, app_digest)
        except Exception as exc:
            return False, {"error": f"code measurement verification failed: {exc}",
                           "claims": claims}

    return True, info


def platform_claim_failures(claims: dict) -> list:
    """The PLATFORM_CLAIMS that the MAA claims do not meet, by name."""
    failed = []
    for name, wanted in PLATFORM_CLAIMS.items():
        got = claims.get(name)
        if type(got) is not type(wanted) or got != wanted:
            failed.append(f"{name}={got!r}")
    return failed


def _strip_sha256(value: str) -> str:
    value = value.strip().lower()
    return value[len("sha256:"):] if value.startswith("sha256:") else value


def _verify_code_pcr(quote_msg: bytes, janus_digest: bytes, app_digest: bytes) -> None:
    """The (already AK-verified) quote selects exactly SHA-256 PCR 15 and its
    pcrDigest is that of PCR 15 after extending ``janus_digest`` then
    ``app_digest`` from zero."""
    try:
        magic, kind = struct.unpack_from(">IH", quote_msg, 0)
        if magic != 0xFF544347 or kind != TPM_ST_ATTEST_QUOTE:
            raise ValueError("the attestation is not a TPM2 quote")
        off = 6
        for _ in range(2):  # qualifiedSigner, extraData
            size, = struct.unpack_from(">H", quote_msg, off)
            off += 2 + size
        off += 17 + 8  # clockInfo, firmwareVersion
        count, = struct.unpack_from(">I", quote_msg, off)
        off += 4
        selected = set()
        for _ in range(count):
            alg, size = struct.unpack_from(">HB", quote_msg, off)
            off += 3
            bitmap = quote_msg[off:off + size]
            off += size
            indices = {8 * i + b for i, bits in enumerate(bitmap) for b in range(8) if bits >> b & 1}
            if indices and alg != TPM_ALG_SHA256:
                raise ValueError("the quote selects a bank other than SHA-256")
            selected |= indices
        size, = struct.unpack_from(">H", quote_msg, off)
        pcr_digest = quote_msg[off + 2:off + 2 + size]
    except struct.error as exc:
        raise ValueError("the quote is truncated") from exc
    if selected != {CODE_PCR}:
        raise ValueError(f"the quote does not select exactly SHA-256 PCR {CODE_PCR}")
    if hashlib.sha256(code_pcr_value(janus_digest, app_digest)).digest() != pcr_digest:
        raise ValueError(f"PCR {CODE_PCR} does not hold exactly these Janus and application measurements")


# PAPER: §4.3 Step 5 — check the quote's qualifyingData == SHA-256(nonce ‖ public key) under the attested AK.
def _verify_tpm_quote(quote_msg: bytes, quote_sig: bytes,
                      runtime_claims_json: bytes,
                      expected_nonce: bytes,
                      expected_pubkey_spki_der: Optional[bytes] = None) -> None:
    """Verify a vTPM TPM2_Quote: AK signature + qualifyingData binding.

    Raises on any failure.  The quote is signed by the CVM's vTPM Attestation
    Key (whose public key is in the MAA-validated runtime claims) over a
    TPMS_ATTEST structure whose extraData (qualifyingData) must equal
    registration_reportdata(expected_nonce, expected_pubkey_spki_der) — i.e.
    SHA256(nonce || backend_pub) when the public key is supplied, binding both
    freshness and the backend's TLS identity.
    """
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    # 1. AK public key from the runtime claims (kid == "HCLAkPub").
    claims = json.loads(runtime_claims_json)
    ak = next((k for k in claims.get("keys", [])
               if k.get("kid") == "HCLAkPub"), None)
    if not ak or ak.get("kty") != "RSA":
        raise ValueError("HCLAkPub RSA key not found in runtime claims")
    n = int.from_bytes(_b64url_decode(ak["n"]), "big")
    e = int.from_bytes(_b64url_decode(ak["e"]), "big")
    ak_pub = _rsa.RSAPublicNumbers(e, n).public_key()

    # 2. Parse TPMT_SIGNATURE: sigAlg(2) hashAlg(2) [RSA: sigSize(2) sig].
    if len(quote_sig) < 6:
        raise ValueError("TPM quote signature too short")
    sig_alg, hash_alg, sig_size = struct.unpack(">HHH", quote_sig[:6])
    if hash_alg != 0x000B:  # TPM_ALG_SHA256
        raise ValueError(f"unsupported TPM quote hash alg 0x{hash_alg:04x}")
    sig = quote_sig[6:6 + sig_size]
    if len(sig) != sig_size:
        raise ValueError("TPM quote signature truncated")
    if sig_alg == 0x0014:    # TPM_ALG_RSASSA (PKCS#1 v1.5)
        scheme = _pad.PKCS1v15()
    elif sig_alg == 0x0016:  # TPM_ALG_RSAPSS
        scheme = _pad.PSS(mgf=_pad.MGF1(_hashes.SHA256()),
                          salt_length=_hashes.SHA256().digest_size)
    else:
        raise ValueError(f"unsupported TPM quote sig alg 0x{sig_alg:04x}")

    # 3. Verify the AK signature over the quoted message.
    ak_pub.verify(sig, quote_msg, scheme, _hashes.SHA256())

    # 4. Extract qualifyingData (extraData) from the TPMS_ATTEST structure and
    #    check the per-connection binding.  Layout:
    #      magic(4) type(2) qualifiedSigner:TPM2B_NAME(size2+name)
    #      extraData:TPM2B_DATA(size2+data) ...
    if len(quote_msg) < 8 or quote_msg[:4] != b"\xff\x54\x43\x47":
        raise ValueError("bad TPM_GENERATED magic in quote message")
    off = 6
    name_len = struct.unpack(">H", quote_msg[off:off + 2])[0]
    off += 2 + name_len
    ed_len = struct.unpack(">H", quote_msg[off:off + 2])[0]
    off += 2
    extra = quote_msg[off:off + ed_len]
    expected_qd = registration_reportdata(expected_nonce, expected_pubkey_spki_der)
    if extra != expected_qd:
        raise ValueError("qualifyingData mismatch: quote is not bound to this "
                         "registration's nonce (+ backend public key)")


if __name__ == "__main__":
    # python3 -m janus.common.snp_attestation [--list] [--app PATH] [--image REF]
    # prints the values for the frontend's EXPECTED_JANUS_MEASUREMENT and
    # EXPECTED_APP_MEASUREMENT.
    import argparse
    ap = argparse.ArgumentParser(
        description="Print the Backend's Janus and application measurements "
                    "(EXPECTED_JANUS_MEASUREMENT, EXPECTED_APP_MEASUREMENT). Run it on a "
                    "backend set up from the release and package, with the same "
                    "JANUS_APP_MEASURE / JANUS_APP_IMAGES settings.")
    ap.add_argument("--list", action="store_true", help="list every measured item")
    ap.add_argument("--app", action="append",
                    help="application file or directory (default: $JANUS_APP_MEASURE)")
    ap.add_argument("--image", action="append",
                    help="application container image (default: $JANUS_APP_IMAGES)")
    args = ap.parse_args()
    for name, measured in (
            ("EXPECTED_JANUS_MEASUREMENT", janus_measurement_entries()),
            ("EXPECTED_APP_MEASUREMENT", app_measurement_entries(args.app, args.image))):
        if args.list:
            for item, digest in measured:
                print(digest, item)
        print(f"{name}=sha256:{measurement_digest(measured).hex()}  ({summarize_measurement(measured)})")
