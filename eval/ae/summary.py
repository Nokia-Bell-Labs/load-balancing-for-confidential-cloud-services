#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Results summary of one run: the tables of the paper with the values measured in this run.

  summary.py --run <id> [--run-root <dir>] [--data <eval/data>] [--out results.md]

Prints aligned tables to the terminal, writes the same tables as Markdown, and one CSV per table
next to the Markdown file (tables/<name>.csv).
ae.py calls this at the end of `-m data` and in `-m figures`.
"""
import argparse, csv, glob, os, re, statistics, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PROTOS = [("vanilla", "TLS"), ("ctls_proxy", "Proxy"), ("ctls_redirect", "Redir."), ("ratls", "RA+TLS"), ("httpa", "HTTPA/2")]
APP_NAMES = {"vanilla": "vanilla", "ctls_proxy": "Janus-proxy", "ctls_redirect": "Janus-redirection", "ratls": "RA+TLS", "httpa": "HTTPA/2",
             "cTLS-proxy": "Janus-proxy", "cTLS-redirect": "Janus-redirection"}


def fmt(v, digits=1, unit=""):
    if v is None: return "-"
    return f"{v:.{digits}f}{unit}" if isinstance(v, float) else f"{v}{unit}"


def table(title, header, rows, note=None, key=None):
    """One table as (terminal text, markdown text, (key, header, rows))."""
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    line = lambda cells: "  " + "  ".join(str(c).rjust(w) if i else str(c).ljust(w) for i, (c, w) in enumerate(zip(cells, widths)))
    txt = [title, line(header), "  " + "  ".join("-" * w for w in widths)] + [line(r) for r in rows]
    md = [f"### {title}", "", "| " + " | ".join(header) + " |", "|" + "|".join(" ---: " if i else " --- " for i in range(len(header))) + "|"] + \
         ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    if note: txt.append("  " + note); md += ["", note]
    return "\n".join(txt) + "\n", "\n".join(md) + "\n", (key or re.sub(r"\W+", "_", title.split(":")[0]).strip("_").lower(), header, rows)


def med_mean(xs):
    return (statistics.median(xs), statistics.mean(xs)) if xs else (None, None)


def table2(data, run):
    rows = []
    for R in (0, 20, 40, 80, 120, 160):
        f = os.path.join(data, f"{run}-rtt-{R}", "summary.csv")
        got = {}
        if os.path.exists(f):
            for r in csv.DictReader(open(f)):
                if r.get("cache_policy", "warm") != "warm": continue
                v = r.get("p50_total_ms") or r.get("p50_total_e2e_ms")
                if v: got[r["protocol"]] = float(v)
        if not got: continue
        rows.append([str(R)] + [fmt(got.get(k)) for k, _ in PROTOS])
    if not rows: return None
    return table("Table 2: median connection establishment in ms, warm AS-key cache.", ["RTT ms"] + [n for _, n in PROTOS], rows, key="table2")


def table3(run_root):
    f = os.path.join(run_root, "table_3.txt")
    if not os.path.exists(f): return None
    t = open(f).read(); rows = []
    m = re.search(r"vanilla leaf certificate \(DER\)\s+(\d+) B", t); rows.append(["vanilla leaf certificate", f"{m.group(1)} B" if m else "-"])
    m = re.search(r"AS-JWT extension\s+(\d+) B", t); rows.append(["attestation extension (AS JWT), added by Janus", f"+{m.group(1)} B" if m else "-"])
    m = re.search(r"Delegated Credential\s+([\d-]+) B", t); rows.append(["Delegated Credential in the handshake, added by Janus", f"+{m.group(1)} B" if m else "-"])
    return table("Table 3: bytes, measured live on the testbed.", ["item", "this run"], rows, key="table3")


def table1(run_root):
    f = os.path.join(run_root, "table_1.txt")
    if not os.path.exists(f): return None
    t = open(f).read(); rows = []
    m = re.search(r"median\s+([\d.]+) ms", t)
    rows.append(["DC issuance (signing), on this client", f"{m.group(1)} ms" if m else "-"])
    return table("Table 1: the DC-issuance cost, measured live. The other steps of Table 1 are timed on the servers, which we do for you on request.",
                 ["step", "this run"], rows, key="table1")


def fig6(data, run):
    def peak(f):
        rows = list(csv.DictReader(open(f))); return max(float(r["achieved_rps"]) for r in rows) if rows else None
    pts = {}
    for d in glob.glob(os.path.join(data, f"{run}-scale-N*")):
        N = int(d.rsplit("N", 1)[1])
        for p in ("ctls_proxy", "ctls_redirect", "vanilla", "ratls", "httpa"):
            f = os.path.join(d, f"{p}_scale_warm_steps.csv")
            if os.path.exists(f) and peak(f) is not None: pts.setdefault(N, {})[p] = peak(f)
    if not pts: return None
    rows = []
    for N in sorted(pts):
        v = pts[N]
        rows.append([str(N), fmt(v.get('ctls_proxy')), fmt(v.get('ctls_redirect')),
                     fmt(v.get('vanilla')) if "vanilla" in v else "", fmt(v.get('ratls')) if "ratls" in v else "", fmt(v.get('httpa')) if "httpa" in v else ""])
    return table("Fig. 6: maximum sustained throughput in req/s. Each backend is capped at 10 req/s.",
                 ["N", "Janus-proxy", "Janus-redir.", "TLS (N=1)", "RA+TLS (N=1)", "HTTPA/2 (N=1)"], rows, key="fig6")


def app_rows(path, col):
    if not os.path.exists(path): return None
    by = {}
    for r in csv.DictReader(open(path)):
        if r.get("warmup", "0") not in ("0", "", None, "False"): continue
        if r.get("ok", "1") not in ("1", "", None): continue
        if r.get("rejected", "0") not in ("0", "", None): continue
        name = APP_NAMES.get(r["protocol"], r["protocol"])
        if name.startswith("Janus") and r.get("ctls_ok", "1") not in ("1", "", None, "n/a"): continue
        try: by.setdefault(name, []).append(float(r[col]))
        except (KeyError, ValueError): continue
    if not by: return None
    rows = []
    for name in ("vanilla", "Janus-proxy", "Janus-redirection", "RA+TLS", "HTTPA/2"):
        if name not in by: continue
        p50, mean = med_mean(by[name]); lo, hi = min(by[name]), max(by[name])
        rows.append([name, str(len(by[name])), fmt(p50, 0), fmt(mean, 0), fmt(lo, 0), fmt(hi, 0)])
    return rows


def fig7(run_root):
    out = []
    for key, title, path, col in (("fig7a", "Fig. 7(a): browser page-load time in ms", os.path.join(run_root, "fig7a", "plt.csv"), "plt_ms"),
                                  ("fig7b", "Fig. 7(b): LLM time to first token in ms", os.path.join(run_root, "fig7b", "llm_raw.csv"), "latency_ms"),
                                  ("fig7c", "Fig. 7(c): microservice request latency in ms", os.path.join(run_root, "fig7c", "microservice_raw.csv"), "latency_ms")):
        rows = app_rows(path, col)
        if rows: out.append(table(title + ".", ["protocol", "n", "median", "mean", "min", "max"], rows, key=key))
    return out


def build(run, run_root, data):
    parts = [t for t in (table1(run_root), table3(run_root), table2(data, run), fig6(data, run)) if t] + fig7(run_root)
    if not parts: return "", "", []
    head = f"Results of run {run}.\n"
    return head + "\n" + "\n".join(p[0] for p in parts), f"# Results of run {run}\n\n" + "\n".join(p[1] for p in parts), [p[2] for p in parts]


def write(out, md, tables):
    """Write the Markdown file `out` and one CSV per table in tables/ next to it."""
    d = os.path.dirname(out) or "."; os.makedirs(os.path.join(d, "tables"), exist_ok=True); open(out, "w").write(md)
    for key, header, rows in tables:
        with open(os.path.join(d, "tables", f"{key}.csv"), "w", newline="") as f: w = csv.writer(f); w.writerow(header); w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True); ap.add_argument("--run-root", default=None); ap.add_argument("--data", default=os.path.join(ROOT, "eval", "data"))
    ap.add_argument("--out", default=None, help="write the Markdown version here")
    a = ap.parse_args()
    run_root = a.run_root or os.path.join(os.path.expanduser("~"), "ae-results", a.run)
    txt, md, tables = build(a.run, run_root, a.data)
    if not txt: print(f"no results of run {a.run} found under {run_root} and {a.data}"); return 1
    print(txt, end="")
    if a.out:
        write(a.out, md, tables); print(f"(saved as {a.out}, one CSV per table in {os.path.join(os.path.dirname(a.out) or '.', 'tables')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
