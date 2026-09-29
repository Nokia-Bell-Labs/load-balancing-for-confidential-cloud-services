#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Build the inputs of the figure generators from the measurements of ONE run.

    overlay_runs.py --run <prefix> --run-root <dir> --dest <dir>

<dest> becomes a copy of plotting/ (the generator scripts) plus the data of the
run in the layout the generators read. Only measured elements are written.
Inputs of a run (all optional; at least one must exist, or this exits 3):
  eval/data/<prefix>-rtt-<R>/*.csv            establishment latency per RTT  (run_table2_fig5.sh)  -> Fig. 5 / Table 2
  eval/data/<prefix>-scale-N<N>/*_steps.csv   throughput per pool size       (run_fig6.sh)         -> Fig. 6 point N
  <run-root>/fig7c/microservice_raw.csv       microservice samples           (run_fig7c.sh)        -> Fig. 7(c)
  <run-root>/fig7a/plt.csv                    browser page loads             (run_fig7a.sh)        -> Fig. 7(a)
  <run-root>/fig7b/llm_raw.csv                LLM time-to-first-token        (run_fig7b.sh)        -> Fig. 7(b)
<dest>/coverage.md and coverage.json say which elements the run measured.
"""
import re, argparse, csv, glob, json, os, shutil, statistics, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
ALL5 = ["vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa"]
PANEL_PROTOS = {"(a) browser": ["vanilla", "ctls_proxy", "ctls_redirect"], "(b) LLM": ALL5, "(c) microservice": ALL5}
PANEL_EXP = {"(a) browser": "fig7a", "(b) LLM": "fig7b", "(c) microservice": "fig7c"}
NAME = {"vanilla": "vanilla", "cTLS-redirect": "ctls_redirect", "cTLS-proxy": "ctls_proxy", "HTTPA/2": "httpa", "RA+TLS": "ratls",
        "ctls_redirect": "ctls_redirect", "ctls_proxy": "ctls_proxy", "httpa": "httpa", "ratls": "ratls"}
SCALE_N = [1, 2, 4, 8, 16, 32]

def pct(v, q):
    s = sorted(v); k = (len(s) - 1) * q / 100; f = int(k); c = min(f + 1, len(s) - 1)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)

def summarize(samples):
    return {"p50_ms": f"{pct(samples,50):.2f}", "p95_ms": f"{pct(samples,95):.2f}", "p99_ms": f"{pct(samples,99):.2f}",
            "mean_ms": f"{statistics.mean(samples):.2f}", "min_ms": f"{min(samples):.2f}", "max_ms": f"{max(samples):.2f}"}

def write_csv(path, cols, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True); ap.add_argument("--run-root", required=True); ap.add_argument("--dest", required=True)
    a = ap.parse_args(); data = os.path.join(ROOT, "eval", "data"); dest = a.dest
    mpath = os.path.join(a.run_root, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.exists(mpath) else {}
    exp_status = {k: v.get("status") for k, v in manifest.get("experiments", {}).items()}
    def status_of(name):   # experiment status from the run manifest, for name or name-N* keys
        return [v for k, v in exp_status.items() if k == name or re.match(re.escape(name) + r"-N\d+$", k)]
    cov = {"run": a.run, "tables_1_3": {}, "figure_5_table_2": {}, "figure_6": {}, "figure_7": {}}
    for t, key in (("Table 1 (live DC-signing cost)", "table1"), ("Table 3 (live certificate and DC sizes)", "table3")):
        st = status_of(key); cov["tables_1_3"][t] = {"status": ("fresh" if st[-1] == "succeeded" else st[-1]) if st else "not run"}
    if os.path.exists(dest): shutil.rmtree(dest)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    shutil.copytree(os.path.join(ROOT, "plotting"), dest, ignore=shutil.ignore_patterns("*.pdf", "*.png", "figures", "__pycache__"))
    fresh_any = False
    # Fig. 5 / Table 2: per-RTT directories
    t2 = status_of("table2"); t2_ok = (not t2) or t2[-1] == "succeeded"   # an interrupted Table 2 run is not plotted
    for R in (0, 20, 40, 80, 120, 160):
        d = os.path.join(data, f"{a.run}-rtt-{R}")
        fresh, counts = [], {}
        if os.path.isdir(d) and t2_ok:
            out = os.path.join(dest, "bench_figures", "data", f"rtt-{R}")
            for proto in ALL5:
                f = os.path.join(d, f"{proto}_warm.csv")
                if not os.path.exists(f): continue
                ok = sum(1 for r in csv.DictReader(open(f)) if r.get("ok") == "1"); counts[proto] = ok
                if ok:
                    os.makedirs(out, exist_ok=True)
                    for g in glob.glob(os.path.join(d, f"{proto}_warm*")): shutil.copy(g, out)
                    fresh.append(proto)
        if fresh:
            fresh_any = True
            cov["figure_5_table_2"][f"rtt-{R}"] = {"status": "fresh" if set(fresh) >= set(ALL5) else "partial", "protocols": sorted(fresh),
                                                  "not measured": [p for p in ALL5 if p not in fresh], "samples": counts}
        else:
            cov["figure_5_table_2"][f"rtt-{R}"] = {"status": "not measured"}
    # Fig. 6: throughput per pool size
    def peak(f):
        rows = list(csv.DictReader(open(f))); return max(float(r["achieved_rps"]) for r in rows) if rows else None
    scale = {}
    for d in glob.glob(os.path.join(data, f"{a.run}-scale-N*")):
        N = int(d.rsplit("N", 1)[1])
        stN = exp_status.get(f"fig6-N{N}")
        if stN and stN != "succeeded": continue                        # an interrupted point is not plotted
        for p in ALL5:
            f = os.path.join(d, f"{p}_scale_warm_steps.csv")
            if os.path.exists(f) and peak(f) is not None: scale.setdefault(N, {})[p] = peak(f)
    rows = []
    for N in sorted(set(SCALE_N) | set(scale)):                       # the standard sizes plus any other measured size
        m = scale.get(N, {})
        rows.append({"N": N, "proxy_rps": f"{m['ctls_proxy']:.1f}" if "ctls_proxy" in m else "", "redirect_rps": f"{m['ctls_redirect']:.1f}" if "ctls_redirect" in m else ""})
        fresh6 = sorted(k for k in m if k in ("ctls_proxy", "ctls_redirect"))
        cov["figure_6"][f"N={N}"] = ({"status": "fresh" if len(fresh6) == 2 else "partial", "protocols": fresh6, "not measured": [p for p in ("ctls_proxy", "ctls_redirect") if p not in fresh6]}
                                     if fresh6 else {"status": "not measured"})
    write_csv(os.path.join(dest, "scalability_capped", "capped_scaleout.csv"), ["N", "proxy_rps", "redirect_rps"], rows)
    m1 = scale.get(1, {})
    write_csv(os.path.join(dest, "scalability_capped", "capped_baselines_n1.csv"), ["protocol", "N", "achieved_rps"],
              [{"protocol": p, "N": 1, "achieved_rps": f"{m1[p]:.1f}" if p in m1 else ""} for p in ("vanilla", "ratls", "httpa")])
    b1 = sorted(k for k in m1 if k in ("vanilla", "ratls", "httpa"))
    cov["figure_6"]["N=1 baselines"] = {"status": "fresh" if len(b1) == 3 else ("partial" if b1 else "not measured"), "protocols": b1,
                                        "not measured": [p for p in ("vanilla", "ratls", "httpa") if p not in b1]}
    if scale: fresh_any = True
    # Fig. 7: application workloads
    apps = os.path.join(dest, "bench_figures", "data", "apps")
    def valid(r):
        """A sample counts only if it is a measured (non-warm-up) attempt that succeeded. A browser sample must not be
        rejected. For Janus rows, the attestation must be verified."""
        if r.get("warmup", "0") not in ("0", "", None, "False"): return False
        if r.get("ok", "1") not in ("1", "", None): return False
        if r.get("rejected", "0") not in ("0", "", None): return False
        if NAME.get(r["protocol"], r["protocol"]).startswith("ctls") and r.get("ctls_ok", "1") not in ("1", "", None, "n/a"): return False
        return True
    def app_panel(key, raw, value_col, csv_name, metric):
        st = status_of(PANEL_EXP[key]); universe = PANEL_PROTOS[key]
        cols = ["protocol", "p50_ms", "p95_ms", "p99_ms", "metric", "mean_ms", "min_ms", "max_ms"]
        write_csv(os.path.join(apps, csv_name), cols, [])   # an empty panel unless the run measured it
        if st and st[-1] != "succeeded":
            cov["figure_7"][key] = {"status": f"{st[-1]} (manifest)"}; return
        if not os.path.exists(raw):
            cov["figure_7"][key] = {"status": "not measured"}; return
        by, rejected = {}, {}
        for r in csv.DictReader(open(raw)):
            p = NAME.get(r["protocol"], r["protocol"])
            if not valid(r): rejected[p] = rejected.get(p, 0) + 1; continue
            v = r.get(value_col)
            if v not in (None, ""): by.setdefault(p, []).append(float(v))
        fresh = {p: summarize(v) for p, v in by.items() if v}
        if not fresh:
            cov["figure_7"][key] = {"status": "failed (no valid samples in " + os.path.relpath(raw, a.run_root) + ")", "rejected": rejected}; return
        write_csv(os.path.join(apps, csv_name), cols, [{"protocol": p, "metric": metric or "", **fresh[p]} for p in universe if p in fresh])
        cov["figure_7"][key] = {"status": "fresh" if set(fresh) >= set(universe) else "partial", "protocols": sorted(fresh),
                                "not measured": [p for p in universe if p not in fresh], "samples": {p: len(v) for p, v in by.items()}, "rejected": rejected}
    app_panel("(a) browser",      os.path.join(a.run_root, "fig7a", "plt.csv"),              "plt_ms",     "browser.csv",      "PLT")
    app_panel("(b) LLM",          os.path.join(a.run_root, "fig7b", "llm_raw.csv"),          "latency_ms", "llm_gpu_ttft.csv", "TTFT")
    app_panel("(c) microservice", os.path.join(a.run_root, "fig7c", "microservice_raw.csv"), "latency_ms", "microservice.csv", None)
    if any(v.get("status") in ("fresh", "partial") for v in cov["figure_7"].values()): fresh_any = True
    # coverage report
    json.dump(cov, open(os.path.join(dest, "coverage.json"), "w"), indent=2)
    with open(os.path.join(dest, "coverage.md"), "w") as f:
        f.write(f"# Coverage of run `{a.run}`\n\nfresh = this run measured every protocol of the element. partial = this run measured some protocols. "
                f"not measured = the run has no data for it, and the figure leaves it out.\n\n")
        for fig, items in (("Tables 1 and 3", cov["tables_1_3"]), ("Figure 5 / Table 2 (per RTT)", cov["figure_5_table_2"]),
                           ("Figure 6 (per pool size)", cov["figure_6"]), ("Figure 7 (per panel)", cov["figure_7"])):
            f.write(f"## {fig}\n\n| element | status | detail |\n|---|---|---|\n")
            for k, v in items.items():
                parts = []
                if v.get("protocols"): parts.append("fresh: " + ", ".join(v["protocols"]))
                if v.get("not measured"): parts.append("not measured: " + ", ".join(v["not measured"]))
                if v.get("samples"): parts.append("valid samples " + str(v["samples"]))
                if v.get("rejected"): parts.append("rejected " + str(v["rejected"]))
                f.write(f"| {k} | {v['status']} | {'. '.join(parts)} |\n")
            f.write("\n")
    if not fresh_any:
        print(f"run '{a.run}' has no figure data (no eval/data/{a.run}-rtt-*, no {a.run}-scale-N*, no fig7* samples under {a.run_root}). Nothing to draw.", file=sys.stderr)
        return 3
    print(f"figure inputs of run '{a.run}' written to {dest} (coverage: {dest}/coverage.md)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
